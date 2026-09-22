/*
    SSSD

    Helper child for reading user and group information form IdPs

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2024 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "oidc_child/oidc_child_util.h"

#include <jansson.h>

#include "util/util.h"

#define IS_ID_CMD(cmd) ( \
    cmd == GET_USER || cmd == GET_USER_GROUPS \
                              || cmd == GET_GROUP \
                              || cmd == GET_GROUP_MEMBERS )

/* Extracts and normalizes the base URL from an idp_type string of
 * the form https://... Sets *base_url to NULL if no URL is present
 *
 * Entra will use default microsoft url if not present, while keycloak
 * will fail. */
static errno_t parse_base_url_from_idp_type(TALLOC_CTX *mem_ctx,
                                            const char *idp_type,
                                            char **_base_url)
{
    char *base_url;
    char *last;
    const char *colon;
    char *p;
    char *limit;

    if (idp_type == NULL) {
        *_base_url = NULL;
        return EOK;
    }

    colon = strchr(idp_type, ':');
    if (colon == NULL) {
        *_base_url = NULL;
        return EOK;
    }

    base_url = talloc_strdup(mem_ctx, colon + 1);
    if (base_url == NULL) {
        return ENOMEM;
    }

    if (*base_url == '\0' || strncasecmp(base_url, "http", 4) != 0) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Colon supplied in [%s] but no valid URL found.\n", idp_type);
        talloc_free(base_url);
        return EINVAL;
    }

    /* strip trailing slashes if it is not part of scheme */
    p = strstr(base_url, "://");
    limit = p ? p + 2 : base_url;
    last = base_url + strlen(base_url) - 1;
    while (last > limit && *last == '/') last--;
    last[1] = '\0';

    *_base_url = base_url;
    return EOK;
}

static errno_t oci_iam_get_resources(TALLOC_CTX *mem_ctx,
                                     struct rest_ctx *rest_ctx,
                                     const char *uri,
                                     const char *bearer_token,
                                     char **out)
{
    errno_t ret;
    char *page_uri = NULL;
    char *dump = NULL;
    json_t *all = NULL;
    json_t *root = NULL;
    json_t *resources = NULL;
    json_t *total_results = NULL;
    json_error_t json_error;
    json_int_t total;
    size_t start_index = 1;
    size_t received;
    size_t index;
    json_t *item;
    char separator;

    all = json_array();
    if (all == NULL) {
        return ENOMEM;
    }

    separator = strchr(uri, '?') == NULL ? '?' : '&';
    do {
        page_uri = talloc_asprintf(rest_ctx, "%s%cstartIndex=%zu&count=1000",
                                   uri, separator, start_index);
        if (page_uri == NULL) {
            ret = ENOMEM;
            goto done;
        }

        clean_http_data(rest_ctx);
        ret = do_http_request(rest_ctx, page_uri, NULL, bearer_token);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "OCI IAM SCIM request failed.\n");
            goto done;
        }

        root = json_loads(get_http_data(rest_ctx), 0, &json_error);
        if (root == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to parse OCI IAM SCIM response on line [%d]: [%s].\n",
                  json_error.line, json_error.text);
            ret = EINVAL;
            goto done;
        }

        resources = json_object_get(root, "Resources");
        total_results = json_object_get(root, "totalResults");
        if (!json_is_array(resources) || !json_is_integer(total_results)) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "OCI IAM response is not a SCIM ListResponse.\n");
            ret = EINVAL;
            goto done;
        }

        total = json_integer_value(total_results);
        if (total < 0) {
            ret = EINVAL;
            goto done;
        }

        received = json_array_size(resources);
        json_array_foreach(resources, index, item) {
            if (json_array_append(all, item) != 0) {
                ret = ENOMEM;
                goto done;
            }
        }

        json_decref(root);
        root = NULL;
        page_uri = NULL;

        if (received == 0 && start_index <= (size_t) total) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "OCI IAM returned an empty page before all results were read.\n");
            ret = EIO;
            goto done;
        }
        start_index += received;
    } while (start_index <= (size_t) total);

    dump = json_dumps(all, 0);
    if (dump == NULL) {
        ret = ENOMEM;
        goto done;
    }

    *out = talloc_strdup(mem_ctx, dump);
    free(dump);
    ret = *out == NULL ? ENOMEM : EOK;
done:
    json_decref(root);
    json_decref(all);
    return ret;
}

static errno_t oci_iam_get_first_id(TALLOC_CTX *mem_ctx, const char *data,
                                    char **out)
{
    json_t *array = NULL;
    json_t *item = NULL;
    json_t *id = NULL;
    json_error_t json_error;

    array = json_loads(data, 0, &json_error);
    if (!json_is_array(array) || json_array_size(array) == 0) {
        json_decref(array);
        return ENOENT;
    }

    item = json_array_get(array, 0);
    id = json_object_get(item, "id");
    if (!json_is_string(id)) {
        json_decref(array);
        return EINVAL;
    }

    *out = talloc_strdup(mem_ctx, json_string_value(id));
    json_decref(array);
    return *out == NULL ? ENOMEM : EOK;
}

static errno_t oci_iam_normalize_resources(TALLOC_CTX *mem_ctx,
                                           enum oidc_cmd oidc_cmd,
                                           const char *data, char **out)
{
    json_t *array = NULL;
    json_t *normalized = NULL;
    json_t *item = NULL;
    json_t *id = NULL;
    json_t *name = NULL;
    json_t *object = NULL;
    json_error_t json_error;
    const char *name_attr;
    const char *posix_name_attr;
    const char *object_type;
    bool is_user;
    size_t index;
    char *dump = NULL;
    errno_t ret = EOK;

    is_user = oidc_cmd == GET_USER || oidc_cmd == GET_GROUP_MEMBERS;
    name_attr = is_user ? "userName" : "displayName";
    posix_name_attr = is_user ? "posixUsername" : "posixGroupname";
    object_type = is_user ? "user" : "group";

    array = json_loads(data, 0, &json_error);
    if (!json_is_array(array)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "OCI IAM resources are not a JSON array on line [%d]: [%s].\n",
              json_error.line, json_error.text);
        ret = EINVAL;
        goto done;
    }

    normalized = json_array();
    if (normalized == NULL) {
        ret = ENOMEM;
        goto done;
    }

    json_array_foreach(array, index, item) {
        id = json_object_get(item, "id");
        name = json_object_get(item, name_attr);
        if (!json_is_string(id) || !json_is_string(name)) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "OCI IAM object is missing '%s' or '%s'.\n", "id", name_attr);
            ret = EINVAL;
            goto done;
        }

        object = json_object();
        if (object == NULL
                || json_object_set(object, "id", id) != 0
                || json_object_set(object, posix_name_attr, name) != 0
                || json_object_set_new(object, "posixObjectType",
                                       json_string(object_type)) != 0
                || (is_user && json_object_set(object, "idpUserIdentifier",
                                                name) != 0)) {
            json_decref(object);
            ret = ENOMEM;
            goto done;
        }

        ret = json_array_append_new(normalized, object);
        object = NULL;
        if (ret != 0) {
            ret = ENOMEM;
            goto done;
        }
    }

    dump = json_dumps(normalized, 0);
    if (dump == NULL) {
        ret = ENOMEM;
        goto done;
    }

    *out = talloc_strdup(mem_ctx, dump);
    free(dump);
    ret = *out == NULL ? ENOMEM : EOK;
done:
    json_decref(object);
    json_decref(normalized);
    json_decref(array);
    return ret;
}

static errno_t oci_iam_lookup(TALLOC_CTX *mem_ctx, enum oidc_cmd oidc_cmd,
                              char *base_url, char *input,
                              enum search_str_type input_type,
                              bool libcurl_debug, const char *ca_db,
                              const char *client_id,
                              const char *client_secret,
                              const char *token_endpoint, const char *scope,
                              const char *bearer_token,
                              struct rest_ctx *rest_ctx, char **out)
{
    errno_t ret;
    char *filter = NULL;
    char *filter_enc = NULL;
    char *uri = NULL;
    char *resources = NULL;
    char *object_id = NULL;

    if (base_url == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing base URL in IdP type [oci_iam].\n");
        return EINVAL;
    }

    switch (oidc_cmd) {
    case GET_USER:
    case GET_USER_GROUPS:
        filter = talloc_asprintf(rest_ctx, "userName eq \"%s\"", input);
        break;
    case GET_GROUP:
    case GET_GROUP_MEMBERS:
        filter = talloc_asprintf(rest_ctx, "displayName eq \"%s\"", input);
        break;
    default:
        return EINVAL;
    }
    if (filter == NULL) {
        return ENOMEM;
    }

    filter_enc = url_encode_string(rest_ctx, filter);
    if (filter_enc == NULL) {
        return ENOMEM;
    }

    uri = talloc_asprintf(rest_ctx, "%s/admin/v1/%s?filter=%s", base_url,
                          (oidc_cmd == GET_USER || oidc_cmd == GET_USER_GROUPS)
                              ? "Users" : "Groups", filter_enc);
    if (uri == NULL) {
        return ENOMEM;
    }

    ret = oci_iam_get_resources(mem_ctx, rest_ctx, uri, bearer_token,
                                &resources);
    if (ret != EOK || oidc_cmd == GET_USER || oidc_cmd == GET_GROUP) {
        goto done;
    }

    ret = oci_iam_get_first_id(rest_ctx, resources, &object_id);
    if (ret != EOK) {
        goto done;
    }

    if (oidc_cmd == GET_USER_GROUPS) {
        filter = talloc_asprintf(rest_ctx,
                                 "members[type eq \"User\" and value eq \"%s\"]",
                                 object_id);
        filter_enc = url_encode_string(rest_ctx, filter);
        uri = talloc_asprintf(rest_ctx, "%s/admin/v1/Groups?filter=%s",
                              base_url, filter_enc);
    } else {
        filter = talloc_asprintf(rest_ctx, "groups.value eq \"%s\"",
                                 object_id);
        filter_enc = url_encode_string(rest_ctx, filter);
        uri = talloc_asprintf(rest_ctx,
                              "%s/admin/v1/Users?attributes=userName&filter=%s&sortBy=id",
                              base_url, filter_enc);
    }
    if (filter == NULL || filter_enc == NULL || uri == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = oci_iam_get_resources(mem_ctx, rest_ctx, uri, bearer_token,
                                &resources);
done:
    if (ret == EOK && out != NULL) {
        ret = oci_iam_normalize_resources(mem_ctx, oidc_cmd, resources, out);
    }
    return ret;
}

/* The following function will lookup users and groups based on Mircosoft's
 * Graph API as described in
 * https://learn.microsoft.com/de-de/graph/api/overview */
errno_t entra_id_lookup(TALLOC_CTX *mem_ctx, enum oidc_cmd oidc_cmd,
                        char *base_url,
                        char *input, enum search_str_type input_type,
                        bool libcurl_debug, const char *ca_db,
                        const char *client_id, const char *client_secret,
                        const char *token_endpoint, const char *scope,
                        const char *bearer_token, struct rest_ctx *rest_ctx,
                        char **out)
{
    errno_t ret;
    char *uri;
    char *filter;
    char *filter_enc;
    const char *obj_id;
    const char **id_list;
    char *short_name;
    char *sep;
    char *tmp;
    struct name_and_type_identifier entra_name_and_type_identifier = {
                            .user_identifier_attr = "userPrincipalName",
                            .group_identifier_attr = "groupTypes",
                            .user_name_attr = "userPrincipalName",
                            .group_name_attr = "displayName" };

    if (base_url == NULL) {
        base_url = talloc_strdup(mem_ctx, "https://graph.microsoft.com/v1.0");
        if (base_url == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    switch (oidc_cmd) {
    case GET_USER:
    case GET_USER_GROUPS:
        sep = strrchr(input, '@');
        if (sep == NULL || sep == input) {
            filter = talloc_asprintf(rest_ctx, "startsWith(userPrincipalName,'%s@')", input);
        } else {
            filter = talloc_asprintf(rest_ctx,
                                     "mail eq '%s' or userPrincipalName eq '%s'",
                                     input, input);
        }
        break;
    case GET_GROUP:
    case GET_GROUP_MEMBERS:
        sep = strrchr(input, '@');
        if (sep == NULL || sep == input) {
            filter = talloc_asprintf(rest_ctx, "displayName eq '%s'", input);
        } else {
            short_name = talloc_strndup(rest_ctx, input, sep - input);
            if (short_name == NULL) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to generate short name, using plain input [%s].\n",
                      input);
                filter = talloc_asprintf(rest_ctx, "displayName eq '%s'", input);
            } else {
                filter = talloc_asprintf(rest_ctx,
                                         "displayName eq '%s' or displayName eq '%s'",
                                         input, short_name);
            }
        }
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unknown command [%d].\n", oidc_cmd);
        ret = EINVAL;
        goto done;
    }

    if (filter == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to create user search filter.\n");
        ret = ENOMEM;
        goto done;
    }

    filter_enc = url_encode_string(rest_ctx, filter);
    if (filter_enc == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to encode user search filter.\n");
        ret = ENOMEM;
        goto done;
    }

    switch (oidc_cmd) {
    case GET_USER:
    case GET_USER_GROUPS:
        uri = talloc_asprintf(rest_ctx, "%s/users?$filter=%s", base_url, filter_enc);
        break;
    case GET_GROUP:
    case GET_GROUP_MEMBERS:
        uri = talloc_asprintf(rest_ctx, "%s/groups?$filter=%s", base_url, filter_enc);
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unknown command [%d].\n", oidc_cmd);
        ret = EINVAL;
        goto done;
    }

    if (uri == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate lookup URI.\n");
        ret = ENOMEM;
        goto done;
    }

    clean_http_data(rest_ctx);
    ret = do_http_request(rest_ctx, uri, NULL, bearer_token);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "User search request failed.\n");
        goto done;
    }

    if (oidc_cmd == GET_USER || oidc_cmd == GET_GROUP) {
        ret = EOK;
        goto done;
    }

    obj_id = get_str_attr_from_embed_json_string(rest_ctx,
                                                 get_http_data(rest_ctx),
                                                 "value", "id");
    if (obj_id == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to read mandatory object id.\n");
        ret = EINVAL;
        goto done;
    }

    switch (oidc_cmd) {
    case GET_USER_GROUPS:
        uri = talloc_asprintf(rest_ctx, "%s/users/%s/getMemberGroups",
                              base_url, obj_id);
        break;
    case GET_GROUP_MEMBERS:
        uri = talloc_asprintf(rest_ctx, "%s/groups/%s/members",
                              base_url, obj_id);
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unknown command [%d].\n", oidc_cmd);
        ret = EINVAL;
        goto done;
    }

    if (uri == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate lookup URI.\n");
        ret = ENOMEM;
        goto done;
    }

    clean_http_data(rest_ctx);
    switch (oidc_cmd) {
    case GET_USER_GROUPS:
        ret = do_http_request_json_data(rest_ctx, uri, "{\"securityEnabledOnly\": true}", bearer_token);
        break;
    case GET_GROUP_MEMBERS:
        ret = do_http_request_json_data(rest_ctx, uri, NULL, bearer_token);
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unknown command [%d].\n", oidc_cmd);
        ret = EINVAL;
        goto done;
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Member(of) search request failed.\n");
        goto done;
    }

    if (oidc_cmd == GET_GROUP_MEMBERS) {
        goto done;
    }

    id_list = get_str_list_from_json_string(rest_ctx, get_http_data(rest_ctx),
                                            "value");
    if (id_list == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to get id list.\n");
        ret = EINVAL;
        goto done;
    }

    if (out != NULL) {
        *out = get_json_string_array_by_id_list(mem_ctx, rest_ctx, bearer_token,
                                                id_list);
        if (*out == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to get objects by ID.\n");
            ret = EIO;
            goto done;
        }
    }

done:
    if (ret == EOK && out != NULL && oidc_cmd != GET_USER_GROUPS) {
        *out = get_json_string_array_from_json_string(mem_ctx, get_http_data(rest_ctx), "value");
        if (*out == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to copy output data.\n");
            ret = ENOMEM;
        }
    }

    if (ret == EOK && out != NULL) {
        ret = add_posix_to_json_string_array(mem_ctx,
                                             &entra_name_and_type_identifier,
                                             '@', *out, &tmp);
        talloc_free(*out);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to add POSIX data.\n");
            *out = NULL;
        } else {
            *out = tmp;
        }
    }

    return ret;
}

/* The following function will lookup users and groups based on Keycloak's
 * REST API as described in
 * https://www.keycloak.org/docs-api/latest/rest-api/index.html */
errno_t keycloak_lookup(TALLOC_CTX *mem_ctx, enum oidc_cmd oidc_cmd,
                        char *base_url,
                        char *input, enum search_str_type input_type,
                        bool libcurl_debug, const char *ca_db,
                        const char *client_id, const char *client_secret,
                        const char *token_endpoint, const char *scope,
                        const char *bearer_token, struct rest_ctx *rest_ctx,
                        char **out)
{
    errno_t ret;
    char *uri;
    char *filter;
    char *filter_enc;
    char *input_enc;
    const char *obj_id;
    char *short_name;
    char *short_name_enc;
    char *sep;
    struct name_and_type_identifier keycloak_name_and_type_identifier = {
                            .user_identifier_attr = "username",
                            .group_identifier_attr = "name",
                            .user_name_attr = "username",
                            .group_name_attr = "name" };

    if (base_url == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing base URL in IdP type [keycloak].\n");
        return EINVAL;
    }

    input_enc = url_encode_string(rest_ctx, input);
    if (input_enc == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to encode input [%s].\n", input);
        return EINVAL;
    }

    switch (oidc_cmd) {
    case GET_USER:
    case GET_USER_GROUPS:
        filter = talloc_asprintf(rest_ctx, "username=%s&exact=true", input_enc);
        break;
    case GET_GROUP:
    case GET_GROUP_MEMBERS:
        sep = strrchr(input, '@');
        if (sep == NULL || sep == input) {
            filter = talloc_asprintf(rest_ctx, "search=%s&exact=true&populateHierarchy=false&briefRepresentation=false", input_enc);
        } else {
            short_name = talloc_strndup(rest_ctx, input, sep - input);
            if (short_name == NULL) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to generate short name, using plain input [%s].\n",
                      input);
                filter = talloc_asprintf(rest_ctx, "search=%s&exact=true",
                                                   input_enc);
            } else {
                short_name_enc = url_encode_string(rest_ctx, short_name);
                if (short_name_enc == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "Failed to encode short name [%s].\n",
                          short_name);
                    ret = ENOMEM;
                    goto done;
                }
                filter = talloc_asprintf(rest_ctx, "search=%s&exact=true",
                                                   short_name_enc);
            }
        }
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unknown command [%d].\n", oidc_cmd);
        ret = EINVAL;
        goto done;
    }

    if (filter == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to create user search filter.\n");
        ret = ENOMEM;
        goto done;
    }

    filter_enc = filter;

    switch (oidc_cmd) {
    case GET_USER:
    case GET_USER_GROUPS:
        uri = talloc_asprintf(rest_ctx, "%s/users?%s", base_url, filter_enc);
        break;
    case GET_GROUP:
    case GET_GROUP_MEMBERS:
        uri = talloc_asprintf(rest_ctx, "%s/groups?%s", base_url, filter_enc);
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unknown command [%d].\n", oidc_cmd);
        ret = EINVAL;
        goto done;
    }

    if (uri == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate lookup URI.\n");
        ret = ENOMEM;
        goto done;
    }

    clean_http_data(rest_ctx);
    ret = do_http_request(rest_ctx, uri, NULL, bearer_token);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "User search request failed.\n");
        goto done;
    }

    if (oidc_cmd == GET_USER || oidc_cmd == GET_GROUP) {
        ret = EOK;
        goto done;
    }

    obj_id = get_str_attr_from_json_array_string(rest_ctx, get_http_data(rest_ctx),
                                                 "id");
    if (obj_id == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to read mandatory object id.\n");
        ret = EINVAL;
        goto done;
    }

    switch (oidc_cmd) {
    case GET_USER_GROUPS:
        uri = talloc_asprintf(rest_ctx,
                              "%s/users/%s/groups?briefRepresentation=false", base_url, obj_id);
        break;
    case GET_GROUP_MEMBERS:
        uri = talloc_asprintf(rest_ctx,
                              "%s/groups/%s/members", base_url, obj_id);
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unknown command [%d].\n", oidc_cmd);
        ret = EINVAL;
        goto done;
    }

    if (uri == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate lookup URI.\n");
        ret = ENOMEM;
        goto done;
    }

    clean_http_data(rest_ctx);
    switch (oidc_cmd) {
    case GET_USER_GROUPS:
        ret = do_http_request_json_data(rest_ctx, uri, NULL, bearer_token);
        break;
    case GET_GROUP_MEMBERS:
        ret = do_http_request_json_data(rest_ctx, uri, NULL, bearer_token);
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unknown command [%d].\n", oidc_cmd);
        ret = EINVAL;
        goto done;
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Member(of) search request failed.\n");
        goto done;
    }

    ret = EOK;

done:
    if (ret == EOK && out != NULL) {
        ret = add_posix_to_json_string_array(mem_ctx,
                                             &keycloak_name_and_type_identifier,
                                             0, get_http_data(rest_ctx), out);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to add POSIX data.\n");
        }
    }

    return ret;
}

errno_t oidc_get_id(TALLOC_CTX *mem_ctx, enum oidc_cmd oidc_cmd,
                    char *idp_type,
                    char *input, enum search_str_type input_type,
                    bool libcurl_debug, const char *ca_db,
                    const char *client_id, const char *client_secret,
                    const char *pkcs12_client_creds,
                    enum client_auth_method client_auth_method,
                    const char *token_endpoint, const char *scope, char **out)
{
    errno_t ret;
    struct rest_ctx *rest_ctx;
    char *cli_cred_reply;
    const char *bearer_token;

    if (!IS_ID_CMD(oidc_cmd)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported command [%d].\n", oidc_cmd);
        return EINVAL;
    }

    if (client_id == NULL || client_secret == NULL || token_endpoint == NULL
            || input == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing required argument.\n");
        return EINVAL;
    }

    rest_ctx = get_rest_ctx(mem_ctx, libcurl_debug, ca_db,
                            pkcs12_client_creds, client_auth_method,
                            client_secret);
    if (rest_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to get REST context.\n");
        return ENOMEM;
    }

    ret = client_credentials_grant(rest_ctx, token_endpoint,
                                   client_id, client_secret, scope);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to get access token with client credentials grant.\n");
        goto done;
    }

    cli_cred_reply = talloc_strdup(rest_ctx, get_http_data(rest_ctx));
    bearer_token = get_bearer_token(rest_ctx, cli_cred_reply);

    if (input_type ==TYPE_OBJECT_ID) {
        ret = ENOTSUP;
        goto done;
    }

    char *base_url = NULL;

    ret = parse_base_url_from_idp_type(mem_ctx, idp_type, &base_url);
    if (ret != EOK) {
        goto done;
    }

    if (idp_type != NULL && strncasecmp(idp_type, "keycloak:",9) == 0) {
        ret = keycloak_lookup(mem_ctx, oidc_cmd, base_url, input, input_type,
                              libcurl_debug, ca_db, client_id, client_secret,
                              token_endpoint, scope, bearer_token, rest_ctx,
                              out);
    } else if (idp_type != NULL
               && strncasecmp(idp_type, "oci_iam:", 8) == 0) {
        ret = oci_iam_lookup(mem_ctx, oidc_cmd, base_url, input, input_type,
                             libcurl_debug, ca_db, client_id, client_secret,
                             token_endpoint, scope, bearer_token, rest_ctx,
                             out);
    } else if (idp_type == NULL
               || strcasecmp(idp_type, "entra_id") == 0
               || strncasecmp(idp_type, "entra_id:", 9) == 0) {
        ret = entra_id_lookup(mem_ctx, oidc_cmd, base_url, input, input_type,
                              libcurl_debug, ca_db, client_id, client_secret,
                              token_endpoint, scope, bearer_token, rest_ctx,
                              out);
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported IdP type [%s].\n", idp_type);
        ret = EINVAL;
        goto done;
    }

done:

    talloc_free(rest_ctx);
    return ret;
}
