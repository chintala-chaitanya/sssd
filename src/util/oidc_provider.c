/*
    SSSD

    Shared OIDC provider behavior definitions

    Authors:
        Chaitanya Chintala <chaitanya.c.chintala@oracle.com>

    Copyright (C) 2026 Oracle and/or its affiliates.

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

#include <stddef.h>
#include <strings.h>

#include "util/oidc_provider.h"

static const struct oidc_provider_behavior entra_id_behavior = {
    .kind = OIDC_PROVIDER_ENTRA_ID,
    .authenticated_user_claim = "id",
    .device_code_client_auth = OIDC_DEVICE_CODE_USE_CONFIGURED_CLIENT_AUTH,
    .device_code_requires_response_type = false,
    .require_https_endpoints = false,
};

static const struct oidc_provider_behavior keycloak_behavior = {
    .kind = OIDC_PROVIDER_KEYCLOAK,
    .authenticated_user_claim = "sub",
    .device_code_client_auth = OIDC_DEVICE_CODE_USE_CONFIGURED_CLIENT_AUTH,
    .device_code_requires_response_type = false,
    .require_https_endpoints = false,
};

static const struct oidc_provider_behavior oci_iam_behavior = {
    .kind = OIDC_PROVIDER_OCI_IAM,
    .authenticated_user_claim = "sub",
    .device_code_client_auth = OIDC_DEVICE_CODE_NO_CLIENT_AUTH,
    .device_code_requires_response_type = true,
    .require_https_endpoints = true,
};

const struct oidc_provider_behavior *oidc_provider_get_behavior(
                                                            const char *idp_type)
{
    if (idp_type != NULL && strncasecmp(idp_type, "keycloak:", 9) == 0) {
        return &keycloak_behavior;
    }

    if (idp_type != NULL && strncasecmp(idp_type, "oci_iam:", 8) == 0) {
        return &oci_iam_behavior;
    }

    if (idp_type == NULL || strcasecmp(idp_type, "entra_id") == 0
                         || strncasecmp(idp_type, "entra_id:", 9) == 0) {
        /* Keep the existing default behavior for an omitted idp_type. */
        return &entra_id_behavior;
    }

    return NULL;
}
