/*
    SSSD

    IdP Backend Module - Manage oidc_child

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

#include <jansson.h>
#include <time.h>

#include "util/child_common.h"
#include "providers/idp/idp_common.h"

#define OIDC_CHILD SSSD_LIBEXEC_PATH"/oidc_child"
#define OIDC_CHILD_LOG_FILE "oidc_child"
#define IDP_METADATA_RETRY_DELAY 5

struct handle_oidc_child_state {
    struct tevent_context *ev;
    struct idp_req *idp_req;
    uint8_t *buf;
    ssize_t len;

    struct child_io_fds *io;
};

static errno_t create_send_buffer(struct idp_req *idp_req,
                                  struct io_buffer **io_buf)
{
    struct io_buffer *buf = NULL;
    const char *client_secret;
    int ret;

    buf = talloc_zero(idp_req, struct io_buffer);
    if (buf == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc failed.\n");
        return ENOMEM;
    }

    client_secret = dp_opt_get_cstring(idp_req->idp_options,
                                       IDP_CLIENT_SECRET);
    if (client_secret == NULL || *client_secret == '\0') {
        ret = EOK;
        goto done;
    }

    buf->size = strlen(client_secret);
    buf->data = talloc_size(buf, buf->size);
    if (buf->data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_size failed.\n");
        talloc_free(buf);
        return ENOMEM;
    }

    safealign_memcpy(buf->data, client_secret, strlen(client_secret), NULL);

    ret = EOK;

done:
    if (ret == EOK) {
        *io_buf = buf;
    }

    return ret;
}

static void handle_oidc_child_send_done(struct tevent_req *subreq);
static void handle_oidc_child_done(struct tevent_req *subreq);

static struct tevent_req *handle_oidc_child_raw_send(TALLOC_CTX *mem_ctx,
                                                     struct tevent_context *ev,
                                                     struct idp_req *idp_req,
                                                     struct io_buffer *send_buffer)
{
    struct tevent_req *req, *subreq;
    struct handle_oidc_child_state *state;
    int ret;
    struct io_buffer *buf = NULL;

    req = tevent_req_create(mem_ctx, &state, struct handle_oidc_child_state);
    if (req == NULL) {
        return NULL;
    }

    state->ev = ev;
    state->idp_req = idp_req;
    state->buf = NULL;
    state->len = 0;

    if (send_buffer == NULL) {
        ret = create_send_buffer(idp_req, &buf);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "create_send_buffer failed.\n");
            goto fail;
        }
    } else {
        buf = send_buffer;
    }

    /* Create new child. */
    ret = sss_child_start(state, ev,
                          OIDC_CHILD, idp_req->oidc_child_extra_args, false,
                          NULL, OIDC_CHILD_LOG_FILE, STDOUT_FILENO,
                          sss_child_handle_exited, NULL,
                          dp_opt_get_int(idp_req->idp_options, IDP_REQ_TIMEOUT),
                          sss_child_handle_timeout,
                          sss_child_create_timeout_cb_pvt(req, ETIMEDOUT),
                          true,
                          &(state->io));
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_child_start() failed.\n");
        goto fail;
    }

    /* Steal the io pair so it can outlive this request if needed. */
    talloc_steal(idp_req->idp_options, state->io);
    state->io->in_use = true;
    if (buf->size == 0) {
        FD_CLOSE(state->io->write_to_child_fd);
        subreq = read_pipe_send(state, ev, state->io->read_from_child_fd);
        if (subreq == NULL) {
            ret = ENOMEM;
            goto fail;
        }
        tevent_req_set_callback(subreq, handle_oidc_child_done, req);
        return req;
    }
    subreq = write_pipe_send(state, ev, buf->data, buf->size,
                             state->io->write_to_child_fd);
    if (!subreq) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, handle_oidc_child_send_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void handle_oidc_child_send_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct handle_oidc_child_state *state = tevent_req_data(req,
                                                struct handle_oidc_child_state);
    int ret;

    ret = write_pipe_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    FD_CLOSE(state->io->write_to_child_fd);

    subreq = read_pipe_send(state, state->ev,
                            state->io->read_from_child_fd);
    if (!subreq) {
        ret = ENOMEM;
        goto done;
    }
    tevent_req_set_callback(subreq, handle_oidc_child_done, req);

done:
    if (ret != EOK) {
        state->io->in_use = false;
        if (state->io->child_exited) {
            talloc_free(state->io);
        }

        tevent_req_error(req, ret);
    }
}

static void handle_oidc_child_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct handle_oidc_child_state *state = tevent_req_data(req,
                                                struct handle_oidc_child_state);
    int ret;

    talloc_zfree(state->io->timeout_handler);

    ret = read_pipe_recv(subreq, state, &state->buf, &state->len);
    state->io->in_use = false;
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

done:
    state->io->in_use = false;
    if (state->io->child_exited) {
        talloc_free(state->io);
    }

    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static int handle_oidc_child_raw_recv(struct tevent_req *req,
                                      TALLOC_CTX *mem_ctx,
                                      uint8_t **buf, ssize_t *len)
{
    struct handle_oidc_child_state *state = tevent_req_data(req,
                                                struct handle_oidc_child_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *buf = talloc_move(mem_ctx, &state->buf);
    *len = state->len;

    return EOK;
}

struct idp_metadata_waiter {
    struct idp_metadata_waiter *prev;
    struct idp_metadata_waiter *next;
    struct idp_metadata_cache *cache;
    struct tevent_req *req;
};

struct idp_metadata_wait_state {
    struct idp_metadata_waiter *waiter;
};

static int idp_metadata_waiter_destructor(struct idp_metadata_waiter *waiter)
{
    if (waiter->cache != NULL) {
        DLIST_REMOVE(waiter->cache->waiters, waiter);
        waiter->cache = NULL;
    }
    return 0;
}

static void idp_metadata_notify_waiters(struct idp_metadata_cache *cache,
                                         errno_t ret)
{
    struct idp_metadata_waiter *waiter;
    time_t now;

    if (ret == EOK) {
        cache->retry_after = 0;
        cache->retry_error = EOK;
    } else {
        now = time(NULL);
        cache->retry_after = now == (time_t) -1
                             ? 0 : now + IDP_METADATA_RETRY_DELAY;
        cache->retry_error = ret;
        DEBUG(SSSDBG_OP_FAILURE,
              "OpenID metadata refresh failed [%d]; retry delayed.\n", ret);
    }

    while ((waiter = cache->waiters) != NULL) {
        DLIST_REMOVE(cache->waiters, waiter);
        waiter->cache = NULL;
        if (ret == EOK) {
            tevent_req_done(waiter->req);
        } else {
            tevent_req_error(waiter->req, ret);
        }
    }
}

static errno_t idp_metadata_store(struct idp_metadata_cache *cache,
                                  const uint8_t *buf, ssize_t len)
{
    json_error_t error;
    json_t *root = NULL;
    json_t *token, *userinfo, *device, *jwks;
    TALLOC_CTX *tmp = NULL;
    char *token_copy, *userinfo_copy, *device_copy, *jwks_copy = NULL;
    time_t now;
    errno_t ret = EINVAL;

    if (len <= 0) {
        return EINVAL;
    }
    root = json_loadb((const char *) buf, len, 0, &error);
    if (!json_is_object(root)) {
        DEBUG(SSSDBG_OP_FAILURE, "Invalid OpenID metadata reply.\n");
        goto done;
    }
    token = json_object_get(root, "token_endpoint");
    userinfo = json_object_get(root, "userinfo_endpoint");
    device = json_object_get(root, "device_authorization_endpoint");
    jwks = json_object_get(root, "jwks_uri");
    if (!json_is_string(token) || !json_is_string(userinfo)
            || !json_is_string(device)
            || (jwks != NULL && !json_is_string(jwks))) {
        DEBUG(SSSDBG_OP_FAILURE, "OpenID metadata is missing an endpoint.\n");
        goto done;
    }

    tmp = talloc_new(cache);
    if (tmp == NULL) {
        ret = ENOMEM;
        goto done;
    }
    token_copy = talloc_strdup(tmp, json_string_value(token));
    userinfo_copy = talloc_strdup(tmp, json_string_value(userinfo));
    device_copy = talloc_strdup(tmp, json_string_value(device));
    if (jwks != NULL) {
        jwks_copy = talloc_strdup(tmp, json_string_value(jwks));
    }
    if (token_copy == NULL || userinfo_copy == NULL || device_copy == NULL
            || (jwks != NULL && jwks_copy == NULL)) {
        ret = ENOMEM;
        goto done;
    }
    now = time(NULL);
    if (now == (time_t) -1) {
        ret = EIO;
        goto done;
    }

    talloc_free(cache->token_endpoint);
    talloc_free(cache->userinfo_endpoint);
    talloc_free(cache->device_auth_endpoint);
    talloc_free(cache->jwks_uri);
    cache->token_endpoint = talloc_steal(cache, token_copy);
    cache->userinfo_endpoint = talloc_steal(cache, userinfo_copy);
    cache->device_auth_endpoint = talloc_steal(cache, device_copy);
    cache->jwks_uri = jwks_copy == NULL ? NULL : talloc_steal(cache, jwks_copy);
    cache->expires_at = now + cache->timeout;
    ret = EOK;

done:
    json_decref(root);
    talloc_free(tmp);
    return ret;
}

static void idp_metadata_refresh_done(struct tevent_req *subreq)
{
    struct idp_metadata_cache *cache = tevent_req_callback_data(
                                                subreq,
                                                struct idp_metadata_cache);
    uint8_t *buf = NULL;
    ssize_t len = 0;
    errno_t ret;

    ret = handle_oidc_child_raw_recv(subreq, cache, &buf, &len);
    if (ret == EOK) {
        ret = idp_metadata_store(cache, buf, len);
    }
    talloc_free(buf);
    talloc_zfree(subreq);
    cache->refresh_req = NULL;
    idp_metadata_notify_waiters(cache, ret);
}

static errno_t idp_metadata_start_refresh(struct idp_metadata_cache *cache,
                                           struct tevent_context *ev)
{
    struct idp_req *idp_req;
    struct io_buffer *empty;
    const char **args;
    const char *token_endpoint;
    const char *userinfo_endpoint;
    size_t c = 0;

    idp_req = talloc_zero(cache, struct idp_req);
    if (idp_req == NULL) {
        return ENOMEM;
    }
    idp_req->idp_options = cache->idp_options;
    args = talloc_zero_array(idp_req, const char *, 7);
    if (args == NULL) {
        talloc_free(idp_req);
        return ENOMEM;
    }
    args[c++] = "--get-openid-configuration";
    args[c] = talloc_asprintf(args, "--issuer-url=%s", cache->issuer_url);
    if (args[c++] == NULL) {
        talloc_free(idp_req);
        return ENOMEM;
    }
    if (cache->idp_type != NULL) {
        args[c] = talloc_asprintf(args, "--idp-type=%s", cache->idp_type);
        if (args[c++] == NULL) {
            talloc_free(idp_req);
            return ENOMEM;
        }
    }
    if (cache->device_auth_fallback != NULL) {
        args[c] = talloc_asprintf(args, "--device-auth-endpoint=%s",
                                    cache->device_auth_fallback);
        if (args[c++] == NULL) {
            talloc_free(idp_req);
            return ENOMEM;
        }
    }
    token_endpoint = dp_opt_get_cstring(cache->idp_options,
                                        IDP_TOKEN_ENDPOINT);
    if (token_endpoint != NULL) {
        args[c] = talloc_asprintf(args, "--token-endpoint=%s", token_endpoint);
        if (args[c++] == NULL) {
            talloc_free(idp_req);
            return ENOMEM;
        }
    }
    userinfo_endpoint = dp_opt_get_cstring(cache->idp_options,
                                           IDP_USERINFO_ENDPOINT);
    if (userinfo_endpoint != NULL) {
        args[c] = talloc_asprintf(args, "--userinfo-endpoint=%s",
                                  userinfo_endpoint);
        if (args[c++] == NULL) {
            talloc_free(idp_req);
            return ENOMEM;
        }
    }
    idp_req->oidc_child_extra_args = args;

    empty = talloc_zero(idp_req, struct io_buffer);
    if (empty == NULL) {
        talloc_free(idp_req);
        return ENOMEM;
    }
    empty->data = talloc_zero_array(empty, uint8_t, 1);
    if (empty->data == NULL) {
        talloc_free(idp_req);
        return ENOMEM;
    }

    cache->refresh_req = handle_oidc_child_raw_send(cache, ev, idp_req, empty);
    if (cache->refresh_req == NULL) {
        talloc_free(idp_req);
        return ENOMEM;
    }
    talloc_steal(cache->refresh_req, idp_req);
    tevent_req_set_callback(cache->refresh_req, idp_metadata_refresh_done,
                            cache);
    return EOK;
}

static struct tevent_req *idp_metadata_get_send(TALLOC_CTX *mem_ctx,
                                                struct tevent_context *ev,
                                                struct idp_metadata_cache *cache)
{
    struct tevent_req *req;
    struct idp_metadata_wait_state *state;
    errno_t ret;
    time_t now = time(NULL);

    req = tevent_req_create(mem_ctx, &state, struct idp_metadata_wait_state);
    if (req == NULL) {
        return NULL;
    }
    if (cache->token_endpoint != NULL && now != (time_t) -1
            && now < cache->expires_at) {
        DEBUG(SSSDBG_TRACE_FUNC, "Using cached OpenID metadata.\n");
        tevent_req_done(req);
        return tevent_req_post(req, ev);
    }
    if (now != (time_t) -1 && now < cache->retry_after) {
        DEBUG(SSSDBG_TRACE_FUNC, "OpenID metadata retry deferred.\n");
        tevent_req_error(req, cache->retry_error);
        return tevent_req_post(req, ev);
    }

    state->waiter = talloc_zero(state, struct idp_metadata_waiter);
    if (state->waiter == NULL) {
        tevent_req_error(req, ENOMEM);
        return tevent_req_post(req, ev);
    }
    state->waiter->cache = cache;
    state->waiter->req = req;
    talloc_set_destructor(state->waiter, idp_metadata_waiter_destructor);
    DLIST_ADD(cache->waiters, state->waiter);
    if (cache->refresh_req == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "Refreshing OpenID metadata.\n");
        ret = idp_metadata_start_refresh(cache, ev);
        if (ret != EOK) {
            idp_metadata_notify_waiters(cache, ret);
            tevent_req_post(req, ev);
        }
    }
    return req;
}

static errno_t idp_metadata_get_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

struct handle_oidc_child_cached_state {
    struct tevent_context *ev;
    struct idp_req *idp_req;
    struct io_buffer *send_buffer;
    uint8_t *buf;
    ssize_t len;
};

static errno_t idp_metadata_apply(struct idp_req *idp_req)
{
    const char **old_args = idp_req->oidc_child_extra_args;
    const char **new_args;
    struct idp_metadata_cache *cache = idp_req->metadata_cache;
    size_t n = 0, c = 0, i;

    while (old_args[n] != NULL) {
        n++;
    }
    new_args = talloc_zero_array(idp_req, const char *, n + 5);
    if (new_args == NULL) {
        return ENOMEM;
    }
    for (i = 0; i < n; i++) {
        if (strncmp(old_args[i], "--issuer-url=", 13) == 0
                || strncmp(old_args[i], "--token-endpoint=", 17) == 0
                || strncmp(old_args[i], "--userinfo-endpoint=", 20) == 0
                || strncmp(old_args[i], "--device-auth-endpoint=", 23) == 0
                || strncmp(old_args[i], "--jwks-uri=", 11) == 0) {
            continue;
        }
        new_args[c++] = old_args[i];
    }
    new_args[c++] = talloc_asprintf(new_args, "--token-endpoint=%s",
                                    cache->token_endpoint);
    new_args[c++] = talloc_asprintf(new_args, "--userinfo-endpoint=%s",
                                    cache->userinfo_endpoint);
    new_args[c++] = talloc_asprintf(new_args, "--device-auth-endpoint=%s",
                                    cache->device_auth_endpoint);
    if (cache->jwks_uri != NULL) {
        new_args[c++] = talloc_asprintf(new_args, "--jwks-uri=%s",
                                        cache->jwks_uri);
    }
    for (i = 0; i < c; i++) {
        if (new_args[i] == NULL) {
            talloc_free(new_args);
            return ENOMEM;
        }
    }
    idp_req->oidc_child_extra_args = new_args;
    return EOK;
}

static void handle_oidc_child_cached_done(struct tevent_req *subreq);

static errno_t handle_oidc_child_cached_start(struct tevent_req *req)
{
    struct handle_oidc_child_cached_state *state = tevent_req_data(
                                  req, struct handle_oidc_child_cached_state);
    struct tevent_req *subreq;
    errno_t ret;

    if (state->idp_req->metadata_cache != NULL
            && state->idp_req->metadata_cache->issuer_url != NULL) {
        ret = idp_metadata_apply(state->idp_req);
        if (ret != EOK) {
            return ret;
        }
    }
    subreq = handle_oidc_child_raw_send(state, state->ev, state->idp_req,
                                         state->send_buffer);
    if (subreq == NULL) {
        return ENOMEM;
    }
    tevent_req_set_callback(subreq, handle_oidc_child_cached_done, req);
    return EOK;
}

static void handle_oidc_child_metadata_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    errno_t ret = idp_metadata_get_recv(subreq);

    talloc_zfree(subreq);
    if (ret == EOK) {
        ret = handle_oidc_child_cached_start(req);
    }
    if (ret != EOK) {
        tevent_req_error(req, ret);
    }
}

struct tevent_req *handle_oidc_child_send(TALLOC_CTX *mem_ctx,
                                          struct tevent_context *ev,
                                          struct idp_req *idp_req,
                                          struct io_buffer *send_buffer)
{
    struct tevent_req *req, *subreq;
    struct handle_oidc_child_cached_state *state;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct handle_oidc_child_cached_state);
    if (req == NULL) {
        return NULL;
    }
    state->ev = ev;
    state->idp_req = idp_req;
    state->send_buffer = send_buffer;

    if (idp_req->metadata_cache != NULL
            && idp_req->metadata_cache->issuer_url != NULL) {
        subreq = idp_metadata_get_send(state, ev, idp_req->metadata_cache);
        if (subreq == NULL) {
            ret = ENOMEM;
            goto fail;
        }
        tevent_req_set_callback(subreq, handle_oidc_child_metadata_done, req);
    } else {
        ret = handle_oidc_child_cached_start(req);
        if (ret != EOK) {
            goto fail;
        }
    }
    return req;

fail:
    tevent_req_error(req, ret);
    return tevent_req_post(req, ev);
}

static void handle_oidc_child_cached_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct handle_oidc_child_cached_state *state = tevent_req_data(
                                  req, struct handle_oidc_child_cached_state);
    errno_t ret;

    ret = handle_oidc_child_raw_recv(subreq, state, &state->buf, &state->len);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
    } else {
        tevent_req_done(req);
    }
}

int handle_oidc_child_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                           uint8_t **buf, ssize_t *len)
{
    struct handle_oidc_child_cached_state *state = tevent_req_data(
                                  req, struct handle_oidc_child_cached_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *buf = talloc_move(mem_ctx, &state->buf);
    *len = state->len;
    return EOK;
}

errno_t set_oidc_common_args(const char **extra_args, size_t *c,
                             const char *idp_type,
                             const char *issuer_url,
                             const char *client_id,
                             const char *client_secret,
                             const char *token_endpoint,
                             const char *scope)
{
    int ret;

    if (idp_type != NULL) {
        extra_args[*c] = talloc_asprintf(extra_args,
                                         "--idp-type=%s", idp_type);
        if (extra_args[*c] == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
            ret = ENOMEM;
            goto done;
        }
        (*c)++;
    }

    if (issuer_url != NULL) {
        extra_args[*c] = talloc_asprintf(extra_args,
                                         "--issuer-url=%s", issuer_url);
        if (extra_args[*c] == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
            ret = ENOMEM;
            goto done;
        }
        (*c)++;
    }

    extra_args[*c] = talloc_asprintf(extra_args,
                                     "--client-id=%s", client_id);
    if (extra_args[*c] == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }
    (*c)++;

    if (client_secret != NULL) {
        extra_args[*c] = talloc_strdup(extra_args,
                                       "--client-secret-stdin");
        if (extra_args[*c] == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
            ret = ENOMEM;
            goto done;
        }
        (*c)++;
    }

    if (token_endpoint != NULL) {
        extra_args[*c] = talloc_asprintf(extra_args,
                                         "--token-endpoint=%s", token_endpoint);
        if (extra_args[*c] == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
            ret = ENOMEM;
            goto done;
        }
        (*c)++;
    }

    extra_args[*c] = talloc_asprintf(extra_args,
                                     "--scope=%s", scope);
    if (extra_args[*c] == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }
    (*c)++;

    ret = EOK;
done:

    return ret;
}
