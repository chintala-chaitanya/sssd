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

#ifndef __OIDC_PROVIDER_H__
#define __OIDC_PROVIDER_H__

#include <stdbool.h>

/*
 * The configured client authentication method applies to token requests. A
 * device authorization endpoint can independently require no client
 * authentication for the initial device-code request.
 */
enum oidc_device_code_client_auth {
    OIDC_DEVICE_CODE_USE_CONFIGURED_CLIENT_AUTH = 0,
    OIDC_DEVICE_CODE_NO_CLIENT_AUTH,
};

enum oidc_provider_kind {
    OIDC_PROVIDER_ENTRA_ID = 0,
    OIDC_PROVIDER_KEYCLOAK,
    OIDC_PROVIDER_OCI_IAM,
};

struct oidc_provider_behavior {
    enum oidc_provider_kind kind;
    const char *authenticated_user_claim;
    enum oidc_device_code_client_auth device_code_client_auth;
    bool device_code_requires_response_type;
    bool require_https_endpoints;
};

const struct oidc_provider_behavior *oidc_provider_get_behavior(
                                                            const char *idp_type);

#endif /* __OIDC_PROVIDER_H__ */
