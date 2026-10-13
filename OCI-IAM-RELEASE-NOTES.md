# OCI IAM Identity Domain adapter — release notes

## Summary

This branch adds OCI IAM Identity Domain support to SSSD's IdP provider. On
Linux hosts using SSSD, it can:

- resolve OCI IAM users, groups, and group membership through OCI SCIM APIs;
- authenticate users through the OAuth 2.0 Device Code flow; and
- authorize SSH access with existing SSSD access controls, for example
  `access_provider = simple` and `simple_allow_groups`.

The adapter is selected with:

```ini
id_provider = idp
idp_type = oci_iam:https://<IDENTITY-DOMAIN>.identity.oraclecloud.com
```

## Functional changes

- Adds `oci_iam` as a supported SSSD IdP type.
- Implements OCI SCIM lookups for users, groups, user group memberships, and
  group members, including paginated SCIM responses.
- Sends OCI IAM's required `response_type=device_code` parameter when
  requesting a device code, without client authentication on that request.
- Handles OCI responses that omit the optional Device Code polling interval by
  using the RFC 8628 default of five seconds.
- Discovers OIDC endpoints from the configured issuer while honoring explicit
  endpoint settings first. Discovery fills only the endpoints not configured;
  this supports OCI IAM's explicit device endpoint and Entra ID's Graph `/me`
  userinfo endpoint without provider-specific endpoint branches.
- Adds `idp_auth_user_identifier_attr` so a configured identifier claim
  overrides the provider default; this does not include upstream's separate
  hybrid AD/Entra identifier conversion logic.
- Caches discovered endpoint metadata in the SSSD backend (default: one hour),
  coalesces concurrent refreshes, and waits five seconds before retrying a
  failed refresh. This cache is separate from user/group identity caches.
- Maps OCI SCIM object IDs deterministically to SSSD-generated UID/GID values.
- Allows a stable `idp_idmap_seed` to preserve those numeric IDs when moving
  from an explicit token endpoint to issuer discovery.
- Maps OCI email-style `userName` values to a Linux-facing short username. For
  example, `alice@example.com` is exposed as `alice`; the complete OCI
  `userName` is retained internally for OIDC authentication matching.
- Rejects ambiguous OCI responses where multiple identities map to the same
  Linux username.
- Refreshes cached supplementary group memberships authoritatively, so removed
  IdP group membership does not continue to grant access from cache.

## File-change rationale

| File | Why it changed |
| --- | --- |
| `src/oidc_child/oidc_child_id.c` | Primary OCI IAM adapter: OCI SCIM requests, pagination, filter escaping, object normalization, email-name mapping, and provider dispatch. |
| `src/oidc_child/oidc_child.c` | Recognizes OCI IAM configuration and rejects insecure OCI endpoint URLs. |
| `src/oidc_child/oidc_child_curl.c` | Sends the OCI-required device-code parameter and selects device-request client authentication from shared provider behavior. |
| `src/oidc_child/oidc_child_util.h` | Carries provider behavior through the shared Device Code flow. |
| `src/oidc_child/oidc_child_json.c` | Uses RFC 8628's five-second fallback when a Device Code response omits `interval`, and merges explicit endpoint values with discovered metadata. |
| `src/db/sysdb.h` | Defines the cached full IdP user identifier attribute. |
| `src/providers/idp/idp_id_eval.c` and `idp_id.h` | Store OCI's full `userName` for authentication matching, remove stale cached supplementary memberships on refresh, and use the configured stable ID-mapping seed. |
| `src/providers/idp/idp_auth.c` | Selects the OIDC `sub` claim as OCI IAM's default authenticated-user identifier while honoring a configured identifier claim. |
| `src/providers/idp/idp_auth_eval.c` | Validates the OIDC `sub` claim against the cached full OCI identifier rather than the SCIM object ID. |
| `src/util/oidc_provider.c` and `.h` | Define the shared provider-behavior table and enum instead of an OCI-specific boolean in the Device Code path. |
| `src/providers/idp/oidc_child_handler.c` and `idp_common.h` | Discover and cache OIDC metadata once per backend cache lifetime, apply explicit endpoint overrides, share in-flight refreshes, and delay retries after a failed refresh. |
| `src/providers/idp/idp_opts.c`, `idp_init.c`, `idp_auth.h`, and `src/config/cfg_rules.ini` | Add the configurable authenticated-user claim and stable ID-mapping seed while preserving existing mapping behavior by default. |
| `src/man/sssd-idp.5.xml` | Documents OCI IAM configuration, issuer discovery, metadata-cache lifetime, HTTPS requirements, and Linux username mapping. |
| `src/tests/system/tests/test_oidc_child.py` | Adds regression coverage for HTTPS-only OCI endpoints and explicit endpoint precedence. |
| `src/tests/system/tests/test_idp.py` | Adds regression coverage for removal of stale IdP group memberships. |
| `src/tests/system/tests/test_oidc_child_oci_iam.py` | New OCI IAM contract tests for SCIM lookups and Device Code behavior. |
| `OCI-IAM-runbook.md` | New operational guide for building, deploying, configuring, and testing on OL10. |

## Security and compatibility

- OCI IAM SCIM, OAuth, OIDC, and Device Authorization endpoints must use HTTPS.
- OCI SCIM filter values are escaped before they are sent to the remote API.
- OCI client secrets are read from SSSD configuration or standard input; tests
  do not place them on a command line.
- Existing Entra ID and Keycloak behavior is retained. The group-membership
  cache-refresh fix also benefits existing IdP providers.
- OCI email local parts must be unique within an Identity Domain for Linux
  login purposes. Two users such as `alice@example.com` and
  `alice@another.example` cannot safely share one SSSD domain.

## Packaging

The IdP adapter and the backend metadata cache are delivered across SSSD's
version-matched subpackages, including `sssd-idp` and `sssd-common`. A
deployment repository should publish the complete matching RPM set produced
by the build, not only `sssd-idp`. The runbook covers building this RPM set
locally or installing the matching build from the Object Storage DNF
repository.

## Validation performed

On Oracle Linux 10, the implementation was validated with an OCI IAM Identity
Domain for:

- client-credentials SCIM user, group, user-group, and group-member lookups;
- Device Code acquisition and browser authentication;
- SSSD/NSS lookup through `getent` and `id`;
- SSSD/PAM authentication through `sssctl user-checks`;
- interactive SSH Device Code login;
- short-name SSH login without `@oci_iam` on a single-domain host with no
  conflicting local username;
- `simple_allow_groups` authorization and access revocation after membership
  removal; and
- automatic first-login home-directory creation with `oddjob-mkhomedir`.

The refactor build was also exercised against OCI IAM for issuer discovery,
backend metadata reuse, concurrent lookups sharing one refresh, and a
five-second retry delay after failed discovery. The OL10 RPM build completed
with 102 packaged tests passed, two skipped, and none failed. After those
RPMs were installed on the test host, short-name SSH login completed the OCI
IAM Device Code flow. Keycloak was not live-tested for this refactor.

For the endpoint-precedence update, a fresh OL10 RPM build also passed with
102 packaged tests passed, two skipped, and none failed. The built
`oidc_child` returned explicit endpoint overrides while discovering the
remaining values from both OCI IAM and Microsoft Entra metadata. On the OCI
test host, removing explicit token/userinfo endpoints and pinning
`idp_idmap_seed` to the former token URL retained the same UID, GID, and group
membership. Without that pin, the UID changed; the tested OCI metadata spells
the token URL with `:443`, and the default mapping seed switches from the
explicit token URL to the issuer URL. The host's original configuration was
restored after testing. The new RPMs also passed an Entra SSSD/NSS lookup with
token and device endpoints discovered, Graph `/me` configured explicitly, and
the original UID and allow-group membership retained through a pinned seed.
An interactive Entra SSH login with this latest build also completed the
Device Code flow successfully. The Entra host's original SSSD configuration
was restored afterward. A live Keycloak system-test run remains pending.

## Files added

- `src/tests/system/tests/test_oidc_child_oci_iam.py`: OCI IAM contract tests,
  enabled only when dedicated CI environment variables are supplied.
- `OCI-IAM-runbook.md`: OL10 build, installation, configuration, and operation
  guide.
- `OCI-IAM-RELEASE-NOTES.md`: reviewer-oriented summary of the implementation,
  security considerations, validation, and file-level rationale.

## Related documentation

- `src/man/sssd-idp.5.xml` documents the `oci_iam` provider configuration and
  issuer-based metadata discovery.
- `OCI-IAM-runbook.md` contains the complete OL10 deployment procedure,
  including PAM, SSH, access-group, cache, and Device Code timeout guidance.
