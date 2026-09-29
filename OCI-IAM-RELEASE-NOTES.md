# OCI IAM Identity Domain adapter — release notes

## Summary

This branch adds OCI IAM Identity Domain support to SSSD's IdP provider. It
allows Oracle Linux hosts to:

- resolve OCI IAM users, groups, and group membership through OCI SCIM APIs;
- authenticate users through OAuth 2.0 Device Authorization Grant; and
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
- Uses OCI IAM's Device Authorization request shape, including
  `response_type=device_code`.
- Handles OCI responses that omit the optional Device Code polling interval by
  using the RFC 8628 default of five seconds.
- Maps OCI SCIM object IDs deterministically to SSSD-generated UID/GID values.
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
| `src/oidc_child/oidc_child_curl.c` | Uses OCI IAM's Device Authorization request format. |
| `src/oidc_child/oidc_child_util.h` | Carries OCI-provider context through the shared Device Code flow. |
| `src/oidc_child/oidc_child_json.c` | Uses RFC 8628's five-second fallback when a Device Code response omits `interval`. |
| `src/db/sysdb.h` | Defines the cached full IdP user identifier attribute. |
| `src/providers/idp/idp_id_eval.c` | Stores OCI's full `userName` for authentication matching and removes stale cached supplementary memberships on refresh. |
| `src/providers/idp/idp_auth.c` | Selects the OIDC `sub` claim as OCI IAM's authenticated-user identifier. |
| `src/providers/idp/idp_auth_eval.c` | Validates the OIDC `sub` claim against the cached full OCI identifier rather than the SCIM object ID. |
| `src/man/sssd-idp.5.xml` | Documents OCI IAM configuration, HTTPS requirements, and Linux username mapping. |
| `src/tests/system/tests/test_oidc_child.py` | Adds regression coverage for HTTPS-only OCI endpoints. |
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

The runtime implementation is delivered by the `sssd-idp` RPM. Because SSSD
subpackages have version-matched dependencies, a deployment repository should
publish the complete matching RPM set produced by the build, not only
`sssd-idp`.

## Validation performed

On Oracle Linux 10, the implementation was validated with an OCI IAM Identity
Domain for:

- client-credentials SCIM user, group, user-group, and group-member lookups;
- Device Code acquisition and browser authentication;
- SSSD/NSS lookup through `getent` and `id`;
- SSSD/PAM authentication through `sssctl user-checks`;
- interactive SSH Device Code login;
- `simple_allow_groups` authorization and access revocation after membership
  removal; and
- automatic first-login home-directory creation with `oddjob-mkhomedir`.

## Files added

- `src/tests/system/tests/test_oidc_child_oci_iam.py`: OCI IAM contract tests,
  enabled only when dedicated CI environment variables are supplied.
- `OCI-IAM-runbook.md`: OL10 build, installation, configuration, and operation
  guide.
- `OCI-IAM-RELEASE-NOTES.md`: reviewer-oriented summary of the implementation,
  security considerations, validation, and file-level rationale.

## Related documentation

- `src/man/sssd-idp.5.xml` documents the `oci_iam` provider configuration.
- `OCI-IAM-runbook.md` contains the complete OL10 deployment procedure,
  including PAM, SSH, access-group, cache, and Device Code timeout guidance.
