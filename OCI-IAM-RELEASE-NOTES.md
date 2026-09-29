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
- Maps OCI email-style `userName` values to a Linux-safe short username. For
  example, `alice@example.com` is exposed as `alice`; the complete OCI
  `userName` is retained internally for OIDC authentication matching.
- Rejects ambiguous OCI responses where multiple identities map to the same
  Linux username.
- Refreshes cached supplementary group memberships authoritatively, so removed
  IdP group membership does not continue to grant access from cache.

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

## Related documentation

- `src/man/sssd-idp.5.xml` documents the `oci_iam` provider configuration.
- `OCI-IAM-runbook.md` contains the complete OL10 deployment procedure,
  including PAM, SSH, access-group, cache, and Device Code timeout guidance.
