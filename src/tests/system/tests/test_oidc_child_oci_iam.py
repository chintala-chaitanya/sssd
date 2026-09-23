"""
OCI IAM oidc_child contract tests.

These tests run only when a CI job supplies a dedicated OCI IAM test domain.
They deliberately read the client secret from the test runner environment and
pass it to oidc_child over standard input, never on the command line.
"""

from __future__ import annotations

import json
import os
import shlex

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.topology import KnownTopology


OIDC_CHILD = "/usr/libexec/sssd/oidc_child"
REQUIRED_ENVIRONMENT = (
    "SSSD_TEST_OCI_IAM_BASE_URL",
    "SSSD_TEST_OCI_IAM_CLIENT_ID",
    "SSSD_TEST_OCI_IAM_CLIENT_SECRET",
    "SSSD_TEST_OCI_IAM_USER",
    "SSSD_TEST_OCI_IAM_GROUP",
)
MISSING_ENVIRONMENT = [name for name in REQUIRED_ENVIRONMENT if not os.environ.get(name)]

pytestmark = pytest.mark.skipif(
    MISSING_ENVIRONMENT,
    reason="OCI IAM contract-test environment is not configured: " + ", ".join(MISSING_ENVIRONMENT),
)


def _environment(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    assert value is not None
    return value


def _identity_args() -> list[str]:
    base_url = _environment("SSSD_TEST_OCI_IAM_BASE_URL").rstrip("/")
    return [
        "--logger=stderr",
        "--idp-type=" + "oci_iam:" + base_url,
        "--token-endpoint=" + base_url + "/oauth2/v1/token",
        "--client-id=" + _environment("SSSD_TEST_OCI_IAM_CLIENT_ID"),
        "--client-secret-stdin",
        "--scope=" + _environment("SSSD_TEST_OCI_IAM_ID_SCOPE", "urn:opc:idm:__myscopes__"),
    ]


def _run_identity_lookup(client: Client, action: str, name: str):
    command = shlex.join([OIDC_CHILD, *_identity_args(), action, "--name=" + name])
    return client.host.conn.run(command, input=_environment("SSSD_TEST_OCI_IAM_CLIENT_SECRET"))


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.Client)
def test_oidc_child_oci_iam__identity_and_membership(client: Client):
    """
    :title: Look up OCI IAM identities and memberships safely
    :setup:
        1. Supply a dedicated OCI IAM test application and user/group through
           SSSD_TEST_OCI_IAM_* CI environment variables.
    :steps:
        1. Look up a user, its groups, a group, and the group's members.
    :expectedresults:
        1. OCI IAM data is normalized into SSSD identity-provider objects.
        2. An email userName exposes only its local part as the POSIX name.
    :customerscenario: False
    """

    user = _environment("SSSD_TEST_OCI_IAM_USER")
    group = _environment("SSSD_TEST_OCI_IAM_GROUP")
    expected_posix_user = _environment("SSSD_TEST_OCI_IAM_POSIX_USER", user.rsplit("@", 1)[0])

    user_data = json.loads(_run_identity_lookup(client, "--get-user", user).stdout)
    assert user_data[0]["posixUsername"] == expected_posix_user
    assert user_data[0]["idpUserIdentifier"] == user

    groups_data = json.loads(_run_identity_lookup(client, "--get-user-groups", user).stdout)
    assert group in [item["posixGroupname"] for item in groups_data]

    group_data = json.loads(_run_identity_lookup(client, "--get-group", group).stdout)
    assert group_data[0]["posixGroupname"] == group

    members_data = json.loads(_run_identity_lookup(client, "--get-group-members", group).stdout)
    assert expected_posix_user in [item["posixUsername"] for item in members_data]


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.Client)
def test_oidc_child_oci_iam__device_code_request(client: Client):
    """
    :title: Request an OCI IAM device code
    :setup:
        1. Supply a dedicated OCI IAM test application through
           SSSD_TEST_OCI_IAM_* CI environment variables.
    :steps:
        1. Request a Device Authorization Grant from OCI IAM.
    :expectedresults:
        1. oidc_child returns a device code and browser verification details.
    :customerscenario: False
    """

    base_url = _environment("SSSD_TEST_OCI_IAM_BASE_URL").rstrip("/")
    command = shlex.join(
        [
            OIDC_CHILD,
            "--logger=stderr",
            "--get-device-code",
            "--idp-type=" + "oci_iam:" + base_url,
            "--device-auth-endpoint=" + base_url + "/oauth2/v1/device",
            "--token-endpoint=" + base_url + "/oauth2/v1/token",
            "--userinfo-endpoint=" + base_url + "/oauth2/v1/userinfo",
            "--client-id=" + _environment("SSSD_TEST_OCI_IAM_CLIENT_ID"),
            "--client-secret-stdin",
            "--scope=" + _environment("SSSD_TEST_OCI_IAM_AUTH_SCOPE", "openid profile"),
        ]
    )
    result = client.host.conn.run(command, input=_environment("SSSD_TEST_OCI_IAM_CLIENT_SECRET"))

    device_data = json.loads(result.stdout_lines[0])
    assert "device_code" in device_data
    assert "expires_in" in device_data
    assert "interval" in device_data

    assert result.stdout_lines[1].startswith("oauth2 {")
    browser_data = json.loads(result.stdout_lines[1][7:])
    assert "verification_uri" in browser_data
    assert "user_code" in browser_data
