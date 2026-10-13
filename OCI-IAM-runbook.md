# OCI IAM Device Code login on Oracle Linux 10

This runbook configures an Oracle Linux 10 host to obtain OCI IAM users/groups
through SCIM and authenticate SSH users with the OAuth 2.0 Device Code flow.
It covers two installation paths for the `oci-iam-idp-refactor` branch: build
the RPMs locally or install them from the Object Storage DNF repository.

The refactor branch adds issuer-based OIDC endpoint discovery and backend
metadata caching. Both paths use the same SSSD configuration below.

Never put the OCI client secret in Git, shell history, chat, or a ticket.

## Design

SSSD has two separate OCI flows:

| Requirement | SSSD flow | OCI IAM interface |
| --- | --- | --- |
| Users, groups, memberships | ID provider lookup | Client Credentials grant and SCIM |
| Interactive SSH login | PAM authentication | Device Code flow and OIDC userinfo |

`access_provider = simple` plus `simple_allow_groups` is authorization. It
limits which OCI IAM users may log in; it does not authenticate them.

## OCI IAM prerequisites

Create a confidential OCI IAM application with:

1. Client ID and Client Secret.
2. Client Credentials access for OCI SCIM identity/group lookups.
3. Device Authorization enabled for browser authentication.
4. An access-control group, for example `OL10_SSH_Users`.

The identity-domain issuer is `https://<DOMAIN>.identity.oraclecloud.com`.
The refactor build discovers its token and userinfo URLs from the issuer's
OpenID configuration. OCI IAM does not advertise a device authorization
endpoint in the tested metadata, so configure this endpoint as a fallback:

```text
device: https://<DOMAIN>.identity.oraclecloud.com/oauth2/v1/device
```

Use the same identity-domain host for the issuer, SCIM base URI, and device URL.

## Choose an RPM installation path

Choose **one** of these paths before continuing to [Configure SSSD](#configure-sssd):

| Path | Use it when | What the host does |
| --- | --- | --- |
| **A. Build the refactor locally** | Developing or building RPMs on this host | Builds and installs RPMs from the refactor source checkout |
| **B. Install from Object Storage** | Installing the packaged build on a host | Adds the public DNF repository and installs its matching RPMs |

Do not build on every target host when using the repository path.

## Path A: Build and install the custom RPMs locally

Enable the Oracle Linux developer repository first:

```bash
sudo dnf config-manager --enable ol10_codeready_builder
sudo dnf makecache
```

Install the build dependencies:

```bash
sudo dnf install -y \
  git gcc make m4 autoconf automake libtool rpm-build rpmdevtools createrepo_c \
  bind-utils bc findutils c-ares-devel check-devel cifs-utils-devel dbus-devel \
  docbook-style-xsl doxygen gettext-devel po4a gdm-pam-extensions-devel \
  jansson-devel libcap-devel libcurl-devel libjose-devel keyutils-libs-devel \
  krb5-devel krb5-libs libcmocka-devel libdhash-devel libfido2-devel \
  libini_config-devel libldb-devel libnfsidmap-devel libnl3-devel \
  libselinux-devel libsemanage-devel libsmbclient-devel libtalloc-devel \
  libtdb-devel libtevent-devel libunistring libunistring-devel libuuid-devel \
  libxml2 libxslt nss_wrapper openldap-devel openssl openssl-devel p11-kit-devel \
  pam-devel pam_wrapper pcre2-devel popt-devel python3-devel python3-setuptools \
  samba-devel samba-winbind selinux-policy-targeted shadow-utils-subid-devel \
  softhsm systemd-devel systemd-rpm-macros systemtap-sdt-devel \
  systemtap-sdt-dtrace uid_wrapper valgrind-devel gnutls-utils openssh
```

Use an existing copy of the `oci-iam-idp-refactor` checkout on the build host,
or clone the branch through HTTPS unless the server has a GitHub SSH key:

```bash
git clone --branch oci-iam-idp-refactor https://github.com/chintala-chaitanya/sssd.git \
  "$HOME/sssd-oci-iam"
cd "$HOME/sssd-oci-iam"
```

If using an existing local checkout, change into that checkout instead of
cloning. Verify that it is on `oci-iam-idp-refactor` before building.

Bootstrap, generate the real RPM spec, and build:

```bash
autoreconf -ivf > "$HOME/sssd-autoreconf.log" 2>&1
./configure > "$HOME/sssd-configure.log" 2>&1
ls -l Makefile config.status contrib/sssd.spec

sudo dnf builddep -y --spec contrib/sssd.spec
make -j2 rpms > "$HOME/sssd-rpmbuild.log" 2>&1
tail -n 40 "$HOME/sssd-rpmbuild.log"
```

Do not use `contrib/sssd.spec.in` with `dnf builddep`: it is a template with
unexpanded `@PACKAGE_NAME@` tokens. `contrib/sssd.spec` appears only after
`./configure`. If `autoreconf` cannot find `autopoint`, install
`gettext-devel`.

### Install the locally built RPM family

The build produces both `x86_64` and `noarch` RPMs. On a new host do not
install only `sssd-idp`: `pam_sss.so` belongs to `sssd-client`, and
`sssd-tools` needs the noarch `python3-sssdconfig` package.

```bash
createrepo_c --update "$HOME/sssd-oci-iam/rpmbuild/RPMS/x86_64"
createrepo_c --update "$HOME/sssd-oci-iam/rpmbuild/RPMS/noarch"

sudo dnf install -y --allowerasing \
  --repofrompath=sssd-local-x86_64,"file://$HOME/sssd-oci-iam/rpmbuild/RPMS/x86_64" \
  --repofrompath=sssd-local-noarch,"file://$HOME/sssd-oci-iam/rpmbuild/RPMS/noarch" \
  --setopt=sssd-local-x86_64.gpgcheck=0 \
  --setopt=sssd-local-noarch.gpgcheck=0 \
  sssd sssd-idp sssd-tools

rpm -q sssd sssd-idp sssd-client sssd-common sssd-tools
rpm -qf /usr/lib64/security/pam_sss.so
rpm -ql sssd-idp | grep '/oidc_child$'
```

All installed SSSD packages should show the same custom version.

## Path B: Install from the Object Storage repository

Use the public DNF repository for the matching SSSD RPM set:

```text
https://objectstorage.us-ashburn-1.oraclecloud.com/n/id3kvohtwgjy/b/sssd-oci-iam-rpms/o/sssd/2.14.0-oci.1/
```

Create the DNF repository definition:

```bash
sudoedit /etc/yum.repos.d/sssd-oci-iam.repo
```

```ini
[sssd-oci-iam]
name=Custom SSSD OCI IAM 2.14.0
baseurl=https://objectstorage.us-ashburn-1.oraclecloud.com/n/id3kvohtwgjy/b/sssd-oci-iam-rpms/o/sssd/2.14.0-oci.1/
enabled=1
gpgcheck=0
repo_gpgcheck=0
metadata_expire=300
```

Validate that DNF can read the repository and selects the intended SSSD
build. Then install the complete matching SSSD family:

```bash
sudo dnf clean all
sudo dnf repolist
sudo dnf repoquery --available sssd sssd-idp sssd-client sssd-tools

sudo dnf install -y --allowerasing sssd sssd-idp sssd-tools

rpm -q sssd sssd-idp sssd-client sssd-common sssd-tools
rpm -qf /usr/lib64/security/pam_sss.so
rpm -ql sssd-idp | grep '/oidc_child$'
```

## Configure SSSD

For RPMs built from `oci-iam-idp-refactor`, create `/etc/sssd/sssd.conf` and
replace all placeholders:

```ini
[sssd]
services = nss, pam
domains = oci_iam

[domain/oci_iam]
id_provider = idp
access_provider = simple
simple_allow_groups = OL10_SSH_Users

idp_type = oci_iam:https://<DOMAIN>.identity.oraclecloud.com
idp_client_id = <CLIENT_ID>
idp_client_secret = <CLIENT_SECRET>
idp_issuer_url = https://<DOMAIN>.identity.oraclecloud.com
# Fallback: the tested OCI IAM metadata does not advertise this endpoint.
idp_device_auth_endpoint = https://<DOMAIN>.identity.oraclecloud.com/oauth2/v1/device
idp_metadata_cache_timeout = 3600

# Identity/group lookup with Client Credentials
idp_id_scope = urn:opc:idm:__myscopes__

# Interactive Device Code authentication
idp_auth_scope = openid profile

# Initial cache policy; tune to the required revocation speed and availability.
entry_cache_user_timeout = 300
entry_cache_group_timeout = 300

[nss]
default_shell = /bin/bash
fallback_homedir = /home/%f
memcache_timeout = 60
entry_cache_nowait_percentage = 0

[prompting/oauth2/sshd]
interactive = true
interactive_prompt = Complete OCI IAM authentication in the browser, then press ENTER.
```

`idp_type` selects the OCI IAM SCIM adapter; `idp_issuer_url` supplies the OIDC
issuer for endpoint discovery. The refactor caches discovered metadata in the
SSSD backend for the configured number of seconds (3600 by default). When an
issuer is set, discovered token and userinfo endpoints take precedence over
explicit endpoint values. The configured device URL is used only if discovery
does not advertise one. The cache is shared by requests handled by that
backend and is reset when SSSD restarts.

Protect the secret:

```bash
sudo chown root:sssd /etc/sssd/sssd.conf
sudo chmod 0640 /etc/sssd/sssd.conf
sudo stat -c '%a %U:%G %n' /etc/sssd/sssd.conf
```

Expected mode/ownership is `640 root:sssd`.

## Authselect and PAM

Never edit generated `/etc/pam.d/system-auth` or `password-auth` directly.
Create or reuse a custom authselect profile:

```bash
sudo authselect current
sudo authselect create-profile oci-iam -b sssd
sudo authselect select custom/oci-iam
```

If the host already has an organization custom profile, copy and modify that
profile rather than selecting a new base profile.

Edit both custom-template files:

```bash
sudoedit /etc/authselect/custom/oci-iam/system-auth
sudoedit /etc/authselect/custom/oci-iam/password-auth
```

In the `auth` section, make these two changes in **each** template:

1. Locate the ordinary `pam_sss.so` line. If it contains `forward_pass`, remove
   that option:

   ```pam
   # Before
   auth    sufficient    pam_sss.so forward_pass

   # After
   auth    sufficient    pam_sss.so
   ```

2. Move that plain line so it is immediately below the
   `pam_faillock.so preauth` line. Remove the original copy, so the plain
   `pam_sss.so` line occurs only once in the `auth` section.

   ```pam
   auth    required      pam_env.so
   auth    required      pam_faildelay.so delay=2000000
   auth    required      pam_faillock.so preauth silent
   auth    sufficient    pam_sss.so
   ```

   Leave all following lines in their existing order. In particular, do not
   use `pam_usertype.so` or `pam_localuser.so` as the insertion point; the
   required placement is directly after `pam_faillock.so preauth`.

This ordering is required because Device Code needs `pam_sss` to request SSSD
pre-authentication before the normal password path is reached.

```bash
sudo authselect apply-changes
sudo grep -nE 'pam_(faillock|sss|usertype|localuser|unix)[.]so' \
  /etc/pam.d/system-auth \
  /etc/pam.d/password-auth
```

In the `auth` portion of both generated files, confirm this order:

```text
pam_sss.so
pam_usertype.so
pam_localuser.so
pam_unix.so
```

The `pam_sss.so` authentication line must not contain `forward_pass`. You will
also see later `pam_unix.so` and `pam_sss.so` entries for the `account`,
`password`, and `session` portions; those are expected and must not be moved.

## First-login home directories

Home-directory creation is not required to authenticate, but without it a
successful user login may start in `/` with a missing-home warning.

```bash
sudo dnf install -y oddjob oddjob-mkhomedir
sudo systemctl enable --now oddjobd.service
sudo authselect enable-feature with-mkhomedir
sudo authselect apply-changes
```

## SSH configuration

Check the currently effective SSH settings before changing them:

```bash
sudo sshd -T | grep -E '^(usepam|kbdinteractiveauthentication|logingracetime) '
```

Create `/etc/ssh/sshd_config.d/40-oci-iam-device-code.conf`:

```text
UsePAM yes
KbdInteractiveAuthentication yes
LoginGraceTime 5m
```

Validate and reload:

```bash
sudo sshd -t
sudo sshd -T | grep -E 'usepam|kbdinteractiveauthentication|logingracetime|pubkeyauthentication|passwordauthentication'
sudo systemctl reload sshd
```

Do not disable public-key authentication. Existing local users such as `opc`
can continue using cloud-init `authorized_keys`; OCI IAM Device Code is a
separate keyboard-interactive/PAM method. `PasswordAuthentication no` is
compatible with Device Code.

`LoginGraceTime 5m` gives the user enough time to open the Device Code URL and
complete browser sign-in and MFA. If the grace period expires, OpenSSH closes
the unauthenticated connection and can temporarily penalize repeated attempts
from the same source IP; those retries may be closed before displaying a new
Device Code prompt.

## Validate

```bash
sudo systemctl enable --now sssd
sudo sss_cache -E

LOGIN_USER='example.user@oci_iam'
getent passwd "$LOGIN_USER"
id "$LOGIN_USER"
getent initgroups "$LOGIN_USER"
getent group OL10_SSH_Users

sudo sssctl user-checks --action auth --service sshd "$LOGIN_USER"
```

The final command must show a Device Code URL and PIN. From another machine,
use the short Linux username when it is unambiguous:

```bash
ssh -l "username" <LINUX_HOST>
```

For an OCI IAM username that is an email address, strip the email domain for
the Linux login. For example, use `ssh -l 'chaitanya.c.chintala' <LINUX_HOST>`
when the OCI IAM username is `chaitanya.c.chintala@oracle.com`. This short-name
SSH login was tested on an OL10 host with only the `oci_iam` SSSD domain. If
another SSSD domain or a local user has the same short name, use the explicit
SSSD domain form `ssh -l 'chaitanya.c.chintala@oci_iam' <LINUX_HOST>` to avoid
ambiguity. Do **not** use `chaitanya.c.chintala@oracle.com@oci_iam`. In the
browser Device Code step, always sign in with the full OCI IAM username.

Keep an existing administrator session open while testing. Validate both an
allowed OCI user and a user removed from `OL10_SSH_Users`.

`getent passwd` refers to the Unix account database, not passwords. NSS routes
the lookup to SSSD through `/etc/nsswitch.conf`; SSSD serves cache data or
retrieves current OCI IAM data as necessary.

## Cache and operations

The upstream default `entry_cache_timeout` is 5400 seconds (90 minutes).
The five-minute values above are an initial privileged-access policy; choose
values appropriate for required revocation speed, availability, and OCI load.
These identity/group caches are separate from the refactor's OIDC metadata
cache. Metadata refresh failures are retried after five seconds rather than
once per request; that retry delay does not cache user or group data.
Do not use `sss_cache -E` as a normal operations process. It is useful for
validation and emergency troubleshooting.

The adapter generates deterministic POSIX UID/GID mappings from immutable OCI
SCIM identifiers and SSSD idmap inputs. Use the same endpoint and idmap policy
on every host for consistent IDs. An OCI user recreated with a new SCIM ID is a
new Linux identity even if it has the same name.

After group membership removal, refresh during testing:

```bash
sudo systemctl restart sssd
sudo sss_cache -E
id 'removed.user@oci_iam'
getent group OL10_SSH_Users
```

The custom branch includes a fix that removes stale cached supplementary group
memberships when OCI returns an authoritative empty membership result.

After validation, remove any temporary debug settings, diagnostic PAM service,
and matching `[prompting/oauth2/<test-service>]` configuration. Rotate a client
secret if it was exposed through terminal capture, chat, screen share, or shell
history.

## Fleet rollout

Build and test one fixed commit, then publish the complete signed RPM set from
both `rpmbuild/RPMS/x86_64` and `rpmbuild/RPMS/noarch` to an internal DNF/YUM
repository. Distribute the repository definition, matching SSSD RPM family,
secret-managed `sssd.conf`, custom authselect profile, SSH drop-in, and
home-directory policy through the approved configuration-management process.

The RPMs contain SSSD code. The SSSD configuration, authselect profile, SSH
configuration, access group, cache policy, and client-secret handling are
host configuration and must be deployed separately.
