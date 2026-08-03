# Two-factor authentication (TOTP)

LLDAP can require a time-based one-time password (TOTP, RFC 6238: SHA-1,
6 digits, 30 second step) as a second factor. Storage uses the existing
`totp_secret` and `mfa_type` columns — no database migration is required.

This page is the full reference for enabling, enrolling, logging in,
resetting, and deploying MFA. Configuration defaults keep it off.

## Configuration

Set `require_mfa` in the config file, via the environment, or with
`--require-mfa`:

| Value | Effect |
| --- | --- |
| `false` (default) | MFA is off. Enrollment is refused; no code is ever required. |
| `true` | Opt-in: only users who have enrolled must provide a code. |
| `"always"` | Every user must enroll. Until they do, the web UI confines them to their enrollment page, every API call except enrollment is refused, and LDAP binds are denied, with *"MFA enrollment required: enroll through the web interface or contact an administrator"*. A successful login still returns a token so the user can open the enrollment page. |

Examples:

```toml
# lldap_config.toml
require_mfa = false
# require_mfa = true
# require_mfa = "always"
```

```bash
# Environment (unquoted for the always form)
LLDAP_REQUIRE_MFA=true
# LLDAP_REQUIRE_MFA=always
```

When the policy is `true` or `"always"`, LLDAP creates the
`lldap_mfa_disabled` group at startup if it does not already exist.
Members of that group are **exempt under both modes**: they authenticate
with the password alone, even if they are enrolled. Use it for service
accounts that cannot type a code, and for break-glass admins.

## Enrollment

1. Open your own profile in the web interface and click **Set up two-factor**.
2. Scan the QR code with an authenticator app, or enter the secret manually.
3. Confirm with the combined format: password, a colon, and the current
   6-digit code. Only the code is checked at this step (the password half
   is shape practice for later logins).

The pending enrollment is valid for **5 minutes**. After that, a session
expired dialog asks you to sign in again and restart.

### Replacing an existing authenticator

Enrolling over an existing second factor additionally requires a current
code from the **authenticator being replaced**, so a stolen session
cannot silently rebind the account to someone else's device. Moving to a
new phone therefore works while you still have the old one. If the old
authenticator is gone, an administrator must `resetUserMfa` first, or you
can complete a password reset by email, which clears the factor.

Under `"always"`, unenrolled users are sent to this page automatically
and cannot use the rest of the UI until they finish or log out.

## Logging in

After enrollment, append a colon and the current code in the password
field:

```text
yourpassword:123456
```

The same combined format works for:

- the web login form
- `POST /auth/simple/login`
- LDAP simple bind

**Breaking change for integrations.** Once a user is enrolled, a plain
password alone is rejected for that account. Services that store a
static password (mail, VPN, Nextcloud, …) cannot supply a fresh code on
every bind — put those accounts in `lldap_mfa_disabled` instead of
enrolling them.

On the web form, a password-only attempt for an enrolled user shows a
short teaching panel with the `password:code` format (not a raw error).
LDAP returns a diagnostic such as *"TOTP code required: append ':' and
the code"* only after the password itself is correct.

### Single-use codes

A verified code cannot be reused for the rest of its acceptance window
(about 90 seconds with the default skew). Replay fails with
*"TOTP code already used"*; wait for the next code. Any other wrong
input stays a generic credentials error.

The used-code record lives **in memory in the running process**. It does
not survive a restart and is not shared between replicas.

### Attempt limiting

An enrolled account gets **5 code attempts per 30-second step**. Once
they are spent, further attempts fail with *"Too many TOTP attempts"*
until the next code, whether or not the code offered is correct. A
mistyped digit therefore costs a short wait, never a lockout, and the
allowance is per account rather than global.

Only codes that fail verification count. A replay is refused by the
single-use record above and does not spend an attempt, so a
double-submitted login does not eat the allowance. The counter is only
ever reached after the password has been verified, so it cannot be used
to lock out someone whose password the attacker does not have.

Like the used-code record, this lives **in memory in the running
process**: it resets on restart and is not shared between replicas.
It bounds guessing rather than capping total failures, so it does not
meet the NIST SP 800-63B ceiling on consecutive failed attempts — for
that, rate-limit `/auth/*` at the reverse proxy or point fail2ban at the
failed-verification log lines. Each guess also costs a full password
bind, which is what limits the unthrottled rate.

## Resetting MFA

| Actor | Can reset |
| --- | --- |
| Admin | Any user, including themselves |
| Password manager | Non-admin users only (never self) |
| Regular user | Nobody |

In the UI: open the target user's profile and use the reset control, or
call the GraphQL mutation `resetUserMfa`. This is the recovery path when
a user has lost the authenticator they would otherwise need in order to
replace it.

A successful **password-reset email** also clears MFA (the mailbox is
the recovery factor). The user must re-enroll afterwards.

## Visibility and secrets

- GraphQL field `mfaEnrolled` reports whether a second factor is set.
  It is visible to **admins and the user themselves**; other readers
  see `null`.
- The sealed TOTP secret is **never** returned on any interface, to
  anyone (including admins).
- Related GraphQL mutations: `startMfaEnrollment`, `finishMfaEnrollment`
  (self), `resetUserMfa` (as above).

## Deployment checklist

- Populate `lldap_mfa_disabled` with service accounts **before** switching
  to `"always"`, or every integration breaks at once. Under `true`, simply
  do not enroll those accounts.
- Keep at least one admin who can still sign in (exempt, enrolled with
  a working authenticator, or unenrolled under `true`) as break-glass
  access.
- Sealed secrets are derived from the server private key
  (`key_seed` / `key_file`). Rotating that key leaves enrolled users with
  `mfa_type` set but an undecryptable secret: login demands a code that
  can never verify, and they cannot re-enroll themselves. An
  administrator must `resetUserMfa` for each affected user first.
- The migration tool does not support MFA logins; run it with an
  unenrolled or exempt admin.
