# Two-factor authentication (TOTP)

LLDAP can require a time-based one-time password (TOTP, RFC 6238: SHA-1,
6 digits, 30 second step) as a second factor. Storage uses the existing
`totp_secret` and `mfa_type` columns — no database migration is required.

This page is the full reference for enabling, enrolling, logging in,
resetting, and deploying MFA. Configuration defaults keep it off.

## Configuration

Set `enable_mfa` in the config file, via the environment, or with
`--enable-mfa`:

| Value | Effect |
| --- | --- |
| `false` (default) | MFA is off. Enrollment is refused; no code is ever required. |
| `true` | Opt-in: only users who have enrolled must provide a code. |
| `"always"` | Every user must enroll. Until they do, the web UI confines them to their enrollment page, every API call except enrollment is refused, and LDAP binds are denied, with *"MFA enrollment required: enroll through the web interface or contact an administrator"*. A successful login still returns a token so the user can open the enrollment page. |

Examples:

```toml
# lldap_config.toml
enable_mfa = false
# enable_mfa = true
# enable_mfa = "always"
```

```bash
# Environment (unquoted for the always form)
LLDAP_ENABLE_MFA=true
# LLDAP_ENABLE_MFA=always
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
   6-digit code. Both halves are checked, and the format is the one you
   will use to log in from then on.

The password is verified the same way the **Modify password** page
verifies the current password: the browser runs the OPAQUE login
handshake against the server and checks the result locally, so the
password itself is never sent. As with that page the check is enforced by
the client — see [Standards and limitations](#standards-and-limitations).
The code checks below are the server-side ones.

The pending enrollment is valid for **5 minutes**. After that, a session
expired dialog asks you to sign in again and restart.

### Replacing an existing authenticator

Enrolling over an existing second factor asks for a current code from the
**authenticator being replaced** before the new QR code is shown, so a
stolen session cannot silently rebind the account to someone else's
device. Moving to a new phone therefore works while you still have the
old one. If the old authenticator is gone, an administrator must
`resetUserMfa` first, or you can complete a password reset by email,
which clears the factor.

The code is checked by the server at `startMfaEnrollment`, and the sealed
enrollment state it returns records that the check passed. A state minted
before the account had a factor cannot be used to replace one.

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
process**: it resets on restart and is not shared between replicas. It
bounds the guessing rate rather than capping total failures; see
[Standards and limitations](#standards-and-limitations) below.

## Resetting MFA

| Actor | Can reset | Needs a code |
| --- | --- | --- |
| Admin | Any user; themselves only when the policy is not `"always"` | No |
| Password manager | Non-admin users only (never self) | No |
| Regular user | Themselves, unless the policy is `"always"` | Yes |

An administrator resets from the target user's profile, or by calling
`resetUserMfa`. This is the recovery path when a user has lost the
authenticator they would otherwise need in order to replace it.

Users give up their own factor from **Reset two-factor** on their own
profile, confirming with password, a colon and a current code — gated
like enrollment above, so it needs the authenticator rather than only a
session.

Under `"always"` **nobody removes their own second factor**, including an
administrator acting on their own account: the control is not offered and
both `resetOwnMfa` and a self-targeted `resetUserMfa` are refused. What
remains is another administrator, or the password-reset email below.

A successful **password-reset email** also clears MFA (the mailbox is
the recovery factor). The user must re-enroll afterwards.

## Visibility and secrets

- GraphQL field `mfaEnrolled` reports whether a second factor is set.
  It is visible to **admins and the user themselves**; other readers
  see `null`.
- The sealed TOTP secret is **never** returned on any interface, to
  anyone (including admins).
- Related GraphQL mutations: `startMfaEnrollment`, `finishMfaEnrollment`,
  `resetOwnMfa` (self), `resetUserMfa` (as above).

## Standards and limitations

The parameters are hardcoded to the values below; none of them is configurable.

| Requirement | Source | Status |
| --- | --- | --- |
| HMAC-SHA-1, 6 digits, 30-second step | RFC 6238 §4–5 | Met. The RFC's Appendix B vectors are unit tests. |
| Validation window of at most one step either side | RFC 6238 §5.2 | Met: ±1 step, so a code is accepted for 90 seconds. |
| Throttle failed verification attempts | RFC 4226 §7.3 | Met: 5 attempts per 30-second step, per account. |
| Resynchronisation for counter drift | RFC 4226 §7.4 | Not applicable to time-based codes; the ±1 step window absorbs clock drift. |
| Authenticator secrets stored in encrypted form | NIST SP 800-63B §5.1.4.2 | Met: sealed with AEAD under a key HKDF-derived from the server's private key, with a per-enrollment salt and the user UUID as associated data. Never returned on any interface. |
| Replay resistance | NIST SP 800-63B §5.2.8 | Met: a verified code is refused for the rest of its acceptance window, at every door. |
| No more than 100 consecutive failed attempts | NIST SP 800-63B §5.2.2 | **Not met** — see below. |
| OTP not usable more than once | OWASP ASVS V2.8.4 | Met, as above. |
| OTP not valid beyond its defined period | OWASP ASVS V2.8.5 | Met: 90 seconds. |
| Approved algorithm, protected symmetric key | OWASP ASVS V2.8.2–3 | Met, as above. |

### Known limitations

**No cap on consecutive failures, and no lockout.** The limiter paces guessing (5 per
30-second step) instead of counting failures toward a ceiling, so it does not meet NIST
SP 800-63B §5.2.2. This is deliberate: locking accounts turns a wrong digit into a denial
of service, and RFC 4226 §7.3 explicitly offers the delay scheme as an alternative. Note
that verification is only reachable **after the password is correct**, so an attacker who
does not have the password cannot spend the allowance or lock anyone out. For a hard
ceiling, rate-limit `/auth/*` at your reverse proxy, or point fail2ban at the failed
verification log lines.

**The replay and rate-limit records are per process, in memory.** Both reset on restart
and neither is shared between replicas. A code consumed on one replica can be replayed on
another, and a restart refills the allowance.

**No recovery codes.** Recovery is an administrator reset, the password-reset email (which
clears the factor), or the `lldap_mfa_disabled` group. There is no offline code list, and
no command-line way to clear a factor.

**Enrolling does not end existing sessions.** A refresh token issued before enrollment
keeps minting access tokens afterwards, without a code, until it expires. Adding a second
factor therefore does not evict someone already holding a session — the same is true of a
password change in LLDAP today. If that matters to you, log out everywhere after enrolling.

**Administrators can exempt themselves.** `lldap_mfa_disabled` is the break-glass path and
membership is admin-only — a regular user or a password manager cannot add anyone, checked
in tests. But an administrator on `"always"` who adds themselves signs in with a password
alone from then on, which is a way around the rule that nobody may drop their own factor.

**The password check at enrollment is enforced by the browser.** The enrollment page runs
the same OPAQUE handshake the **Modify password** page uses, and checks the result locally,
so a caller driving the GraphQL API directly can skip it. Every code check is server-side.

**Turning the policy off strands enrolled users' combined format.** With `enable_mfa =
false` the `password:code` suffix is no longer split, so the whole string is treated as the
password and the login fails. Enrolled users must go back to a plain password.

**The issuer shown in the authenticator is fixed.** Enrollment URIs always carry
`issuer=LLDAP`, so someone enrolled with two LLDAP servers sees two entries under the same
name, told apart only by the account. There is no setting for it — `TOTP_ISSUER` in
`crates/sql-backend-handler/src/sql_mfa_handler.rs` needs a rebuild, and existing entries
keep the old label until the user re-enrolls.

**Rotating the server key orphans sealed secrets.** See the deployment checklist below.

## Deployment checklist

- Populate `lldap_mfa_disabled` with service accounts **before** switching
  to `"always"`, or every integration breaks at once. Under `true`, simply
  do not enroll those accounts.
- Keep at least one admin who can still sign in (exempt, enrolled with
  a working authenticator, or unenrolled under `true`) as break-glass
  access. There is no command-line way to clear a second factor, and
  under `"always"` an admin cannot clear their own, so plan for either a
  second admin or `enable_password_reset` left on. Without both, a lone
  admin who loses their authenticator is down to editing `mfa_type` and
  `totp_secret` in the database by hand.
- Sealed secrets are derived from the server private key
  (`key_seed` / `key_file`). Rotating that key leaves enrolled users with
  `mfa_type` set but an undecryptable secret: login demands a code that
  can never verify, and they cannot re-enroll themselves. An
  administrator must `resetUserMfa` for each affected user first.
- The migration tool does not support MFA logins, and refuses an enrolled
  account by name rather than failing to parse the response. Run it as an
  unenrolled admin under `true`. Under `"always"` that is not enough — an
  unenrolled account receives a token but is gated out of the API the tool
  needs — so put the account in `lldap_mfa_disabled` first.
