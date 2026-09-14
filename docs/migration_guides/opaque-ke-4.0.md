# Upgrading across the opaque-ke 0.7 → 4.0 change

This release upgrades the OPAQUE password protocol from `opaque-ke` 0.7 to 4.0
(RFC 9807). The migration is **automatic, progressive and non-destructive**:
just start the upgraded server. Existing passwords keep working and are
re-encoded in the new format automatically on each user's next successful
login (LDAP bind, simple HTTP login, or OPAQUE web login). You do **not** need
to reset anyone's password, pass any flag, or restart more than once.

Two things do change for operators and users:

- **Everyone is logged out once.** When the database schema is migrated, every
  existing session is invalidated: all JSON Web Tokens are blacklisted and all
  refresh tokens are deleted. Users simply log in again. This guarantees that
  no session issued before the upgrade can be used to reset a password while
  that password's own upgrade is in flight.
- **Stop every instance before upgrading.** Running a pre-4.0 instance next to
  a 4.0 instance is not supported: the old binary cannot start against the new
  schema, and an old instance still running during the upgrade could write a
  password file the new binary cannot read. Stop all instances, upgrade, start.

## How the automatic upgrade works

On first start, the server detects that its key is still in the `opaque-ke`
0.7 format and verifies against the database that it is the same key that was
in use at the last successful startup. Only then does it start using a 4.0 key,
keeping the old key around to validate not-yet-upgraded passwords:

| Mode | What happens on first start |
| --- | --- |
| **`server_key` file** | Nothing is written. The 4.0 key is *derived* from the existing file: its bytes are hashed (with a fixed label) and used as the seed of the key generation, exactly like `key_seed`. Every start and every instance sharing the file derives the same key. The file stays a 0.7 key file and keeps validating not-yet-upgraded passwords. |
| **`key_seed`** | Nothing is written. The old 0.7 key is re-derived from the same seed in memory on every start. |

In both cases the server records the hash of the new key in the database.
Because every instance derives the same key, several instances starting at the
same time all record the same value; there is no file to race on.

If the key file is corrupted (it parses as neither the 4.0 nor the 0.7
format), or it is a 0.7 key that does *not* match the key recorded in the
database, the server refuses to start and explains what to do. It never
silently generates a new key, since that would unrecoverably invalidate every
password.

Each successful login then re-registers the password in the 4.0 format. That
write is conditional: it only replaces the exact password file that was just
validated, and only while it is still marked as 0.7. A password reset that
lands in between always wins.

## Keep the key file

After the upgrade the 4.0 key exists nowhere but in the derivation from your
`server_key` file (or from your `key_seed`). **The file is still the only copy
of your server key**: keep it, keep backing it up, never replace it. Deleting
or changing it invalidates every password, exactly as before the upgrade.

Because the new key is derived from the old one, a `server_key` file that
leaked before the upgrade stays as sensitive as it was. If you need a clean
break, generate a new key with `--force-update-private-key`; that invalidates
all passwords, which then have to be reset.

## Do NOT pass `--force-update-private-key` or `--force-ldap-user-pass-reset`

Neither flag is needed for this upgrade; both keep their usual meaning of
*intentionally* replacing the key and invalidating all existing passwords.
Only use them if you actually changed the key itself (a new `key_seed`, or a
different/lost `server_key` file), in which case the old passwords are
genuinely unrecoverable.

## Verifying

After the upgrade, the logs print how many users still hold a v0.7
password. As an admin, the user list in the web UI shows how many users still
have a pre-upgrade password and a "Password upgrade pending" badge next to
each of them (also available as the admin-only `hasLegacyPassword` GraphQL
field). The count drops to zero as users log in. You can also check the
`users.password_version` column: `0` = legacy v0.7, `1` = current v4.0.

## Rolling back

Take a backup of your database **before** starting the new version. Rolling
back to a pre-4.0 binary means restoring that backup: the new binary records
its key hash in the database, the schema migration cannot be undone, and
passwords that were already re-registered are unreadable by the old binary.
The key file itself is not modified by the upgrade and needs no restore.

## Pre-release builds

Builds of this change from before its release rotated the key file in place
and wrote a `<keyfile>.v07` sidecar. Deployments that ran such a build keep
working with their rotated 4.0 key file. Their sessions are not invalidated
again, and the sidecar is no longer read: the server warns while it exists.
Delete it, it holds an old server key.
