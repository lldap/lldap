# Upgrading across the opaque-ke 0.7 → 4.0 change

This release upgrades the OPAQUE password protocol from `opaque-ke` 0.7 to 4.0
(RFC 9807). The migration is **fully automatic, progressive and
non-destructive**: just start the upgraded server. Existing passwords keep
working and are re-encoded in the new format automatically on each user's next
successful login (LDAP bind, simple HTTP login, or OPAQUE web login). You do
**not** need to reset anyone's password, pass any flag, or restart more than
once.

## How the automatic upgrade works

On first start, the server detects that its key is still in the `opaque-ke`
0.7 format and verifies against the database that it is the same key that was
in use at the last successful startup. Only then does it switch to a 4.0 key,
keeping the old key around to validate not-yet-upgraded passwords:

| Mode | What happens on first start |
| --- | --- |
| **`server_key` file** | The file is rotated to a fresh 4.0 key; the old key is saved next to it as `<keyfile>.v07` so passwords keep validating until each user logs in. The sidecar is deleted automatically once everyone is upgraded. |
| **`key_seed`** | Nothing is written to disk. The old 0.7 key is re-derived from the same seed in memory on every start. No sidecar, no key file. |

If the key file is corrupted (it parses as neither the 4.0 nor the 0.7
format), or it is a 0.7 key that does *not* match the key recorded in the
database, the server refuses to start and explains what to do — it never
silently generates a new key, since that would unrecoverably invalidate every
password.

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

Keep a backup of your database (and `server_key` file, if you use one) from
before the upgrade. Because the key file is rotated in place for file-based
deployments, rolling back to a pre-4.0 binary requires restoring both the old
binary **and** the old key file/database.
