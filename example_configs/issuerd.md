# Issuerd configuration

[Issuerd](https://github.com/issuerd/issuerd) is a horizontally scalable IAM
server implementing OIDC/OAuth2 with a Keycloak-compatible Admin API. Like
Keycloak, it supports **user federation** over LDAP, which is how it integrates
with LLDAP: users stay in LLDAP, Issuerd imports them and validates their
passwords with an LDAP bind.

Keep in mind that LLDAP is _read-only_ over LDAP: users and groups are created
in LLDAP (web UI or GraphQL) and appear in Issuerd after a sync (or on first
login). Use Issuerd to assign roles and manage clients.

## Get Issuerd running

The quickest way is the demo compose stack (PostgreSQL + Redis, admin console
on http://localhost:8080/admin/console, admin/admin):

```bash
git clone https://github.com/issuerd/issuerd
cd issuerd && docker compose up -d
```

or a single container with in-memory storage for a quick look:

```bash
docker run --rm -p 8080:8080 issuerd/issuerd:latest
```

## Configure user authentication

In the Issuerd admin console, select your realm and go to **Identity
providers** → **Add provider** → `ldap`. The key settings are:

 - Edit Mode: `WRITABLE` if you want users to change/reset passwords through
   Issuerd (see the password section below); otherwise `READ_ONLY`.
 - Vendor: `Other` (`GENERIC`)
 - Connection URL: `ldap://<your-lldap-container>:3890`
 - Bind DN: `uid=admin,ou=people,dc=example,dc=com` (replace with your admin user and `dc`)
 - Bind Credential: your LLDAP admin password
 - Users DN: `ou=people,dc=example,dc=com`
 - Base DN: `dc=example,dc=com`
 - Username LDAP attribute: `uid`
 - RDN LDAP attribute: `uid` (LLDAP user DNs are `uid=<name>,ou=people,...`)
 - UUID LDAP attribute: `entryUUID`
 - User Object Classes: `inetOrgPerson,posixAccount,mailAccount,person` —
   exactly these four. Issuerd ANDs every listed class into the user search
   filter, and LLDAP user entries carry precisely this set (no
   `organizationalPerson`); an extra class would match zero users.
 - Search scope: `SUBTREE`
 - Pagination: leave off. Issuerd always pages its searches (RFC 2696), which
   LLDAP tolerates by answering with a single page — no action needed; the
   flag is parsed for Keycloak parity only.

## Map user attributes (email, names)

Issuerd wires mapper rules from the provider's `mappers` list (Keycloak mapper
type ids). Add these to get the email and names onto synced/imported users —
LLDAP serves `mail`, `givenName`/`first_name`, `sn`/`last_name` and `cn`
(display name) on user entries:

```bash
TOKEN=$(curl -s -X POST "http://localhost:8080/realms/master/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=admin-cli \
  -d username=admin -d password=admin | jq -r .access_token)

for M in \
  '{"name":"email","mapper_type":"user-attribute-ldap-mapper","config":{"user.attribute":"email","ldap.attribute":"mail"}}' \
  '{"name":"first name","mapper_type":"user-attribute-ldap-mapper","config":{"user.attribute":"firstName","ldap.attribute":"givenName"}}' \
  '{"name":"last name","mapper_type":"user-attribute-ldap-mapper","config":{"user.attribute":"lastName","ldap.attribute":"sn"}}'
do
  curl -X POST \
    "http://localhost:8080/admin/realms/myrealm/identity-provider/instances/lldap/mappers" \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "$M"
done
```

The same entries go into the provision YAML under the provider's `mappers:`
list, and the admin console's mapper dialog offers them with descriptions
(Identity providers → your provider → Mappers → Add Mapper). Re-run the sync
after adding mappers to refresh existing users.

> **Note on attribute casing:** LLDAP's `"*"` expansion returns schema
> attributes lowercased (`givenname`), which Issuerd handles — LDAP attribute
> lookups are case-insensitive. Your mapper config can keep the canonical
> camelCase spellings (`givenName`, `memberOf`).

Save the provider, then trigger a full sync: **Identity providers** → your
provider → **Sync users** (or the REST endpoint below). Users log in at the
Issuerd login page with their LLDAP username/password; the password is verified
by an LDAP bind, and unknown users are imported on first login too.

## Configure group mapping

Issuerd's group sync is built into the provider config (no separate mapper
object needed). LLDAP serves a virtual `memberOf` attribute on user entries,
which is exactly what the sync consumes. Additional provider settings:

 - `groupsDn`: `ou=groups,dc=example,dc=com` (enables group sync)
 - `groupsInclude`: optional comma-separated allowlist of group names to sync
   (e.g. `developers`)
 - `memberOfLdapAttribute`: defaults to `memberOf`, which matches LLDAP.

On each full sync, LLDAP groups under `ou=groups` reconcile into same-named
Issuerd groups: missing groups are created, pre-existing groups are adopted,
and only sync-managed memberships are touched. To grant application roles,
assign them to the synced group in Issuerd (**Groups** → the group → **Role
mapping**) — for example mapping the realm role `developer` onto the synced
`developers` group.

## Password changes through Issuerd

Although LLDAP is read-only for ordinary data, it **does accept password
changes over LDAP** from an authorized bind — both a plain `userPassword`
replace and the RFC 3062 *Password Modify* extended operation (Issuerd uses
the former). With `editMode: WRITABLE` (or `UNSYNCED`) on the provider, all of
Issuerd's password paths write straight into LLDAP instead of a local
credential:

- the account console's change-password (verifies the current password with an
  LDAP bind first),
- the `UPDATE_PASSWORD` required action and the reset-credentials email flow,
- admin **Users → Reset password**.

The provider's bind account must be allowed to change the target password in
LLDAP: members of `lldap_admin` can change anyone's, members of
`lldap_password_manager` can change regular users' (not other admins'), and a
user can always change their own. The stock `admin` account covers the first
case.

> **Caveat:** resetting the password of the federated user who **is** the
> provider's bind account (e.g. a synced `admin`) changes the service account
> password in LLDAP — the provider then binds with the stale configured
> credential until you update `bindCredential` to match. Prefer a dedicated
> service account for binding, not a persona people log in as.

With `editMode: READ_ONLY` every password-set path for federated users fails
with a 400-level error instead — pick that if passwords must only ever live in
LLDAP's own UI.

## REST API / provisioning equivalents

Everything above is one `IdentityProviderRepresentation`:

```bash
TOKEN=$(curl -s -X POST "http://localhost:8080/realms/master/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=admin-cli \
  -d username=admin -d password=admin | jq -r .access_token)

curl -X POST "http://localhost:8080/admin/realms/myrealm/identity-provider/instances" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{
    "alias": "lldap",
    "provider_id": "ldap",
    "enabled": true,
    "config": {
      "connectionUrl": "ldap://lldap:3890",
      "bindDn": "uid=admin,ou=people,dc=example,dc=com",
      "bindCredential": "changeme",
      "usersDn": "ou=people,dc=example,dc=com",
      "baseDn": "dc=example,dc=com",
      "usernameLdapAttribute": "uid",
      "rdnLdapAttribute": "uid",
      "uuidLdapAttribute": "entryUUID",
      "userObjectClasses": "inetOrgPerson,posixAccount,mailAccount,person",
      "vendor": "GENERIC",
      "searchScope": "SUBTREE",
      "editMode": "READ_ONLY",
      "pagination": "false",
      "groupsDn": "ou=groups,dc=example,dc=com",
      "groupsInclude": "developers"
    }
  }'

# Trigger a full sync (blocks until done):
curl -X POST "http://localhost:8080/admin/realms/myrealm/user-federation/lldap/sync?strategy=full" \
  -H "Authorization: Bearer $TOKEN"
```

Or declaratively in the boot-time provision file:

```yaml
identity_providers:
  - realm: myrealm
    alias: lldap
    provider_id: ldap
    enabled: true
    config:
      connectionUrl: ldap://lldap:3890
      bindDn: uid=admin,ou=people,dc=example,dc=com
      bindCredential: changeme
      usersDn: ou=people,dc=example,dc=com
      baseDn: dc=example,dc=com
      usernameLdapAttribute: uid
      rdnLdapAttribute: uid
      uuidLdapAttribute: entryUUID
      userObjectClasses: inetOrgPerson,posixAccount,mailAccount,person
      vendor: GENERIC
      searchScope: SUBTREE
      # WRITABLE enables password changes through Issuerd; READ_ONLY if they
      # must only live in LLDAP's own UI.
      editMode: WRITABLE
      pagination: "false"
      groupsDn: ou=groups,dc=example,dc=com
      groupsInclude: developers
```

## Notes and current limitations

 - **Sync overwrites mapped fields**: every full sync refreshes email,
   first/last name, custom attributes and the enabled flag from the directory.
   Local edits to those fields on a federated user do not survive a sync —
   treat LLDAP as the source of truth. (Passwords are the exception: with
   `editMode: WRITABLE` they are written *through* to LLDAP, never stored
   locally.)
 - **Group memberships are read in LLDAP**, mapped in Issuerd — manage the
   groups and their members in LLDAP, manage role assignments on the synced
   Issuerd groups.

Tested with `lldap/lldap:stable` against the current Issuerd release: admin
bind, full user sync, virtual `memberOf` group sync, email/first/last-name
attribute mapping, end-user LDAP-bind login, and password changes through both
the self-service account API and the admin reset endpoint (write-through with
`editMode: WRITABLE`) all verified.
