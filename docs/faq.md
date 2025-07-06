# Frequently Asked Questions

- [I can't login](#i-cant-log-in)
- [Discord Integration](#discord-integration)
- [Migrating from SQLite](#migrating-from-sqlite)
- How does LLDAP compare [with OpenLDAP](#how-does-lldap-compare-with-openldap)? [With FreeIPA](#how-does-lldap-compare-with-freeipa)? [With Kanidm](#how-does-lldap-compare-with-kanidm)?

## I can't log in!

If you just set up the server, can get to the login page but the password you
set isn't working, try the following:

- If you have changed the admin password in the config after the first run, it
  won't be used (unless you force its use with `force_ldap_user_pass_reset`).
  The config password is only for the initial admin creation.
- (For docker): Make sure that the `/data` folder is persistent, either to a
  docker volume or mounted from the host filesystem.
- Check if there is a `lldap_config.toml` file (either in `/data` for docker
  or in the current directory). If there isn't, copy
  `lldap_config.docker_template.toml` there, and fill in the various values
  (passwords, secrets, ...).
- Check if there is a `users.db` file (either in `/data` for docker or where
  you specified the DB URL, which defaults to the current directory). If
  there isn't, check that the user running the command (user with ID 10001
  for docker) has the rights to write to the `/data` folder. If in doubt, you
  can `chmod 777 /data` (or whatever the folder) to make it world-writeable.
- Make sure you restart the server.
- If it's still not working, join the
  [Discord server](https://discord.gg/h5PEdRMNyP) to ask for help.

## Discord Integration

[Use this bot](https://github.com/JaidenW/LLDAP-Discord) to Automate discord role synchronization for paid memberships.
- Allows users with the Subscriber role to self-serve create an LLDAP account based on their Discord username, using the `/register` command.

## Migrating from SQLite

If you started with an SQLite database and would like to migrate to
MySQL/MariaDB or PostgreSQL, check out the [DB
migration docs](/docs/database_migration.md).

## How does LLDAP compare with OpenLDAP?

[OpenLDAP](https://www.openldap.org) is a monster of a service that implements
all of LDAP and all of its extensions, plus some of its own. That said, if you
need all that flexibility, it might be what you need! Note that installation
can be a bit painful (figuring out how to use `slapd`) and people have mixed
experiences following tutorials online. If you don't configure it properly, you
might end up storing passwords in clear, so a breach of your server would
reveal all the stored passwords!

OpenLDAP doesn't come with a UI: if you want a web interface, you'll have to
install one (not that many look nice) and configure it.

LLDAP is much simpler to setup, has a much smaller image (10x smaller, 20x if
you add PhpLdapAdmin), and comes packed with its own purpose-built web UI.
However, it's not as flexible as OpenLDAP.

## How does LLDAP compare with FreeIPA?

[FreeIPA](http://www.freeipa.org) is the one-stop shop for identity management:
LDAP, Kerberos, NTP, DNS, Samba, you name it, it has it. In addition to user
management, it also does security policies, single sign-on, certificate
management, linux account management and so on.

If you need all of that, go for it! Keep in mind that a more complex system is
more complex to maintain, though.

LLDAP is much lighter to run (<10 MB RAM including the DB), easier to
configure (no messing around with DNS or security policies) and simpler to
use. It also comes conveniently packed in a docker container.

## How does LLDAP compare with kanidm?

[Kanidm](https://kanidm.com) is an up-and-coming Rust identity management
platform, covering all your bases: OAuth, Linux accounts, SSH keys, Radius,
WebAuthn. It comes with a (read-only) LDAPS server.

It's fairly easy to install and does much more; but their LDAP server is
read-only, and by having more moving parts it is inherently more complex. If
you don't need to modify the users through LDAP and you're planning on
installing something like [KeyCloak](https://www.keycloak.org) to provide
modern identity protocols, check out Kanidm.
