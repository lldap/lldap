# Frequently Asked Questions

- [I can't login](#i-cant-log-in)
- [Discord Integration](#discord-integration)
- [Migrating from SQLite](#migrating-from-sqlite)
- How does LLDAP compare [with OpenLDAP](#how-does-lldap-compare-with-openldap)? [With FreeIPA](#how-does-lldap-compare-with-freeipa)? [With Kanidm](#how-does-lldap-compare-with-kanidm)?
- [Does LLDAP support vhosts?](#does-lldap-support-vhosts)
- [Does LLDAP provide commercial support contracts?](#does-lldap-provide-commercial-support-contracts)
- [Can I make a donation to fund development?](#can-i-make-a-donation-to-fund-development)
- [Is LLDAP sustainable? Can we depend on it for our infrastructure?](#is-lldap-sustainable-can-we-depend-on-it-for-our-infrastructure)
- [Does LLDAP need Internet access?](#does-lldap-need-internet-access)
- [Why does my browser make requests to external HTTP services?](#why-does-my-browser-make-requests-to-external-http-services)
- [What is LLDAP's privacy policy?](#what-is-lldaps-privacy-policy)

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

## Does LLDAP support vhosts?

LLDAP does not natively support virtualhosts, sometimes known as multi-tenancy:

- users are all part of the same base DN (`ou=people,dc=example,dc=com`)
- you may support multiple domains by using fully-qualified email addresses as usernames (eg. `user@example.com` and `user@example.org`); however, you can't have more fine-grained permissions than what is provided by default (which applies across all users)

LLDAP is very lightweight (~15MiB RAM on startup) and it's therefore possible to run one instance per virtualhost if you need to properly support multiple domains.

## Does LLDAP provide commercial support contracts?

LLDAP does not provide commercial support. It's provided as volunteer-developed free-software on a best-effort basis. If that's not ideal for you, you should probably consider using a professional all-in-one solution such as OpenLDAP, FreeIPA, or Kanidm.

LLDAP is free-software (under a copyleft GPL 3.0 license) and anyone can provide consultancy and support contracts for the software. However, the LLDAP project currently does not endorse any 3rd party to provide such services in an official manner. This may be revised in the future if developers from the community step up and provide amazing services.

## Can I make a donation to fund development?

You can make a donation on [buymeacoffee.com/nitnelave](https://buymeacoffee.com/nitnelave) to personally support @nitnelave, the maintainer and main developer of the project.

It's not a goal for them to raise enough money to be employed to work on LLDAP. As of July 2025, the donations (<100€/month) are not sufficient anyway to employ people to work on LLDAP, even part-time.

## Is LLDAP sustainable? Can we depend on it for our infrastructure?

LLDAP is hobbyist software developed in good will by volunteers. LLDAP is not sustainable, as only @nitnelave knows the entire codebase (bus factor = 1).

The project is not too complex and is even kept minimalist on purpose. However, unless you'd like to audit and maintain the codebase in the foreseeable future, it's not recommended to adopt LLDAP for the infrastructure of your big organization.

You are free to use LLDAP for any purpose, as long as you respect the copyleft. However, please do not complain if feature X is not implemented, or if the volunteers are not fixing problems fast enough for your taste. LLDAP is a project born of love and adventure, not a commercial endeavour.

## Does LLDAP need Internet access?

By default, LLDAP uses CSS, fonts and JS served from third-party [Content Delivery Networks](https://en.wikipedia.org/wiki/Content_delivery_network). This has upsides and downsides, which are being evaluted in issue [#1219](https://github.com/lldap/lldap/issues/1219).

It is possible to run LLDAP without Internet access, in a LAN setup, which is the default configuration for our provided Docker images. You need to make sure the `index.html` file served by `lldap` from the configured `assets_path` is actually the `app/index_local.html` file. Then, download the external resources to the same folder. Assuming you use the default `assets_path = "./app/"`:

```sh
for file in $(cat app/static/libraries.txt); do wget -P app/static "$file"; done
for file in $(cat app/static/fonts/fonts.txt); do wget -P app/static/fonts "$file"; done
```

LLDAP should now be working on your LAN without requiring Internet access on the server or client side.

## Why does my browser make requests to external HTTP services?

By default, LLDAP uses CSS, fonts and JS served from third-party [Content Delivery Networks](https://en.wikipedia.org/wiki/Content_delivery_network). This has upsides and downsides, which are being evaluted in issue [#1219](https://github.com/lldap/lldap/issues/1219).

If you are worried about the privacy and security of your setup, it is also possible to serve all static assets locally without 3rd parties. See the question [Does LLDAP need Internet access?](#does-lldap-need-internet-access) of this FAQ.

## What is LLDAP's privacy policy?

LLDAP is copyleft software for you to self-host. The LLDAP developers do not collect any information from the deployed instances or their respective users, and do not provide hosting services of any kind. What you do with this software developed in good faith is entirely your responsibility, and we encourage you to adopt a privacy-friendly and transparent privacy policy.

Under certain circumstances, users browsing an LLDAP service may perform automated HTTP requests to third-party [Content Delivery Networks](https://en.wikipedia.org/wiki/Content_delivery_network). That is however, dependent on the instance's specific LLDAP configuration and is entirely their responsibility. Any data collected in this manner is not communicated to the LLDAP project.

If you are curious about your LLDAP provider's privacy policy, feel free to contact your admin directly.