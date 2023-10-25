# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] 2023-09-14

### Breaking

 - Emails and UUIDs are now enforced to be unique.
   - If you have several users with the same email, you'll have to disambiguate
     them. You can do that by either issuing SQL commands directly
     (`UPDATE users SET email = 'x@x' WHERE user_id = 'bob';`), or by reverting
     to a 0.4.x version of LLDAP and editing the user through the web UI.
     An error will prevent LLDAP 0.5+ from starting otherwise.
   - This was done to prevent account takeover for systems that allow to
     login via email.

### Added

 - The server private key can be set as a seed from an env variable (#504).
   - This is especially useful when you have multiple containers, they don't
     need to share a writeable folder.
 - Added support for changing the password through a plain LDAP Modify
   operation (as opposed to an extended operation), to allow Jellyfin
   to change password (#620).
 - Allow creating a user with multiple objectClass (#612).
 - Emails now have a message ID (#608).
 - Added a warning for browsers that have WASM/JS disabled (#639).
 - Added support for querying OUs in LDAP (#669).
 - Added a button to clear the avatar in the UI (#358).


### Changed

 - Groups are now sorted by name in the web UI (#623).
 - ARM build now uses musl (#584).
 - Improved logging.
 - Default admin user is only created if there are no admins (#563).
   - That allows you to remove the default admin, making it harder to
     bruteforce.

### Fixed

 - Fixed URL parsing with a trailing slash in the password setting utility
   (#597).

In addition to all that, there was significant progress towards #67,
user-defined attributes. That complex feature will unblock integration with many
systems, including PAM authentication.

### New services

 - Ejabberd
 - Ergo
 - LibreNMS
 - Mealie
 - MinIO
 - OpnSense
 - PfSense
 - PowerDnsAdmin
 - Proxmox
 - Squid
 - Tandoor recipes
 - TheLounge
 - Zabbix-web
 - Zulip

## [0.4.3] 2023-04-11

The repository has changed from `nitnelave/lldap` to `lldap/lldap`, both on GitHub
and on DockerHub (although we will keep publishing the images to 
`nitnelave/lldap` for the foreseeable future). All data on GitHub has been
migrated, and the new docker images are available both on DockerHub and on the
GHCR under `lldap/lldap`.

### Added

 - EC private keys are not supported for LDAPS.

### Changed

 - SMTP user no longer has a default value (and instead defaults to unauthenticated).

### Fixed

 - WASM payload is now delivered uncompressed to Safari due to a Safari bug.
 - Password reset no longer redirects to login page.
 - NextCloud config should add the "mail" attribute.
 - GraphQL parameters are now urldecoded, to support special characters in usernames.
 - Healthcheck correctly checks the server certificate.

### New services

 - Home Assistant
 - Shaarli

## [0.4.2] - 2023-03-27

### Added

 - Add support for MySQL/MariaDB/PostgreSQL, in addition to SQLite.
 - Healthcheck command for docker setups.
 - User creation through LDAP.
 - IPv6 support.
 - Dev container for VsCode.
 - Add support for DN LDAP filters.
 - Add support for SubString LDAP filters.
 - Add support for LdapCompare operation.
 - Add support for unencrypted/unauthenticated SMTP connection.
 - Add a command to setup the database schema.
 - Add a tool to set a user's password from the command line.
 - Added consistent release artifacts.

### Changed

 - Payload is now compressed, reducing the size to 700kb.
 - entryUUID is returned in the default LDAP fields.
 - Slightly improved support for LDAP browsing tools.
 - Password reset can be identified by email (instead of just username).
 - Various front-end improvements, and support for dark mode.
 - Add content-type header to the password reset email, fixing rendering issues in some clients.
 - Identify groups with "cn" instead of "uid" in memberOf field.

### Removed

 - Removed dependency on nodejs/rollup.

### Fixed

 - Email is now using the async API.
 - Fix handling of empty/null names (display, first, last).
 - Obscured old password field when changing password.
 - Respect user setting to disable password resets.
 - Fix handling of "present" filters with unknown attributes.
 - Fix handling of filters that could lead to an ambiguous SQL query.

### New services

 - Authentik
 - Dell iDRAC
 - Dex
 - Kanboard
 - NextCloud + OIDC or Authelia
 - Nexus
 - SUSE Rancher
 - VaultWarden
 - WeKan
 - WikiJS
 - ZendTo

### Dependencies (highlights)

 - Upgraded Yew to 0.19
 - Upgraded actix to 0.13
 - Upgraded clap to 4
 - Switched from sea-query to sea-orm 0.11

## [0.4.1] - 2022-10-10

### Added

 - Added support for STARTTLS for SMTP.
 - Added support for user profile pictures, including importing them from OpenLDAP.
 - Added support for every config value to be specified in a file.
 - Added support for PKCS1 keys.

### Changed

 - The `dn` attribute is no longer returned as an attribute (it's still part of the response).
 - Empty attributes are no longer returned.
 - The docker image now uses the locally-downloaded assets.

## [0.4.0] - 2022-07-08

### Breaking

The `lldap_readonly` group has been renamed `lldap_password_manager` (migration happens automatically) and a new `lldap_strict_readonly` group was introduced.

### Added
  - A new `lldap_strict_readonly` group allows granting readonly rights to users (not able to change other's passwords, in particular).

### Changed
  - The `lldap_readonly` group is renamed `lldap_password_manager` since it still allows users to change (non-admin) passwords.

### Removed
  - The `lldap_readonly` group was removed.

## [0.3.0] - 2022-07-08

### Breaking
As part of the update, the database will do a one-time automatic migration to
add UUIDs and group creation times.

### Added
  - Added support and documentation for many services:
    - Apache Guacamole
    - Bookstack
    - Calibre
    - Dolibarr
    - Emby
    - Gitea
    - Grafana
    - Jellyfin
    - Matrix Synapse
    - NextCloud
    - Organizr
    - Portainer
    - Seafile
    - Syncthing
    - WG Portal
  - New migration tool from OpenLDAP.
  - New docker images for alternate architectures (arm64, arm/v7).
  - Added support for LDAPS.
  - New readonly group.
  - Added UUID attribute for users and groups.
  - Frontend now uses the refresh tokens to reduce the number of logins needed.

### Changed
  - Much improved logging format.
  - Simplified API login.
  - Allowed non-admins to run search queries on the content they can see.
  - "cn" attribute now returns the Full Name, not Username.
  - Unknown attributes now warn instead of erroring.
    - Introduced a list of attributes to silence those warnings.

### Deprecated
 - Deprecated "cn" as LDAP username, "uid" is the correct attribute.

### Fixed
  - Usernames, objectclass and attribute names are now case insensitive.
  - Handle "1.1" and other wildcard LDAP attributes.
  - Handle "memberOf" attribute.
  - Handle fully-specified scope.

### Security
  - Prevent SQL injections due to interaction between two libraries.

## [0.2.0] - 2021-11-27
