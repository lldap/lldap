# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
