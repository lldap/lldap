# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
