# Configuration for Vaultwarden

https://github.com/ViViDboarder/vaultwarden_ldap will send an invitation to any member of the group `vaultwarden`.

Replace `dc=example,dc=com` with your LLDAP configured domain.

`docker-compose.yml` to run `vaultwarden_ldap`
```
version: '3'
services:
  ldap_sync:
    image: vividboarder/vaultwarden_ldap:0.6-alpine
    volumes:
      - ./config.toml:/config.toml:ro
    environment:
      CONFIG_PATH: /config.toml
      RUST_BACKTRACE: 1
    restart: always
```
Configuration to use LDAP in `config.toml`
```toml
vaultwarden_url = "http://your_bitwarden_url:port"
vaultwarden_admin_token = "insert_admin_token_vaultwarden"
ldap_host = "insert_ldap_host"
ldap_port = 3890
ldap_bind_dn = "uid=admin,ou=people,dc=example,dc=com"
ldap_bind_password = "insert_admin_pw_ldap"
ldap_search_base_dn = "dc=example,dc=com"
ldap_search_filter = "(&(objectClass=*)(memberOf=cn=vaultwarden,ou=groups,dc=example,dc=com)(uid=*))"
ldap_sync_interval_seconds = 300
```
Will check every 300 seconds your ldap group ```vaultwarden``` and send an invitation by email to any new member of this group.
