# OCIS (OwnCloud Infinite Scale)

This is using version 5 which is currently still in RC.

IMPORTANT: There is a bug/quirk in how the OCIS container handles bind mounts.  

If the bind mount locations (eg. `/srv/ocis/{app,cfg}`) don't exist when the container is started, OCIS creates them with `root` permissions.  It then seems to drop permissions to UID 1000 and gives an error because it can't create files in the `{app,cfg}`.

So you must create the bind mount locations and manually chown them to uid/gid 1000, eg.

```
# cd /srv/ocis
# mkdir app cfg
# chown 1000:1000 app cfg
# docker compose up -d && docker compose logs -f 
```

## .env

```
OCIS_URL="https://ocis.example.nz"
LDAP_BASE_DN="dc=example,dc=nz"
LDAP_BIND_PASSWORD=very-secret-yogurt
# LLDAP UUID to be given admin permissions
LLDAP_ADMIN_UUID=c1c2428a-xxxx-yyyy-zzzz-6cc946bf6809
```

## docker-compose.yml

```
version: "3.7"

networks:
  caddy:
    external: true

services:
  ocis:
    image: owncloud/ocis:5.0.0-rc.4
    container_name: ocis
    networks:
      - caddy
    entrypoint:
      - /bin/sh
    command: ["-c", "ocis init || true; ocis server"]
    environment:
      OCIS_URL: ${OCIS_URL}
      OCIS_LOG_LEVEL: warn
      OCIS_LOG_COLOR: "false"
      PROXY_TLS: "false" # do not use SSL between Traefik and oCIS
      OCIS_INSECURE: "false"
      # Basic Auth is required for WebDAV clients that don't support OIDC
      PROXY_ENABLE_BASIC_AUTH: "false"
      #IDM_ADMIN_PASSWORD: "${ADMIN_PASSWORD}" # Not needed if admin user is in LDAP (?)
      #OCIS_PASSWORD_POLICY_BANNED_PASSWORDS_LIST: "banned-password-list.txt"

      # Assumes your LLDAP container is named `lldap`
      OCIS_LDAP_URI: ldap://lldap:3890
      OCIS_LDAP_INSECURE: "true"
      OCIS_LDAP_BIND_DN: "uid=admin,ou=people,${LDAP_BASE_DN}"
      OCIS_LDAP_BIND_PASSWORD: ${LDAP_BIND_PASSWORD}
      OCIS_ADMIN_USER_ID: ${LLDAP_ADMIN_UUID}

      OCIS_LDAP_USER_ENABLED_ATTRIBUTE: uid
      GRAPH_LDAP_SERVER_WRITE_ENABLED: "false" # Does your LLDAP bind user have write access?
      GRAPH_LDAP_REFINT_ENABLED: "false"
      # Disable the built in LDAP server
      OCIS_EXCLUDE_RUN_SERVICES: idm
      # both text and binary cause errors in LLDAP, seems harmless though (?)
      #IDP_LDAP_UUID_ATTRIBUTE_TYPE: 'text'

      LDAP_LOGIN_ATTRIBUTES: "uid"
      IDP_LDAP_LOGIN_ATTRIBUTE: "uid"
      IDP_LDAP_UUID_ATTRIBUTE: "entryuuid"
      OCIS_LDAP_USER_SCHEMA_ID: "entryuuid"
      OCIS_LDAP_GROUP_SCHEMA_ID: "uid"
      OCIS_LDAP_GROUP_SCHEMA_GROUPNAME: "uid"

      OCIS_LDAP_GROUP_BASE_DN: "ou=groups,${LDAP_BASE_DN}"
      OCIS_LDAP_GROUP_OBJECTCLASS: "groupOfUniqueNames"
      # can filter which groups are imported, eg: `(&(objectclass=groupOfUniqueNames)(uid=ocis_*))`
      OCIS_LDAP_GROUP_FILTER: "(objectclass=groupOfUniqueNames)"

      OCIS_LDAP_USER_BASE_DN: "ou=people,${LDAP_BASE_DN}"
      OCIS_LDAP_USER_OBJECTCLASS: "inetOrgPerson"
      # Allows all users
      #OCIS_LDAP_USER_FILTER: "(objectclass=inetOrgPerson)"
      # Allows users who are in the LLDAP group `ocis_users`
      OCIS_LDAP_USER_FILTER: "(&(objectclass=person)(memberOf=cn=ocis_users,ou=groups,${LDAP_BASE_DN}))"
      # NOT WORKING: Used instead of restricting users with OCIS_LDAP_USER_FILTER
      #OCIS_LDAP_DISABLE_USER_MECHANISM: "group"
      #OCIS_LDAP_DISABLED_USERS_GROUP_DN: "uid=ocis_disabled,ou=groups,${LDAP_BASE_DN}"
    volumes:
      # - ./config/ocis/banned-password-list.txt:/etc/ocis/banned-password-list.txt
      # IMPORTANT: see note at top about creating/cowning bind mounts
      - ./cfg:/etc/ocis
      - ./app:/var/lib/ocis
    restart: always
```
