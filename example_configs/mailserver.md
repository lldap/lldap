# Mailserver Docker

[Docker-mailserver](https://docker-mailserver.github.io/docker-mailserver/latest/) is a Production-ready fullstack but simple mail server (SMTP, IMAP, LDAP, Antispam, Antivirus, etc.) running inside a container.

To integrate with LLDAP, make sure you fill in the attributes correctly

Exemple starting [docker-compose](https://github.com/docker-mailserver/docker-mailserver/blob/master/compose.yaml)

Most important part :
```yaml
      # >>> Postfix LDAP Integration
      - ACCOUNT_PROVISIONER=LDAP
      - LDAP_SERVER_HOST=lldap:3890
      - LDAP_SEARCH_BASE=dc=d3n,dc=com
      - LDAP_BIND_DN=uid=admin,ou=people,dc=d3n,dc=com
      - LDAP_BIND_PW=admin123$*
      - LDAP_QUERY_FILTER_USER=(&(objectClass=inetOrgPerson)(|(uid=%u)(mail=%u)))
      - LDAP_QUERY_FILTER_GROUP=(&(objectClass=groupOfUniqueNames)(|(uid=%s)(cn=%s)))
      - LDAP_QUERY_FILTER_ALIAS=(&(objectClass=inetOrgPerson)(|(uid=%u)(mail=%u)))
      - LDAP_QUERY_FILTER_DOMAIN=(|(mail=*@%s)(mailAlias=*@%s)(mailGroupMember=*@%s))
      # <<< Postfix LDAP Integration

      # >>> Dovecot LDAP Integration
      - DOVECOT_AUTH_BIND=yes
      - DOVECOT_USER_FILTER=(&(objectClass=inetOrgPerson)(|(uid=%u)(mail=%u)))
      - DOVECOT_USER_ATTRS==uid=5000,=gid=5000,=home=/var/mail/%Ln,=mail=maildir:~/Maildir
```

Optional to create a bridge network
```shell
docker network create my_bridge 
```

## Final Version 
```yaml
version: "3.9"
services:
  lldap:
    image: nitnelave/lldap:stable
    ports:
      - "3890:3890"
      - "17170:17170"
    volumes:
      - "lldap_data:/data"
    environment:
      - VERBOSE=true
      - TZ=Etc/UTC
      - LLDAP_JWT_SECRET=94721b2ada4bf1ba6462f5eb341ff08372392dbf76
      - LLDAP_LDAP_USER_PASS=admin123$*
      - LLDAP_LDAP_BASE_DN=dc=d3n,dc=com
  mailserver:
    image: ghcr.io/docker-mailserver/docker-mailserver:latest
    container_name: mailserver
    hostname: mail.d3n.com
    ports:
      - "25:25"    # SMTP  (explicit TLS => STARTTLS)
      - "143:143"  # IMAP4 (explicit TLS => STARTTLS)
      - "465:465"  # ESMTP (implicit TLS)
      - "587:587"  # ESMTP (explicit TLS => STARTTLS)
      - "993:993"  # IMAP4 (implicit TLS)
    volumes:
      - mailserver-data:/var/mail
      - mailserver-state:/var/mail-state
      - mailserver-config:/tmp/docker-mailserver/
      - /etc/localtime:/etc/localtime:ro
    restart: always
    stop_grace_period: 1m
    healthcheck:
      test: "ss --listening --tcp | grep -P 'LISTEN.+:smtp' || exit 1"
      timeout: 3s
      retries: 0
    environment:
      - LOG_LEVEL=debug
      - SUPERVISOR_LOGLEVEL=debug
      - SPAMASSASSIN_SPAM_TO_INBOX=1
      - ENABLE_FAIL2BAN=0
      - ENABLE_AMAVIS=0
      - SPOOF_PROTECTION=1
      - ENABLE_OPENDKIM=0
      - ENABLE_OPENDMARC=0
      # >>> Postfix LDAP Integration
      - ACCOUNT_PROVISIONER=LDAP
      - LDAP_SERVER_HOST=lldap:3890
      - LDAP_SEARCH_BASE=dc=d3n,dc=com
      - LDAP_BIND_DN=uid=admin,ou=people,dc=d3n,dc=com
      - LDAP_BIND_PW=admin123$*
      - LDAP_QUERY_FILTER_USER=(&(objectClass=inetOrgPerson)(|(uid=%u)(mail=%u)))
      - LDAP_QUERY_FILTER_GROUP=(&(objectClass=groupOfUniqueNames)(|(uid=%s)(cn=%s)))
      - LDAP_QUERY_FILTER_ALIAS=(&(objectClass=inetOrgPerson)(|(uid=%u)(mail=%u)))
      - LDAP_QUERY_FILTER_DOMAIN=(|(mail=*@%s)(mailAlias=*@%s)(mailGroupMember=*@%s))
      # <<< Postfix LDAP Integration

      # >>> Dovecot LDAP Integration
      - DOVECOT_AUTH_BIND=yes
      - DOVECOT_USER_FILTER=(&(objectClass=inetOrgPerson)(|(uid=%u)(mail=%u)))
      - DOVECOT_USER_ATTRS==uid=5000,=gid=5000,=home=/var/mail/%Ln,=mail=maildir:~/Maildir
      # <<< Dovecot LDAP Integration
      - POSTMASTER_ADDRESS=postmaster@d3n.com
    cap_add:
      - SYS_PTRACE
      - NET_ADMIN # For Fail2Ban to work
  roundcubemail:
    image: roundcube/roundcubemail:latest
    container_name: roundcubemail
    restart: always
    volumes:
      - roundcube_data:/var/www/html
    ports:
      - "9002:80"
    environment:
      - ROUNDCUBEMAIL_DB_TYPE=sqlite
      - ROUNDCUBEMAIL_SKIN=elastic
      - ROUNDCUBEMAIL_DEFAULT_HOST=mailserver # IMAP
      - ROUNDCUBEMAIL_SMTP_SERVER=mailserver # SMTP

networks:
  default:
    external: true
    name: my_bridge
volumes:
  mailserver-data:
  mailserver-config:
  mailserver-state:
  lldap_data:
  roundcube_data:

```