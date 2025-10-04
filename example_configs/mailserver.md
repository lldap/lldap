# Mailserver Docker

[Docker-mailserver](https://docker-mailserver.github.io/docker-mailserver/latest/) is a Production-ready full-stack but simple mail server (SMTP, IMAP, LDAP, Antispam, Antivirus, etc.) running inside a container.

To integrate with LLDAP, ensure you correctly adjust the `docker-mailserver` container environment values.

## Compose File Sample
```yaml
version: "3.9"
services:
  lldap:
    image: lldap/lldap:stable
    ports:
      - "3890:3890"
      - "17170:17170"
    volumes:
      - "lldap_data:/data"
    environment:
      - VERBOSE=true
      - TZ=Etc/UTC
      - LLDAP_JWT_SECRET=yourjwt
      - LLDAP_LDAP_USER_PASS=adminpassword
      - LLDAP_LDAP_BASE_DN=dc=example,dc=com

  mailserver:
    image: ghcr.io/docker-mailserver/docker-mailserver:latest
    container_name: mailserver
    hostname: mail.example.com
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
      - LDAP_SERVER_HOST=ldap://lldap:3890
      - LDAP_SEARCH_BASE=ou=people,dc=example,dc=com
      - LDAP_BIND_DN=uid=admin,ou=people,dc=example,dc=com
      - LDAP_BIND_PW=adminpassword
      - LDAP_QUERY_FILTER_USER=(&(objectClass=inetOrgPerson)(|(uid=%u)(mail=%n)))
      - LDAP_QUERY_FILTER_GROUP=(&(objectClass=groupOfUniqueNames)(uid=%s))
      - LDAP_QUERY_FILTER_ALIAS=(&(objectClass=inetOrgPerson)(|(uid=%u)(mail=%n)))
      - LDAP_QUERY_FILTER_DOMAIN=(mail=*@%s)
      # <<< Postfix LDAP Integration
      # >>> Dovecot LDAP Integration
      - ENABLE_QUOTAS=0
      - DOVECOT_AUTH_BIND=yes
      - DOVECOT_USER_FILTER=(&(objectClass=inetOrgPerson)(|(uid=%u)(mail=%n)))
      - DOVECOT_USER_ATTRS==uid=5000,=gid=5000,=home=/var/mail/%Ln,=mail=maildir:~/Maildir
      - POSTMASTER_ADDRESS=postmaster@d3n.com
    cap_add:
      - SYS_PTRACE
      - NET_ADMIN # For Fail2Ban to work

  roundcubemail:
    image: roundcube/roundcubemail:latest
    container_name: roundcubemail
    restart: always
    volumes:
      - roundcube_config:/var/roundcube/config
      - roundcube_plugins:/var/www/html/plugins
    ports:
      - "9002:80"
    environment:
      - ROUNDCUBEMAIL_DB_TYPE=sqlite
      - ROUNDCUBEMAIL_SKIN=elastic
      - ROUNDCUBEMAIL_DEFAULT_HOST=mailserver # IMAP
      - ROUNDCUBEMAIL_SMTP_SERVER=mailserver # SMTP
      - ROUNDCUBEMAIL_COMPOSER_PLUGINS=roundcube/carddav
      - ROUNDCUBEMAIL_PLUGINS=carddav

volumes:
  mailserver-data:
  mailserver-config:
  mailserver-state:
  lldap_data:
  roundcube_config:
  roundcube_plugins:

```
