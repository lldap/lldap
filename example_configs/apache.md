# Configuration for Apache

This example snippet provides space under `/webdav/<username>/` if they log in as the user in question.

## Apache LDAP Configuration

```
# The User/Group specified in httpd.conf needs to have write permissions
# on the directory where the DavLockDB is placed and on any directory where
# "Dav On" is specified.

DavLockDB "/var/local/apache2/DavLock"

Alias /webdav "/var/local/apache2/data"

<Directory "/var/local/apache2/data">
        AllowOverride None
        Require all denied
        DirectoryIndex disabled
</Directory>

<DirectoryMatch "^/var/local/apache2/data/(?<user>[^/]+)">
        AuthType Basic
        AuthName "LDAP Credentials"
        AuthBasicProvider ldap

        AuthLDAPURL ldap://lldap:3890/ou=people,dc=example,dc=com?uid?sub?(objectClass=person)
        AuthLDAPBindDN uid=integration,ou=people,dc=example,dc=com
        AuthLDAPBindPassword [redacted]

        <RequireAll>
                Require ldap-user "%{env:MATCH_USER}"
                Require ldap-group cn=WebDAV,ou=groups,dc=example,dc=com
        </RequireAll>

        Dav On
        Options +Indexes
</DirectoryMatch>
```
### Notes

* Make sure you create the `data` directory, and the subdirectories for your users.
* `integration` was an LDAP user I added with strict readonly.
* The `WebDAV` group was something I added and put relevant users into, more as a test of functionality than out of any need.
* I left the comment from the Apache DAV config in because it's not kidding around and it won't be obvious what's going wrong from the Apache logs if you miss that.

## Apache Orchestration

The stock Apache server with that stanza added to the bottom of the stock config and shared into the container.
```
    webdav:
      image: httpd:2.4.66-trixie
      restart: always
      volumes:
        - /opt/webdav:/var/local/apache2
        - ./httpd.conf:/usr/local/apache2/conf/httpd.conf
      labels:
        - "traefik.enable=true"
        - "traefik.http.routers.webdav.entrypoints=websecure"
        - "traefik.http.routers.webdav.rule=Host(`redacted`) && PathPrefix(`/webdav`)"
        - "traefik.http.routers.webdav.tls.certresolver=myresolver"
        - "traefik.http.routers.webdav.service=webdav-service"
        - "traefik.http.services.webdav-service.loadbalancer.server.port=80"
```

