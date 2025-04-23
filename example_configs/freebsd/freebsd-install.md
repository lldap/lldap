## Install from Port

Install from Port:

```
pkg install lldap
```

Copy the configuration and don't forget to set up:

```
`cp /usr/local/share/lldap/lldap_config.toml.example /usr/local/lldap_server/lldap_config.toml`
```

Enable lldap service in /etc/rc.conf:

`sysrc lldap_enable="YES"`

Start your service:

`service lldap start`

## Migrates from Manual Installation:

Backup the database, configuration, and user specified file (like cert):
```
cp /usr/local/lldap_server/users.db ./
cp /usr/local/lldap_server/lldap_config.toml ./
```

delete all file and install package from port:

```
rm -rf /usr/local/lldap_server
pkg install lldap
```

Move the db and config back:

```
mv ./users.db /usr/local/lldap_server/ 
mv ./lldap_config.toml /usr/local/lldap_server/ 
```

Set the file permission of the twp file to ldap:
```
chown ldap:ldap /usr/local/lldap_server/users.db
chown ldap:ldap /usr/local/lldap_server/lldap_config.toml
```


## Manual Installation (Deprecated)

Extract lldap's [FreeBSD tar.gz](https://github.com/n-connect/rustd-hbbx/blob/main/x86_64-freebsd_lldap-0.5.1.tar.gz) under /usr/local/:

`tar -xvf x86_64-freebsd_lldap-0.5.1.tar.gz -C /usr/local/`

Move rc.d script into the right place:
`mv /usr/local/lldap_server/rc.d_lldap /usr/local/etc/rc.d/lldap`

Make your config, if your want to enable LDAPS, copy your server key and certification files, and set the owneship (currently ldap):

`cp /usr/local/lldap_server/lldap_config.docker_template.toml /usr/local/lldap_server/lldap_config..toml`

Enable lldap service in /etc/rc.conf:

`sysrc lldap_enable="YES"`

Start your service:

`service lldap start`
