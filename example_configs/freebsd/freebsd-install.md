Install lldap port from pkg

```
pkg install lldap
```

Make your config, if your want to enable LDAPS, copy your server key and certification files, and set the owneship (currently www):

`cp /usr/local/share/lldap/lldap_config.toml.example /usr/local/lldap_server/lldap_config.toml`

Enable lldap service in /etc/rc.conf:

`sysrc lldap_enable="YES"`

Start your service:

`service lldap start`
