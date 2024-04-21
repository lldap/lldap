Extract lldap's [FreeBSD tar.gz](https://github.com/n-connect/rustd-hbbx/blob/main/x86_64-freebsd_lldap-0.5.1.tar.gz) under /usr/local/:

`tar -xvf x86_64-freebsd_lldap-0.5.1.tar.gz -C /usr/local/`

Move rc.d script into the right place:
`mv /usr/local/lldap_server/rc.d_lldap /usr/local/etc/rc.d/`

Make your config, if your want to enable LDAPS, copy your server key and certification files, and set the owneship (currently www):

`cp /usr/local/lldap_server/lldap_config.docker_template.toml /usr/local/lldap_server/lldap_config..toml`

Enable lldap service in /etc/rc.conf:

`echo "lldap_enable=YES" > /etc/rc.conf`

Start your service:

`service lldap start`
