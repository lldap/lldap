# Squid

[Squid](http://www.squid-cache.org/) is a caching HTTP/HTTPS proxy.

This guide will show you how to configure it to allow any user of the group `proxy` to use the proxy server.

The configuration file `/etc/squid/squid.conf`
```
auth_param basic program /usr/lib/squid/basic_ldap_auth -b "dc=example,dc=com" -D "uid=admin,ou=people,dc=example,dc=com" -W /etc/squid/ldap_password -f "(&(memberOf=uid=proxy,ou=groups,dc=example,dc=com)(uid=%s))" -H ldap://IP_OF_LLDAP_SERVER:3890
acl localnet src 0.0.0.1-0.255.255.255	# RFC 1122 "this" network (LAN)
acl localnet src 10.0.0.0/8		# RFC 1918 local private network (LAN)
acl localnet src 100.64.0.0/10		# RFC 6598 shared address space (CGN)
acl localnet src 169.254.0.0/16 	# RFC 3927 link-local (directly plugged) machines
acl localnet src 172.16.0.0/12		# RFC 1918 local private network (LAN)
acl localnet src 192.168.0.0/16		# RFC 1918 local private network (LAN)
acl localnet src fc00::/7       	# RFC 4193 local private network range
acl localnet src fe80::/10      	# RFC 4291 link-local (directly plugged) machines
acl SSL_ports port 443
acl Safe_ports port 80		# http
acl Safe_ports port 21		# ftp
acl Safe_ports port 443		# https
acl Safe_ports port 70		# gopher
acl Safe_ports port 210		# wais
acl Safe_ports port 1025-65535	# unregistered ports
acl Safe_ports port 280		# http-mgmt
acl Safe_ports port 488		# gss-http
acl Safe_ports port 591		# filemaker
acl Safe_ports port 777		# multiling http
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localhost manager
http_access deny manager
include /etc/squid/conf.d/*.conf
http_access allow localhost
acl ldap-auth proxy_auth REQUIRED
http_access allow ldap-auth
# http_access deny all
http_port 3128
coredump_dir /var/spool/squid
refresh_pattern ^ftp:		1440	20%	10080
refresh_pattern ^gopher:	1440	0%	1440
refresh_pattern -i (/cgi-bin/|\?) 0	0%	0
refresh_pattern \/(Packages|Sources)(|\.bz2|\.gz|\.xz)$ 0 0% 0 refresh-ims
refresh_pattern \/Release(|\.gpg)$ 0 0% 0 refresh-ims
refresh_pattern \/InRelease$ 0 0% 0 refresh-ims
refresh_pattern \/(Translation-.*)(|\.bz2|\.gz|\.xz)$ 0 0% 0 refresh-ims
refresh_pattern .		0	20%	4320
```
The password for the binduser is stored in `/etc/squid/ldap_password` e.g.
```
PASSWORD_FOR_BINDUSER
```

After you restart squid with `systemctl restart squid` check it is working with
```
curl -O -L "https://www.redhat.com/index.html" -x "user_name:password@proxy.example.com:3128"
```
