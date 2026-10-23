# Configuration for freeradius

> Before you get started you should be aware that since LLDAP
> does not store and hand out cleartext-passwords,
> the only authentication methods that are known to work are PAP and TTLS/PAP.

For more guides and reference on freeradius see [the official documentation](https://www.freeradius.org/documentation/).
Depending on the distribution you use to set up freeradius the filepaths may be different from the ones given here.
The version given here is for valid for Debian 13 Trixie with freeradius 3.2.10 .

Install the LDAP module for freeradius

```bash
apt install freeradius-ldap
```

Go to */etc/freeradius/mods-available/ldap* and set the configuration.
You can use [the most basic configuration](ldap) for reference.

Then create a symlink to *mods-enabled* to activate the LDAP module.

```bash
cd /etc/freeradius/mods-enabled/
ln -s ../mods-available/ldap .
```

Now in order to enable authentication via the LDAP module, go to */etc/freeradius/sites-enabled/default* and add (or uncomment)

```text
authorize {

  ...
  
      ldap
      
      if ((ok || updated) && User-Password && !control:Auth-Type) {
            update control {
                  &Auth-Type := ldap
            }
      }

  ...
  
}
```

and

```text
authenticate {

      ...
  
      Auth-Type LDAP {
            ldap
      }
  
      ...
    
}
```

To also enable LDAP in other sites, uncomment the LDAP sections in these configuration files as well.
If you want to use EAP-TTLS/PAP you will have to do so in the */etc/freeradius/sites-enabled/inner-tunnel* file.

After you restart freeradius, either via systemd

```bash
systemctl restart freeradius
```

or in debug mode

```bash
freeradius -X
```

run a test by attempting a login with radtest

```bash
radtest <username> <password> localhost 0 <client_secret>
```

Use a username and corresponding password from your LLDAP
and the client secret for localhost from */etc/freeradius/clients.conf*.

If this checks out, you have successfully set up your freeradius to use LLDAP as backend.
In case it does not, follow the debug output to find the errors.

You can now go on to set up freeradius for EAP-TTLS/PAP authentication in your wifi
or many of the other things freeradius enables you to do.
