# Getting Started with UNIX PAM using SSSD

## Configuring LLDAP

### Configure LDAPS

This guide assumes LLDAP is being configured with ldaps.

Even in private networks you **should** configure LLDAP to communicate over HTTPS, otherwise passwords will be transmitted
in plain text. Even using self-signed certificate will drastically improve security.

You can generate an SSL certificate for it with the following command. The `subjectAltName` is **required**. Make sure
all domains are listed there, even your `CN`.

```bash
openssl req -x509 -nodes -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 36500 -subj "/CN=ldap.example.com" -addext "subjectAltName = DNS:ldap.example.com"
```

With the generated certificates for your domain, copy the certificates and enable ldaps in the LLDAP configuration.

```
[ldaps_options]
enabled=true
port=636
cert_file="cert.pem"
key_file="key.pem"
```

### Setting up custom attributes

SSSD makes use of the `posixAccount` and `sshPublicKey` object types, their attributes have to be created manually in
LLDAP.

Add the following custom attributes to the **User schema**.

| Attribute     | Type    | Multiple | Example    |
|---------------|---------|:--------:|------------|
| uidNumber     | integer |          | 3000       |
| gidNumber     | integer |          | 3000       |
| homeDirectory | string  |          | /home/user |
| unixShell     | string  |          | /bin/bash  |
| sshPublicKey  | string  |    X     | *sshKey*   |

Add the following custom attributes to the **Group schema.**

| Attribute     | Type    | Multiple | Example    |
|---------------|---------|:--------:|------------|
| gidNumber     | integer |          | 3000       |

The only optional attributes are `unixShell` and `sshPublicKey`. All other attributes **must** be fully populated for
each group and user being used by SSSD. The `gidNumber` of the user schema represents the users primary group. To add
more groups to a user, add the user to groups with an `gidNumber` assigned.

## Client setup

### Install the client packages

You need to install the packages `sssd` `sssd-tools` `libnss-sss` `libpam-sss` `libsss-sudo` .

E.g. on Debian/Ubuntu

```bash
sudo apt install -y sssd sssd-tools libnss-sss libpam-sss libsss-sudo
```

### Configure the client packages

This example makes the following assumptions which need to be adjusted:

* Domain: `example.com`
* Domain Component: `dc=example,dc=com`
* LDAP URL: `ldaps://ldap.example.com/`
* Bind Username: `binduser`
* Bind Password: `bindpassword`

Use your favourite text editor to create the SSSD global configuration `/etc/sssd/sssd.conf`.
The global config filters **out** the root user and group and restricts the number of failed login attempts
with cached credentials.

```bash
sudo nano /etc/sssd/sssd.conf
```

```
[sssd]
config_file_version = 2
services = nss, pam, ssh
domains = example.com

[nss]
filter_users = root
filter_groups = root

[pam]
offline_failed_login_attempts = 3
offline_failed_login_delay = 5

[ssh]
```

The domain configuration is set up for the LLDAP `RFC2307bis` schema and the custom attributes created at the beginning
of the guide. It allows all configured LDAP users to log in to the machine by default while filtering out users and
groups which don't have their posix IDs set. Because caching is enabled make sure to check the [Debugging](#Debugging)
section on how to flush the cache if you are having problems.

Create a separate configuration file for your domain.

```bash
sudo nano /etc/sssd/conf.d/example.com.conf
```

```
[domain/example.com]
id_provider = ldap
auth_provider = ldap
chpass_provider = ldap
access_provider = permit

enumerate = True
cache_credentials = True

# ldap provider
ldap_uri = ldaps://ldap.example.com/
ldap_schema = rfc2307bis
ldap_search_base = dc=example,dc=com

ldap_default_bind_dn = uid=binduser,ou=people,dc=example,dc=com
ldap_default_authtok = bindpassword

ldap_tls_cacert = /etc/ssl/certs/ca-certificates.crt
ldap_tls_reqcert = demand

# users
ldap_user_search_base = ou=people,dc=example,dc=com?subtree?(uidNumber=*)
ldap_user_object_class = posixAccount
ldap_user_name = uid
ldap_user_gecos = cn
ldap_user_uid_number = uidNumber
ldap_user_gid_number = gidNumber
ldap_user_home_directory = homeDirectory
ldap_user_shell = unixShell
ldap_user_ssh_public_key = sshPublicKey

# groups
ldap_group_search_base = ou=groups,dc=example,dc=com?subtree?(gidNumber=*)
ldap_group_object_class = groupOfUniqueNames
ldap_group_name = cn
ldap_group_gid_number = gidNumber
ldap_group_member = uniqueMember
```

SSSD will **refuse** to run if it’s config files have the wrong permissions, so apply the following permissions to it:

```bash
sudo chmod 600 /etc/sssd/sssd.conf
sudo chmod 600 /etc/sssd/conf.d/example.com.conf
```

Enable automatic creation of home directories:

```bash
sudo pam-auth-update --enable mkhomedir
```

Restart SSSD to apply any changes:

```bash
sudo systemctl restart sssd
```

## Permissions and SSH Key sync

### SSH Key Sync

Add the following to the bottom of your OpenSSH config file:

```bash
sudo nano /etc/ssh/sshd_config
```

```bash
AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys
AuthorizedKeysCommandUser nobody
```

Now restart both SSH and SSSD:

```bash
sudo systemctl restart ssh
sudo systemctl restart sssd
```

### Permissions Sync

Linux often manages permissions to tools such as Sudo and Docker based on group membership. There are two possible ways 
to achieve this. 

**Number 1**

**If all your client systems are set up identically,** you can just check the group id of the local group, i.e. `sudo`
being 27 on most Debian and Ubuntu installs, and set that as the gid in LLDAP. 
For tools such as docker, you can create a group before install with a custom gid on the system, which must be the same
on all, and use that GID on the LLDAP group

Sudo

![image](https://github.com/user-attachments/assets/731847e6-c857-4250-a007-a3790a6a1b6d)

Docker

```bash
sudo groupadd docker -g 722
```

![image](https://github.com/user-attachments/assets/face88d0-5a20-4442-a5e3-9f6a1ae41b68)

**Number 2**

Create a group in LLDAP that you would like all your users who have sudo access to be in, and add the following to the
bottom of `/etc/sudoers` . 

E.g. if your group is named `lldap_sudo`

```bash
%lldap_sudo ALL=(ALL:ALL) ALL
```

## Debugging

To verify your config file’s validity, you can run the following command

```bash
sudo sssctl config-check
```

To flush SSSD’s cache

```bash
sudo sss_cache -E
```

Man pages
```bash
man sssd
man sssd-ldap
```

## Final Notes
To see the old guide for NSLCD, go to NSLCD.md.
