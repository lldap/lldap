# Getting Started with UNIX PAM using SSSD

## Configuring LLDAP

### Configure LDAPS

You **must** use LDAPS. You MUST NOT use plain LDAP. Even over a private network this costs you nearly nothing, and passwords will be sent in PLAIN TEXT without it.

```jsx
[ldaps_options]
enabled=true
port=6360
cert_file="cert.pem"
key_file="key.pem"
```

You can generate an SSL certificate for it with the following command. The `subjectAltName` is REQUIRED. Make sure all domains are listed there, even your `CN`.

```bash
openssl req -x509 -nodes -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 36500 -nodes -subj "/CN=lldap.example.net" -addext "subjectAltName = DNS:lldap.example.net"
```

### Setting up the custom attributes

You will need to add the following custom attributes to the **user schema**.

- uidNumber (integer)
- gidNumber (integer, multiple values)
- homeDirectory (string)
- unixShell (string)
- sshPublicKey (string) (only if you’re setting up SSH Public Key Sync)

You will need to add the following custom attributes to the **group schema.**

- gidNumber (integer)

You will now need to populate these values for all the users you wish to be able to login.

## Client setup

### Install the client packages

You need to install the packages `sssd` `sssd-tools` `libnss-sss` `libpam-sss` `libsss-sudo` .

E.g. on Debian/Ubuntu

```bash
sudo apt update; sudo apt install -y sssd sssd-tools libnss-sss libpam-sss libsss-sudo
```

### Configure the client packages

Use your favourite text editor to create/open the file `/etc/sssd/sssd.conf` .

E.g. Using nano

```bash
sudo nano /etc/sssd/sssd.conf
```

Insert the contents of the provided template (sssd.conf), and you will need to change the content on the following line numbers:

- Line 3
- Line 9
- Line 14
- Line 18
- Line 19
- Line 23
- Line 26
- Line 37

SSSD will **refuse** to run if it’s config file is world-readable, so apply the following permissions to it:

```bash
sudo chmod 600 /etc/sssd/sssd.conf
```

Restart SSSD to apply any changes:

```bash
sudo systemctl restart sssd
```

Enable automatic creation of home directories
```bash
sudo pam-auth-update --enable mkhomedir
```

## Permissions and SSH Key sync

### SSH Key Sync

In order to do this, you need to setup the custom attribute `sshPublicKey` in the user schema. Then, you must modify your SSSD config file to include:

```bash
sudo nano /etc/sssd/sssd.conf
```

```jsx
[domain/example.com]
ldap_user_ssh_public_key = sshPublicKey
```

And the following to the bottom of your OpenSSH config file:

```bash
/etc/ssh/sshd_config
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

Linux often manages permissions to tools such as Sudo and Docker based on group membership. There are two possible ways to achieve this. 

**Number 1**

**If all your client systems are setup identically,** you can just check the group id of the local group, i.e. Sudo being 27 on most Debian and Ubuntu installs, and set that as the gid in LLDAP. For tools such as docker, you can create a group before install with a custom gid on the system, which must be the same on all, and use that GID on the LLDAP group

Sudo

![image](https://github.com/user-attachments/assets/731847e6-c857-4250-a007-a3790a6a1b6d)

Docker

```jsx
sudo groupadd docker -g 722
```

![image](https://github.com/user-attachments/assets/face88d0-5a20-4442-a5e3-9f6a1ae41b68)

**Number 2**

Create a group in LLDAP that you would like all your users who have sudo access to be in, and add the following to the bottom of `/etc/sudoers` . 

E.g. if your group is named `lldap_sudo`

```bash
%lldap_sudo ALL=(ALL:ALL) ALL
```

## Debugging

To verify your config file’s validity, you can run the following command

```jsx
sudo sssctl config-check
```

To flush SSSD’s cache

```jsx
sudo sss_cache -E
```

## Final Notes
To see the old guide for NSLCD, go to NSLCD.md.
