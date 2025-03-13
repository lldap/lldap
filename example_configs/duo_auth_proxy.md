# Duo Auth Proxy Configuration Guide

## Configuring DuoAuthProxy

To set up DuoAuthProxy with LLDAP, you need to configure the `authproxy.cfg` file properly. 
- `bind_dn`
- `service_account_username`
- `service_account_password`
- `search_dn`
- `ikey`
- `skey`
- `api_host`

### Access your Duo admin console
1. Log in to your Duo admin console.
2. Navigate to **Applications** -> **Protect an Application**.
3. Search for `proxy` and select **LDAP Proxy**.
4. Copy the credentials (`ikey`, `skey`, `api_host`) for the next step.

### Example Configuration

```ini
[main]
log_stdout=true

[ad_client]
host=LLDAP
port=3890
auth_type=plain
bind_dn=uid=svc-duoauthproxy,ou=people,dc=example,dc=com
service_account_username=svc-duoauthproxy
service_account_password=password
search_dn=ou=people,dc=example,dc=com
username_attribute=uid
at_attribute=mail

[ldap_server_auto]
ikey=DIXXXXXXXXXXXXXXXXXX
skey=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
api_host=api-XXXXXXXX.duosecurity.com
failmode=secure
client=ad_client
port=1812
exempt_primary_bind=false
exempt_ou_1=uid=svc-duoauthproxy,ou=people,dc=example,dc=com
```

### Running DuoAuthProxy in Docker

```sh
docker run -d \
       --name=DuoAuthProxy \
       --network auth \
       -v /path/to/authproxy.cfg:/app/conf/authproxy.cfg \
       --restart unless-stopped \
       minimages/duoauthproxy
```

You can also choose to host it natively or generate your own image using the official instructions.

# Connecting a Service to Duo Auth Proxy
This section demonstrates how to connect a service to Duo Auth Proxy, using Jellyfin as an example. You can follow the same approach for other services.
## Preparing Jellyfin

Ensure Jellyfin is set up and added to the `auth` network:

```sh
docker network connect auth jellyfin
```

### Installing LDAP Authentication Plugin

Jellyfin requires the LDAP Authentication plugin. Restart Jellyfin after installing the plugin.

### Configuring LDAP Authentication in Jellyfin

#### **LDAP Server Settings**
- **LDAP Server:** `DuoAuthProxy`
- **LDAP Port:** `1812`
- **Secure LDAP:** unchecked
- **StartTLS:** unchecked
- **Skip SSL/TLS Verification:** checked
- **Allow Password Change:** *(optional, requires `lldap_password_manager` group)*
- **LDAP Bind User:** `uid=svc-duoauthproxy,ou=people,dc=example,dc=com`
- **LDAP Bind User Password:** `password`
- **LDAP Base DN for searches:** `ou=people,dc=example,dc=com`

Click **Save and Test LDAP Server Settings** to check connectivity.

#### **LDAP User Settings**
- **LDAP Search Filter:** `(uid=*)`
- **LDAP Search Attributes:** `uid, mail`
- **LDAP Uid Attribute:** `uid`
- **LDAP Username Attribute:** `uid`
- **LDAP Password Attribute:** `userPassword`
- **LDAP Admin Base DN:** `ou=people,dc=example,dc=com`
- **LDAP Admin Filter:** `(memberof=cn=lldap_admin,ou=example,dc=com)`

Click **Save and Test LDAP Filter Settings** to verify user detection.

#### **Final Setup**
- Enter `admin` in **Test Login Name**
- Click **Save Search Attribute Settings and Query User** to finalize lookup
- Adjust **Jellyfin User Settings** as needed
- Click the big blue **Save** button

If existing users are present, switch their authentication provider to **LDAP-Authentication**.

### Testing the New Authentication Flow

Log out and attempt login to verify the new authentication flow. If issues arise, restart Jellyfin and try again.

