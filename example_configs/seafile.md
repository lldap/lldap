# Configuration for Seafile
Seafile can be bridged to LLDAP directly, or by using Authelia as an intermediary. This document will guide you through both setups.

## Configuring Seafile v11.0+ to use LLDAP directly
Starting Seafile v11.0 :
- CCNET module doesn't exist anymore
- More flexibility is given to authenticate in seafile : ID binding can now be different from user email, so LLDAP UID can be used.

Add the following to your `seafile/conf/seahub_settings.py` :
```
ENABLE_LDAP = True
LDAP_SERVER_URL = 'ldap://192.168.1.100:3890'
LDAP_BASE_DN = 'ou=people,dc=example,dc=com'
LDAP_ADMIN_DN = 'uid=admin,ou=people,dc=example,dc=com'
LDAP_ADMIN_PASSWORD = 'CHANGE_ME'
LDAP_PROVIDER = 'ldap'
LDAP_LOGIN_ATTR = 'uid'
LDAP_CONTACT_EMAIL_ATTR = 'mail'
LDAP_USER_ROLE_ATTR = ''
LDAP_USER_FIRST_NAME_ATTR = 'givenName'
LDAP_USER_LAST_NAME_ATTR = 'sn'
LDAP_USER_NAME_REVERSE = False
```

* Replace `192.168.1.100:3890` with your LLDAP server's ip/hostname and port.
* Replace every instance of `dc=example,dc=com` with your configured domain.

After restarting the Seafile server, users should be able to log in with their UID and password.

Note : There is currently no ldap binding for users' avatar. If interested, do [mention it](https://forum.seafile.com/t/feature-request-avatar-picture-from-ldap/3350/6) to the developers to give more credit to the feature.

## Configuring Seafile (prior to v11.0) to use LLDAP directly
**Note for Seafile before v11:** Seafile's LDAP interface used to require a unique, immutable user identifier in the format of `username@domain`. This isn't true starting Seafile v11.0 and ulterior versions (see previous section Configuring Seafile v11.0+ §).
For Seafile instances prior to v11, since LLDAP does not provide an attribute like `userPrincipalName`, the only attribute that somewhat qualifies is therefore `mail`. However, using `mail` as the user identifier results in the issue that Seafile will treat you as an entirely new user if you change your email address through LLDAP.

Add the following to your `seafile/conf/ccnet.conf` file:
```
[LDAP]
HOST = ldap://192.168.1.100:3890
BASE = ou=people,dc=example,dc=com
USER_DN = uid=admin,ou=people,dc=example,dc=com
PASSWORD = CHANGE_ME
LOGIN_ATTR = mail
```
* Replace `192.168.1.100:3890` with your LLDAP server's ip/hostname and port.
* Replace every instance of `dc=example,dc=com` with your configured domain.

After restarting the Seafile server, users should be able to log in with their email address and password.

### Filtering by group membership
If you only want members of a specific group to be able to log in, add the following line:
```
FILTER = memberOf=cn=seafile_user,ou=groups,dc=example,dc=com
```
* Replace `seafile_user` with the name of your group.

## Configuring Seafile to use LLDAP with Authelia as an intermediary
Authelia is an open-source authentication and authorization server that can use LLDAP as a backend and act as an OpenID Connect Provider. We're going to assume that you have already set up Authelia and configured it with LLDAP.
If not, you can find an example configuration [here](authelia_config.yml).

1. Add the following to Authelia's `configuration.yml`:
```
identity_providers:
  oidc:
    hmac_secret: Your_HMAC_Secret #Replace with a random string
    issuer_private_key: |
        -----BEGIN RSA PRIVATE KEY-----
        Your_Private_Key
        #See https://www.authelia.com/configuration/identity-providers/open-id-connect/#issuer_private_key for instructions on how to generate a key
        -----END RSA PRIVATE KEY-----
    cors:
      endpoints:
        - authorization
        - token
        - revocation
        - introspection
        - userinfo
    clients:
      - id: seafile
        description: Seafile #The display name of the application. Will show up on Authelia consent screens
        secret: Your_Shared_Secret #Replace with random string
        public: false
        authorization_policy: one_factor #Can also be two_factor
        scopes:
          - openid
          - profile
          - email
        redirect_uris:
          - https://seafile.example.com/oauth/callback/
        userinfo_signing_algorithm: none
        pre_configured_consent_duration: 6M
        #On first login you must consent to sharing information between Authelia and Seafile. This option configures the amount of time after which you need to reconsent.
        # y = years, M = months, w = weeks, d = days
```

2. Add the following to `seafile/conf/seahub_settings.py`
```
ENABLE_OAUTH = True
OAUTH_ENABLE_INSECURE_TRANSPORT = True
OAUTH_CLIENT_ID = 'seafile' #Must be the same as in Authelia
OAUTH_CLIENT_SECRET = 'Your_Shared_Secret' #Must be the same as in Authelia
OAUTH_REDIRECT_URL = 'https://seafile.example.com/oauth/callback/'
OAUTH_PROVIDER_DOMAIN = 'auth.example.com'
OAUTH_AUTHORIZATION_URL = 'https://auth.example.com/api/oidc/authorization'
OAUTH_TOKEN_URL = 'https://auth.example.com/api/oidc/token'
OAUTH_USER_INFO_URL = 'https://auth.example.com/api/oidc/userinfo'
OAUTH_SCOPE = [
  "openid",
  "profile",
  "email",
]
OAUTH_ATTRIBUTE_MAP = {
    "preferred_username": (True, "email"), #Seafile will create a unique identifier of your <LLDAP's User ID >@<the value specified in OAUTH_PROVIDER_DOMAIN>. The identifier is not visible to the user and not actually used as the email address unlike the value suggests
    "name": (False, "name"),
    "id": (False, "not used"),
    "email": (False, "contact_email"),
}
```

Restart both your Authelia and Seafile server. You should see a "Single Sign-On" button on Seafile's login page. Clicking it should redirect you to Authelia. If you use the [example config for Authelia](authelia_config.yml), you should be able to log in using your LLDAP User ID.
