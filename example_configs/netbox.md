# Configuration for Netbox

Netbox LDAP configuration is located [here](https://netboxlabs.com/docs/netbox/en/stable/installation/6-ldap/)

## Prerequisites

1. Install requirements
    
    **Debian/Ubuntu:** `sudo apt install -y libldap2-dev libsasl2-dev libssl-dev`

    **CentOS:** `sudo yum install -y openldap-devel python3-devel`

2. Install django-auth-ldap

    `source /opt/netbox/venv/bin/activatepip3 install django-auth-ldap`

3. Add package to local requirements

    `sudo sh -c "echo 'django-auth-ldap' >> /opt/netbox/local_requirements.txt"`

4. Enable LDAP backend in configuration.py (*default: /opt/netbox/netbox/netbox/configuration.py*)

    `REMOTE_AUTH_BACKEND = 'netbox.authentication.LDAPBackend'`

## LDAP Configuration

1. Create ldap_config.py file

    `touch /opt/netbox/netbox/netbox/ldap_config.py`

2. Copy and modify the configuration below

```python
import ldap
from django_auth_ldap.config import LDAPSearch, NestedGroupOfNamesType

# Server URI
AUTH_LDAP_SERVER_URI = "ldaps://lldap.example.com:6360"

# Connection options, if necessary
AUTH_LDAP_CONNECTION_OPTIONS = {
    ldap.OPT_REFERRALS: 0  # Disable referral chasing if not needed
}

# Bind DN and password for the service account
AUTH_LDAP_BIND_DN = "uid=admin,ou=people,dc=example,dc=com"
AUTH_LDAP_BIND_PASSWORD = "ChangeMe!"

# Ignore certificate errors (for self-signed certificates)
LDAP_IGNORE_CERT_ERRORS = False  # Only use in development or testing!

# Include this setting if you want to validate the LDAP server certificates against a CA certificate directory on your server
# Note that this is a NetBox-specific setting which sets:
#     ldap.set_option(ldap.OPT_X_TLS_CACERTDIR, LDAP_CA_CERT_DIR)
LDAP_CA_CERT_DIR = '/etc/ssl/certs'

# Include this setting if you want to validate the LDAP server certificates against your own CA.
# Note that this is a NetBox-specific setting which sets:
#     ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, LDAP_CA_CERT_FILE)
LDAP_CA_CERT_FILE = '/path/to/example-CA.crt'

# User search configuration
AUTH_LDAP_USER_SEARCH = LDAPSearch(
    "ou=people,dc=example,dc=com",
    ldap.SCOPE_SUBTREE,
    "(uid=%(user)s)"
)

# User DN template
AUTH_LDAP_USER_DN_TEMPLATE = "uid=%(user)s,ou=people,dc=example,dc=com"

# Map LDAP attributes to Django user attributes
AUTH_LDAP_USER_ATTR_MAP = {
    "username": "uid",
    "email": "mail",
    "first_name": "givenName",
    "last_name": "sn",
}

# Group search configuration
AUTH_LDAP_GROUP_SEARCH = LDAPSearch(
    "ou=groups,dc=example,dc=com",
    ldap.SCOPE_SUBTREE,
    "(objectClass=group)"
)
AUTH_LDAP_GROUP_TYPE = NestedGroupOfNamesType()

# Require users to be in a specific group to log in
AUTH_LDAP_REQUIRE_GROUP = "cn=netbox_users,ou=groups,dc=example,dc=com"

# Mirror LDAP group assignments
AUTH_LDAP_MIRROR_GROUPS = True

# Map LDAP groups to Django user flags
AUTH_LDAP_USER_FLAGS_BY_GROUP = {
    "is_superuser": "cn=netbox_admins,ou=groups,dc=example,dc=com"
}

# Find group permissions
AUTH_LDAP_FIND_GROUP_PERMS = True

# Cache group memberships to reduce LDAP traffic
AUTH_LDAP_CACHE_TIMEOUT = 3600

# Always update user information from LDAP on login
AUTH_LDAP_ALWAYS_UPDATE_USER = True
```

3. Restart netbox and netbox-rq

    `sudo systemctl restart netbox netbox-rq`

## Troubleshoot LDAP

1. Make logging directory

    `sudo mkdir -p /opt/netbox/local/logs/`

2. Make log file

    `sudo touch /opt/netbox/local/logs/django-ldap-debug.log`

3. Set permissions

    `sudo chown -R netbox:root /opt/netbox/local`

4. Add the following to */opt/netbox/netbox/netbox/configuration.py*

```py
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'netbox_auth_log': {
            'level': 'DEBUG',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/opt/netbox/local/logs/django-ldap-debug.log',
            'maxBytes': 1024 * 500,
            'backupCount': 5,
        },
    },
    'loggers': {
        'django_auth_ldap': {
            'handlers': ['netbox_auth_log'],
            'level': 'DEBUG',
        },
    },
}
```