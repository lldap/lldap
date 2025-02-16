# Configuration for Quay

Quay is a container image registry that enables you to build, organize, distribute, and deploy containers.

The official LDAP configuration documentation is located [here](https://docs.projectquay.io/config_quay.html#config-fields-ldap).

For standalone deployments of Project Quay, the core configuration is primarily set through the `config.yaml` file.

If you install Project Quay on OpenShift Container Platform / OKD using the Project Quay Operator, the configuration resides in the `config bundle secret`. 

This example assists with a basic LDAP configuration.

```yaml
AUTHENTICATION_TYPE: LDAP
LDAP_ADMIN_DN: cn=bind_user,ou=people,dc=example,dc=com # The admin DN user must be a member of the lldap_strict_readonly group.
LDAP_ADMIN_PASSWD: password
LDAP_ALLOW_INSECURE_FALLBACK: false
LDAP_BASE_DN:
    - dc=example
    - dc=com
LDAP_EMAIL_ATTR: mail
LDAP_UID_ATTR: uid
LDAP_URI: ldap://<example_url>
LDAP_USER_RDN:
    - ou=people
```
