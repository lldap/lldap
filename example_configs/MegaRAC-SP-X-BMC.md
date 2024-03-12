# MegaRAC SP-X BMC IPMI LDAP Setup

The MegaRAC SP-X BMC is a service processor firmware stack designed by American Megatrends Inc. (AMI), aimed at providing out-of-band management for servers and computing systems. 
It's part of the MegaRAC family of management solutions, offering remote server management capabilities, including monitoring, control, and maintenance functionalities, independent of the operating system or system state. 
This enables administrators to manage systems remotely for tasks such as updates, troubleshooting, and recovery.

## Setting up LLDAP with MegaRAC SP-X BMC IPMI

### Pre-requisites
- Create and assign the `ipmi` group in LLDAP to a (test) user.
- Bind User: It is recommended that you create a separate user account (e.g, `bind_user`) instead of admin for sharing Bind credentials with other services. The bind_user should be a member of the lldap_strict_readonly group to limit access to your LDAP configuration in LLDAP.
- Bind Password: password of the user specified above

### Configuration Steps

1. **Navigate**: Go to `Settings > External User Settings > LDAP/E-Directory Settings > General Settings`.

2. **General LDAP Settings**:
    - **Encryption Type**: `SSL` (or No Encryption if preferred)
    - **Common Name Type**: `FQDN` (or IP if you use a plain IP address to connect to lldap)
    - **Server Address**: `fqdn.lldap.tld`
    - **Port**: `6360` (default for SSL, adjust if necessary to default non ssl `3890`)

3. **Authentication** (use read-only bind user):
    - **Bind DN**: `uid=bind_user,ou=people,dc=example,dc=com`
    - **Password**: `change_bind_user_password`

4. **Search Configuration**:
    - **Search Base**: `ou=people,dc=example,dc=com`
    - **Attribute of User Login**: `uid`

![image](https://github.com/lldap/lldap/blob/main/example_configs/images/megarac_user.png)

5. **Navigate**: Go to `Settings > External User Settings > LDAP/E-Directory Settings > Role groups`.

6. **Click on empty role group in order to assign a new one**

7. **Role Group - Group Details**:
    - **Group Name**: `ipmi`
    - **Group Domain**: `cn=ipmi,ou=groups,dc=example,dc=com`
    - **Group Privilege**: `Administrator`

8. **Group Permissions**:
    - KVM Access: Enabled (adjust as needed)
    - VMedia Access: Enabled (adjust as needed)

![image](https://github.com/lldap/lldap/blob/main/example_configs/images/megarac_group.png)

