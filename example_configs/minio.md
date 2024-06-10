# MinIO Configuration

MinIO is a High-Performance Object Storage released under GNU Affero General Public License v3. 0. It is API compatible with the Amazon S3 cloud storage service. This example assists with basic LDAP configuration and policy attachment.

## LDAP Config

### Navigation

- Login to the WebUI as a consoleAdmin user
- Navigate to `Administrator > Identity > LDAP`
- Click `Edit Configuration`

### Configuration Options

- Server Insecure: Enabled
- Server Address: Hostname or IP for your LLDAP host
- Lookup Bind DN: `uid=admin,ou=people,dc=example,dc=com`
  - It is recommended that you create a separate user account (e.g, `bind_user`) instead of `admin` for sharing Bind credentials with other services. The `bind_user` should be a member of the `lldap_strict_readonly` group to limit access to your LDAP configuration in LLDAP.
- Lookup Bind Password: The password for the user referenced above
- User DN Search Base: `ou=people,dc=example,dc=com`
- User DN Search Filter: `(&(uid=%s)(memberOf=cn=minio_admin,ou=groups,dc=example,dc=com))`
  - This search filter will only allow users that are members of the `minio_admin` group to authenticate. To allow all lldap users, this filter can be used instead `(uid=%s)`
- Group Search Base DN: `ou=groups,dc=example,dc=com`
- Group Search Filter: `(member=%d)`

### Enable LDAP

> Note there appears to be a bug in some versions of MinIO where LDAP is enabled and working, however the configuration UI reports that it is not enabled.

Now, you can enable LDAP authentication by clicking the `Enable LDAP` button, a restart of the service or container is needed. With this configuration, LLDAP users will be able to log in to MinIO now. However they will not be able to do anything, as we need to attach policies giving permissions to users.

## Policy Attachment

Creating MinIO policies is outside of the scope for this document, but it is well documented by MinIO [here](https://min.io/docs/minio/linux/administration/identity-access-management/policy-based-access-control.html). Policies are written in JSON, are extremely flexible, and can be configured to be very granular. In this example we will be using one of the built-in Policies, `consoleAdmin`. We will be applying these policies with the `mc` command line utility.

- Alias your MinIO instance: `mc alias set myMinIO http://<your-minio-address>:<your-minio-api-port> admin <your-admin-password>`
- Attach a policy to your LDAP group: `mc admin policy attach myMinIO consoleAdmin --group='cn=minio_admin,ou=groups,dc=example,dc=com'`

## Alternative configuration

The above options didn't work for me (thielj; 2024-6-10; latest lldap and minio docker images). In particular, having a User DN search base of `ou=people,dc=example,dc=com` conflicted with the condition `memberOf=cn=admins,ou=groups,dc=example,dc=com` due to the groups being outside the 'ou=people' search base. Using just `dc=example,dc=com` as search base was frowned upon by MinIO due to duplicate results. 

The following environment variables made both MinIO and LLDAP happy:

```yaml
    environment:
      MINIO_ROOT_USER: "admin"
      MINIO_ROOT_PASSWORD: "${ADMIN_PASSWORD:?error}"
      
      MINIO_IDENTITY_LDAP_SERVER_ADDR: "ldap.${TOP_DOMAIN}:636"
      #MINIO_IDENTITY_LDAP_TLS_SKIP_VERIFY: "off"
      #MINIO_IDENTITY_LDAP_SERVER_INSECURE: "off"
      #MINIO_IDENTITY_LDAP_SERVER_STARTTLS: "off"

      # https://github.com/lldap/lldap/blob/main/example_configs/minio.md
      MINIO_IDENTITY_LDAP_LOOKUP_BIND_DN: "${LDAP_AUTH_BIND_USER}"
      MINIO_IDENTITY_LDAP_LOOKUP_BIND_PASSWORD: "${LDAP_AUTH_BIND_PASSWORD}"
      MINIO_IDENTITY_LDAP_USER_DN_SEARCH_BASE_DN: "ou=people,${LDAP_BASE_DN}"
      # allow all users to login; they need a policy attached before they can actually do anything
      MINIO_IDENTITY_LDAP_USER_DN_SEARCH_FILTER: "(&(objectclass=posixAccount)(uid=%s))"
      #MINIO_IDENTITY_LDAP_USER_DN_ATTRIBUTES: "uid,cn,mail"
      MINIO_IDENTITY_LDAP_GROUP_SEARCH_BASE_DN: "ou=groups,${LDAP_BASE_DN}"
      MINIO_IDENTITY_LDAP_GROUP_SEARCH_FILTER: "(&(objectclass=groupOfUniqueNames)(member=%d))"
```

Another tip, there's no need to download or install the MinIO CLI. Assuming your running container is named `minio`, this does the trick:

```
$ docker exec minio mc alias set localhost http://localhost:9000 admin "${ADMIN_PASSWORD}"
$ docker exec minio mc ready localhost
$ docker exec minio mc admin policy attach localhost consoleAdmin --group="cn=admins,ou=groups,${LDAP_BASE_DN}"
```
