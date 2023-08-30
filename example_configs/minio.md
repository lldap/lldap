# MinIO Configuration

MinIO is a High-Performance Object Storage released under GNU Affero General Public License v3. 0. It is API compatible with the Amazon S3 cloud storage service. This example assists with basic LDAP configuration and policy attachment.

## LDAP Config

### Navigation

- Login to the WebUI as a consoleAdmin user
- Navigate to `Administrator > Identity > LDAP`
- Click `Edit Configuration`

### Configuration Options

- Server Insecure: Enabled
- Server Address: `Hostname or IP for your LLDAP host`
- Lookup Bind DN: `uid=admin,ou=people,dc=example,dc=com`
  - It is recommended that you create a separate user account (e.g, `bind_user`) instead of `admin` for sharing Bind credentials with other services. The `bind_user` should be a member of the `lldap_strict_readonly` group to limit access to your LDAP configuration in LLDAP.
- Lookup Bind Password: `The password for the user referenced above`
- User DN Search Base: `ou=people,dc=example,dc=com`
- User DN Search Filter: `(&(uid=%s)(memberOf=cn=minio_user,ou=groups,dc=example,dc=com))`
  - This search filter will only allow users that are members of the `minio_user` group to authenticate. To allow all lldap users, this filter can be used instead `(uid=%s)`
- Group Search Base DN: `ou=groups,dc=example,dc=com`
- Group Search Filter: `(member=%d)`

### Enable LDAP

> Note there appears to be a bug in some versions of MinIO where LDAP is enabled and working, however the configuration UI reports that it is not enabled.

Now, you can enable LDAP authentication by clicking the `Enable LDAP` button, a restart of the service or container is needed. With this configuration, LLDAP users will be able to log in to MinIO now. However they will not be able to do anything, as we need to attach policies giving permissions to users.

## Policy Attachment

Creating MinIO policies is outside of the scope for this document, but it is well documented by MinIO [here](https://min.io/docs/minio/linux/administration/identity-access-management/policy-based-access-control.html). Policies are written in JSON, are extremely flexible, and can be configured to be very granular. In this example we will be using one of the built-in Policies, `consoleAdmin`. We will be applying these policies with the `mc` command line utility.

- Alias your MinIO instance: `mc alias set myMinIO http://<your-minio-address>:<your-minio-api-port> admin <your-admin-password>`
- Attach a policy to your LDAP group: `mc admin policy attach myMinIO consoleAdmin --group='cn=minio_user,ou=groups,dc=example,dc=com'`
