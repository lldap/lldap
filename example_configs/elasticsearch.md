# Elasticsearch configuration

> ⚠️ Configuring Elasticsearch to use LDAP auth requires a paid licence. Only the `default` and `file` realms are enabled on a Basic licence. Using the trial licence on cluster init will allow LDAP auth to be configured.

This basic configuration example is for LLDAP auth on [Elastic Cloud on Kubernetes (ECK)](https://www.elastic.co/docs/deploy-manage/deploy/cloud-on-k8s). Advanced configuration can be found in the [Elastic docs](https://www.elastic.co/docs/deploy-manage/users-roles/cluster-or-deployment-auth/ldap).

## Elasticsearch

To perform auth using LLDAP in Elasticsearch, add the following lines to the Elasticsearch spec:

```yaml
spec:
  nodesets:
    - name: elasticsearch
      config:
        xpack.security.authc.realms.ldap:
          ldap1:
            order: 1
            enabled: true
            url: "ldap://<ip.of.lldap.instance>:3890"
            user_dn_templates:
              - "uid={0},ou=people,dc=example,dc=com"
            bind_dn: "uid=admin,ou=people,dc=example,dc=com"
            group_search:
              base_dn: "ou=groups,dc=example,dc=com"
            unmapped_groups_as_roles: false
  secureSettings:
    - secretName: elasticsearch-keystore-values
```

Then, create a secret called `elasticsearch-keystore-values`:

```yaml
apiVersion: v1
kind: Secret
type: Opaque
metadata:
  name: elasticsearch-keystore-values
  namespace: elastic
data:
  xpack.security.authc.realms.ldap.ldap1.secure_bind_password: base64_encoded_ldap_admin_password
```

## Kibana

To allow Kibana to auth logins using LLDAP, add the following lines to the Kibana spec:

```yaml
spec:
  config:
    xpack.security.authc.providers:
      basic.ldap1:
        order: 0
```

Unless doing additional manifest configuration to automatically map, you will need to create a role mapping between an LLDAP role and an Elasticsearch role (e.g. `superuser`). This can be done by logging in using the default `elastic` user created during cluster init and then creating a role mapping in Stack Management. Once created, you will be able to login using LLDAP auth.