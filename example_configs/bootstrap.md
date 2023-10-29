# Bootstrapping lldap using [bootstrap.sh](bootstrap.sh) script

bootstrap.sh allows managing your lldap in a git-ops, declarative way using JSON config files.

The script can:

* create, update users
  * set/update all lldap built-in user attributes
  * add/remove users to/from corresponding groups
  * set/update user avatar from file, link or from gravatar by user email
  * set/update user password
* create groups
* delete redundant users and groups (when `DO_CLEANUP` env var is true)
* maintain the desired state described in JSON config files


![](images/bootstrap-example-log-1.jpeg)

## Required packages

> These packages are present in Alpine Linux repos and will be installed automatically by script if the corresponding commands can't be found

- curl
- [jq](https://github.com/jqlang/jq)
- [jo](https://github.com/jpmens/jo)

## Environment variables

- `LLDAP_URL` or `LLDAP_URL_FILE` - URL to your lldap instance or path to file that contains URL (**MANDATORY**)
- `LLDAP_ADMIN_USERNAME` or `LLDAP_ADMIN_USERNAME_FILE` - admin username or path to file that contains username (**MANDATORY**)
- `LLDAP_ADMIN_PASSWORD` or `LLDAP_ADMIN_PASSWORD_FILE` - admin password or path to file that contains password (**MANDATORY**)
- `USER_CONFIGS_DIR` (default value: `/user-configs`) - directory where the user JSON configs could be found
- `GROUP_CONFIGS_DIR` (default value: `/group-configs`) - directory where the group JSON configs could be found
- `LLDAP_SET_PASSWORD_PATH` - path to the `lldap_set_password` utility (default value: `/app/lldap_set_password`)
- `DO_CLEANUP` (default value: `false`) - delete groups and users not specified in config files, also remove users from groups that they do not belong to

## Config files

There are two types of config files: [group](#group-config-file-example) and [user](#user-config-file-example) configs.
Each config file can be as one JSON file with nested JSON top-level values as several JSON files.

### Group config file example

Group configs are used to define groups that will be created by the script

Fields description:

* `name`: name of the group (**MANDATORY**)

```json
{
  "name": "group-1"
}
{
  "name": "group-2"
}
```

### User config file example

User config defines all the lldap user structures,
if the non-mandatory field is omitted, the script will clean this field in lldap as well.

Fields description:

* `id`: it's just username (**MANDATORY**)
* `email`: self-explanatory (**MANDATORY**)
* `password`: would be used to set the password using `lldap_set_password` utility
* `displayName`: self-explanatory
* `firstName`: self-explanatory
* `lastName`: self-explanatory
* `avatar_file`: must be a valid path to jpeg file (ignored if `avatar_url` specified)
* `avatar_url`: must be a valid URL to jpeg file (ignored if `gravatar_avatar` specified)
* `gravatar_avatar` (`false` by default): the script will try to get an avatar from [gravatar](https://gravatar.com/) by previously specified `email` (has the highest priority)
* `weserv_avatar` (`false` by default): avatar file from `avatar_url` or `gravatar_avatar` would be converted to jpeg using [wsrv.nl](https://wsrv.nl) (useful when your avatar is png)
* `groups`: an array of groups the user would be a member of (all the groups must be specified in group config files)

```json
{
  "id": "username",
  "email": "username@example.com",
  "password": "changeme",
  "displayName": "Display Name",
  "firstName": "First",
  "lastName": "Last",
  "avatar_file": "/path/to/avatar.jpg",
  "avatar_url": "https://i.imgur.com/nbCxk3z.jpg",
  "gravatar_avatar": "false",
  "weserv_avatar": "false",
  "groups": [
    "group-1",
    "group-2"
  ]
}

```

## Deploy example

### Kubernetes job

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: lldap-bootstrap
  annotations:
    argocd.argoproj.io/hook: PostSync
    argocd.argoproj.io/hook-delete-policy: BeforeHookCreation
spec:
  template:
    spec:
      restartPolicy: OnFailure
      containers:
        - name: lldap-bootstrap
          image: nitnelave/lldap:v0.5.0

          command:
            - /bootstrap/bootstrap.sh

          env:
            - name: LLDAP_URL
              value: "http://lldap:8080"

            - name: LLDAP_ADMIN_USERNAME
              valueFrom: { secretKeyRef: { name: lldap-admin-user, key: username } }

            - name: LLDAP_ADMIN_PASSWORD
              valueFrom: { secretKeyRef: { name: lldap-admin-user, key: password } }

            - name: DO_CLEANUP
              value: "true"

          volumeMounts:
            - name: bootstrap
              mountPath: /bootstrap/bootstrap.sh
              subPath: bootstrap.sh

            - name: user-configs
              mountPath: /user-configs
              readOnly: true

            - name: group-configs
              mountPath: /group-configs
              readOnly: true

      volumes:
        - name: bootstrap
          configMap:
            name: bootstrap
            defaultMode: 0555
            items:
              - key: bootstrap.sh
                path: bootstrap.sh

        - name: user-configs
          projected:
            sources:
              - secret:
                  name: lldap-admin-user
                  items:
                    - key: user-config.json
                      path: admin-config.json
              - secret:
                  name: lldap-password-manager-user
                  items:
                    - key: user-config.json
                      path: password-manager-config.json
              - secret:
                  name: lldap-bootstrap-configs
                  items:
                    - key: user-configs.json
                      path: user-configs.json

        - name: group-configs
          projected:
            sources:
              - secret:
                  name: lldap-bootstrap-configs
                  items:
                    - key: group-configs.json
                      path: group-configs.json
```
