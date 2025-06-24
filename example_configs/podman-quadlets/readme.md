## Installing the quadlet lldap user service

The following assumes you have a working podman installation.

- Copy `lldap-db.container`,`lldap.container`, `lldap-db.volume`, `lldap-frontend.network` and `lldap-backend.network` to `~/.config/containers/systemd/`
- Create the necessary secrets: `lldap-jwt-secret`, `lldap-key-seed`and `lldap-ldap-user-pass`
    - Podman allows several different methods to create secrets; here, it will be done purely from the command line. Don't forget to replace the secret values with something actually secret.
    ```bash
        $ LC_ALL=C tr -dc 'A-Za-z0-9!#%&'\''()*+,-./:;<=>?@[\]^_{|}~' </dev/urandom | head -c 32 | podman secret create lldap-jwt-secret -
        $ LC_ALL=C tr -dc 'A-Za-z0-9!#%&'\''()*+,-./:;<=>?@[\]^_{|}~' </dev/urandom | head -c 32 | podman secret create lldap-key-seed -
        $ echo 'your-third-secret-here' | podman secret create lldap-ldap-user-pass -
    ```
    - if later on you need to query any of those secret, you can do so with `podman secret inspect <name of the secret> --showsecret`. The value of the secret is in the output's "SecretData" field.
- At this point you should be able to start the container.
    - Test this with:
    ```bash
        $ podman --user daemon-reload
        $ podman --user start lldap
        $ podman --user status lldap
    ```
    - Assuming it launched correctly, you should now stop it again.
    ```bash
        $ podman --user stop lldap
    ```
- Make any adjustments you feel are necessary to the networks file.
- Now all that's left to do is the [bootstrapping process](../bootstrap/bootstrap.md#docker-compose)
    - Prepare your bootstrapping config as for the manual process in `~/containers/lldap`
    - Toward the end of the container section, uncomment the lines in `ldap.container` regarding
     the bootstrap process.
    - Start the container:
        ```bash
        $ podman --user daemon-reload
        $ podman --user start lldap
        ```
    - Attach a terminal to the container, and run bootstrap.sh
        ```bash
        $ podman exec -ti lldap bash
        $ ./bootstrap.sh
        ```
- Once the bootstrapping is done, remove or comment out the lines uncommented at the previous step, stop the unit, reload the daemon, and start it again.
- LLDAP should be available to any unit that includes the lldap-frontend network.
    - If your outside-facing webserver is in a quadlet too, make sure they share a network, e.g. by adding `Network=lldap-frontend.network` in its quadlet file and making the necessary adjustments to the server configs.
    - Your webserver should then manage access to LLDAP from the outside world.
- If your webserver is not running in a podman container/quadlet, then you should publish a port to access LLDAP on the localhost. For example `PublishPort=127.0.0.1:17170:17170`, will make the default port that LLDAP binds to inside the container available from the outside.
    - There is no real reason to modify the port inside the container, but the outside one you might need to adjust if another service already binds it on your host system.
