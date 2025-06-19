## Installing the quadlet lldap user service

The following assumes you have a working podman installation.

- Copy the .containers, .volume and .network files to `~/.config/containers/systemd/`
- Create the necessary secrets: `lldap-jwt-secret`, `lldap-key-seed`and `lldap-ldap-user-pass`
    - Podman allows several different methods to create secrets; here, it will be done purely from the command line. Don't forget to replace the secret values with something actually secret.
    ```
        $ echo 'your-first-secret-here' | podman secret create lldap-jwt-secret -
        $ echo 'your-second-secret-here' | podman secret create lldap-key-seed -
        $ echo 'your-third-secret-here' | podman secret create lldap-ldap-user-pass -
    ```
- At this point you should be able to start the container.
    - Test this with:
    ```
        $ podman --user daemon-reload
        $ podman --user start lldap
        $ podman --user status lldap
    ```
    - If anything anomalous shows up in the log, I'm sorry. It's not you, it's really me.
    - Assuming it launched correctly, you should now stop it again.
    ```
        $ podman --user stop lldap
    ```
- Make any adjustments you feel are necessary to the networks file (because I have no clue what I'm doing).
- Now all that's left to do is the [bootstrapping process](../bootstrap/bootstrap.md#docker-compose)
    - Prepare your bootstrapping config as for the manual process in `~/containers/lldap`
    - Uncomment the lines in lldap.container pertaining to the bootstrap process (lines 61-65)
    - Start the container:
        ```
        $ podman --user daemon-reload
        $ podman --user start lldap
        ```
    - Attach a terminal to the container, and run bootstrap.sh
        ```
        $ podman exec -ti lldap bash
        $ ./bootstrap.sh
        ```
- Once the bootstrapping is done, you comment out the lines in lldap.container regarding bootstrapping (61-65), stop the unit, reload the daemon, and start it again.
- LLDAP is available to any unit that includes the lldap-frontend network. (? I think)
    - If your outside-facing webserver is in a quadlet too, add `Network=lldap-frontend.network` in its quadlet file and make the necessary adjustments to the server configs. Or rename LLDAP's frontend network to a network useful to your webserver, if that is an organizational principle that is aesthetic to you.
    - Your webserver should then manage access to LLDAP from the outside world.
- If your webserver is not running in a podman container/quadlet, then you should publish a port to access LLDAP on the localhost. For example `PublishPort=127.0.0.1:17170:17170`, will make the default port that LLDAP binds to inside the container available from the outside.
    - There is no real reason to modify the port inside the container, but the outside one you might need to adjust if another service already binds it on your host system.
