# Home Assistant Configuration

Home Assistant configures ldap auth via the [Command Line Auth Provider](https://www.home-assistant.io/docs/authentication/providers/#command-line). The wiki mentions a script that can be used for LDAP authentication, but it doesn't work in the container version (it is lacking both `ldapsearch` and `curl` ldap protocol support). Thankfully LLDAP has a graphql API to save the day!

## Graphql-based Auth Script

The [auth script](lldap-ha-auth.sh) attempts to authenticate a user against an LLDAP server, using credentials provided via `username` and `password` environment variables. The first argument must be the URL of your LLDAP server, accessible from Home Assistant. You can provide an additional optional argument to confine allowed logins to a single group. The script will output the user's display name as the `name` variable, if not empty.

1. Copy the [auth script](lldap-ha-auth.sh) to your home assistant instance. In this example, we use `/config/lldap-ha-auth.sh`.
      - Set the script as executable by running `chmod +x /config/lldap-ha-auth.sh`
2. Add the following to your configuration.yaml in Home assistant:
```yaml
homeassistant:
  auth_providers:
    # Ensure you have the homeassistant provider enabled if you want to continue using your existing accounts
    - type: homeassistant
    - type: command_line
      command: /config/lldap-ha-auth.sh
      # Only allow users in the 'homeassistant_user' group to login.
      # Change to ["https://lldap.example.com"] to allow all users
      args: ["https://lldap.example.com", "homeassistant_user"]
      meta: true
```
3. Reload your config or restart Home Assistant
