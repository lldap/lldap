# Trusted header authentication

If you already have a reverse proxy that authenticates your users (Authelia,
authentik, oauth2-proxy, ...), it can log them into LLDAP directly. The proxy
adds a header with the username to each request, and LLDAP trusts it.

This lets you protect the LLDAP web interface with multi-factor
authentication. For example, Authelia can use LLDAP as its user backend, while
LLDAP's web interface sits behind Authelia, which requires MFA.

If your identity provider supports OpenID Connect but can't act as an
authentication proxy itself, you can use
[oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/) instead (see
[below](#with-oauth2-proxy)).

LLDAP only trusts the header if the request comes from one of the addresses
listed in `trusted_proxies`.

## Security considerations

1. Only the proxy should be able to reach the LLDAP web server from a trusted
   address. Anything else that can connect from one of the `trusted_proxies`
   can log in as any user, including the admin, just by setting the header.
2. Your proxy **must** remove the header from incoming requests (or overwrite
   it). Otherwise, anyone who can reach the proxy can log in as any user by
   sending the header themselves.
3. If your goal is to require MFA, you **should** block the password login
   endpoints (`/auth/opaque/login/finish` and `/auth/simple/login`) at the
   proxy. Otherwise, users can still log in with only their password. Don't
   block `/auth/opaque/login/start`, because the password change form uses it
   to check the current password.

## How it works

When a request carries the header (by default "Remote-User"):

- LLDAP checks the address of the TCP connection against `trusted_proxies`. It
  never looks at "X-Forwarded-For" or similar headers, which anyone can forge.
- If the address is not trusted, the request is rejected. It does _not_ fall
  back to token authentication.
- Otherwise, the user named in the header is logged in, with the same rights
  as if they had logged in with their password.

The header takes precedence over any token sent with the same request.

Requests without the header are not affected, and neither is the LDAP server.
To log in with a password, don't send the header.

## Configuration

In your `lldap_config.toml`:

```toml
[trusted_header_options]
enabled = true
trusted_proxies = ["172.28.0.0/24"]
# Optional, defaults to "Remote-User".
header_name = "Remote-User"
# Optional, usually the sign-out page of your SSO provider or oauth2-proxy.
logout_url = "https://example.com/oauth2/sign_out"
```

See [lldap_config.docker_template.toml](../lldap_config.docker_template.toml)
for all the options and the corresponding environment variables.

`trusted_proxies` is a list of networks in CIDR notation. For a single address,
use `/32` for IPv4 or `/128` for IPv6. By default, only localhost
(`127.0.0.0/8` and `::1/128`) is trusted.

Set it to the smallest network shared by the proxy and LLDAP. In many setups,
that's just localhost, with LLDAP listening on the loopback interface and the
proxy running on the same host. With Docker, use a dedicated network (see
below). Only trust a LAN if you control every host on it.

You'll usually want to set `logout_url`. As long as the proxy keeps sending the
header, clicking "Logout" in LLDAP logs the user right back in. Redirecting to
the sign-out page of the proxy ends the session there too.

### With Docker

Container IPs change when containers are recreated, so trust a dedicated
network with a fixed subnet instead:

```yaml
networks:
  default:
  auth-net:
    ipam:
      config:
        - subnet: 172.28.0.0/24

services:
  proxy:
    networks: [default, auth-net]
  lldap:
    networks:
      default:
      auth-net:
        aliases: [lldap-auth]
```

Only the proxy and LLDAP should be on `auth-net`. LLDAP stays on the `default`
network because your other services connect to its LDAP port from there, and it
may need to reach your mail server or database. Other services can't join
`auth-net`, because they would then be trusted and could log in as any user.

Since LLDAP is on two networks, the name "lldap" resolves to both of its
addresses. If the proxy connects through the `default` network, its address
isn't trusted and LLDAP rejects the requests. The `lldap-auth` alias avoids
this because it only exists on `auth-net`. Point the proxy to
`http://lldap-auth:17170` rather than `http://lldap:17170`.

In a typical setup with Authelia, though, Authelia is the _only_ LDAP client of
LLDAP. It uses LLDAP as its first-factor backend, and your other services
authenticate through Authelia. If LLDAP doesn't need to reach a mail server or
database either, you can put it on `auth-net` only, and you don't need the
`lldap-auth` alias.

### With Kubernetes

Pod IPs are not stable either. You can trust the pod CIDR of your cluster, and
add a NetworkPolicy so that only the proxy can reach the web port of LLDAP:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: lldap-http-from-proxy-only
spec:
  podSelector:
    matchLabels:
      app: lldap # Adapt to the labels of your LLDAP pods.
  policyTypes: [Ingress]
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: auth # The proxy's namespace.
          podSelector:
            matchLabels:
              app: proxy # Adapt to the labels of your proxy pods.
      ports:
        - port: 17170
    # The policy denies everything else, so keep the LDAP port open.
    - ports:
        - port: 3890
```

This requires a network plugin that enforces NetworkPolicies.

If other pods use the web API directly (for instance, the
[bootstrap job](../example_configs/bootstrap/bootstrap.md#kubernetes-job)),
allow them as well. Since they are inside the pod CIDR, they can also log in
with the header, so only allow pods you trust.

The proxy should reach LLDAP through a ClusterIP service. Going through a
NodePort or a LoadBalancer can change the source address of the connection,
so LLDAP will reject the requests.

## With oauth2-proxy

Refer to the [oauth2-proxy docs](https://oauth2-proxy.github.io/oauth2-proxy/)
to set it up with your identity provider. oauth2-proxy can either forward
requests to LLDAP itself or answer auth subrequests from your reverse proxy
(Nginx, Caddy, Traefik, ...). Either way, on the LLDAP side:

- Put whichever one connects to LLDAP in `trusted_proxies`.
- Configure oauth2-proxy to use the claim holding the LLDAP username (usually
  "preferred_username") as the user, instead of the email. Then set
  `header_name` to the header oauth2-proxy sends the username in. When using a
  reverse proxy in front, configure it to copy that header into the request to
  LLDAP and overwrite any value sent by the client.
- Set `logout_url` to the sign-out page of oauth2-proxy. That only ends the
  oauth2-proxy session, so your identity provider may log the user right back
  in. Use the `rd` query parameter to also redirect to your identity provider's
  logout page, as explained in the
  [oauth2-proxy docs](https://oauth2-proxy.github.io/oauth2-proxy/features/endpoints#sign-out).

## Troubleshooting

If requests are rejected, the HTTP 401 response body contains the IP address
that LLDAP saw (in the web interface, check the `/auth/refresh` response in
your browser's developer tools). Compare it with your `trusted_proxies`. It's
often the address of a different network than the one you expected.

## Scripting

A script running from a trusted address can authenticate by sending the header
instead of a token. See the
[scripting docs](scripting.md#with-trusted-header-authentication) for details.
