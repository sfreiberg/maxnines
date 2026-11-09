# HTTPS

Without HTTPS, passwords and agent data cross the network unencrypted, and Chrome won't
offer to install the app. Choose one of these in `server.hcl`:

| Choice | Use it when | In `server.hcl` |
| --- | --- | --- |
| No TLS | A proxy handles HTTPS, or it's a small trusted network | No `tls` block |
| Your own certificate | You already manage certificates, or use a private authority | `tls` block with files |
| Automatic certificates | The server can be reached from the internet | `tls` block with `acme` |

Everything stays on the one port in `listen`. There's no redirect from `http://` on that
port, as it only speaks HTTPS once TLS is on. Binding to port 443 usually needs extra
rights, which depends on how you run the server.

## No TLS

Leave the `tls` block out. Behind a proxy that handles HTTPS, set `public_url` to the
address agents use, and list the proxy so client addresses are read correctly.
Sign-in attempts are limited per client address, so without `trusted_proxies` every
browser behind the proxy shares one allowance:

```hcl
listen          = "127.0.0.1:9000"
public_url      = "wss://maxnines.example.com/ws"
trusted_proxies = ["127.0.0.1"]
```

## Your own certificate

```hcl
listen     = "0.0.0.0:443"
public_url = "wss://maxnines.example.com/ws"

tls {
  certificate_file = "/etc/maxnines/server.crt"
  key_file         = "/etc/maxnines/server.key"

  # Only for a certificate from a private authority.
  # ca_file = "/etc/maxnines/ca.pem"
}
```

| Setting | Required | Meaning |
| --- | --- | --- |
| `certificate_file` | Yes | The certificate in PEM format, followed by any intermediates |
| `key_file` | Yes | Its private key in PEM format, without a passphrase |
| `ca_file` | For a private authority | Who signed it, for this server's own command line tools |

- `public_url` has to start with `wss://`, and its name has to be on the certificate.
- Replace the files to renew, and the server picks them up within an hour with no
  restart. If a new file can't be read, the old certificate stays in use and it's logged.
- Keep the key readable only by the account running the server.

## Automatic certificates

```hcl
listen     = "0.0.0.0:443"
public_url = "wss://maxnines.example.com/ws"

tls {
  acme {
    domains   = ["maxnines.example.com"]
    email     = "you@example.com"
    cache_dir = "/var/lib/maxnines/acme"
  }
}
```

| Setting | Required | Meaning |
| --- | --- | --- |
| `domains` | Yes | The names to get a certificate for. Each has to point at this server |
| `cache_dir` | Yes | Keeps the certificate and account key. Created if needed |
| `email` | No | Who the certificate service can contact |
| `directory` | No | The ACME service. Defaults to Let's Encrypt |
| `ca_file` | No | Who to trust for a private ACME service |

- **Port 443 has to reach this server from the internet.** Let's Encrypt proves you
  control the name by connecting to it there, on the same port as everything else, so
  port 80 isn't needed. A firewall or router can forward 443 to another `listen` port.
- The first start takes a moment while the certificate is issued, and renewal is
  automatic.
- `cache_dir` has to survive restarts and stay private, because it holds the account key
  and Let's Encrypt limits how many certificates it will issue. Keep it out of synced
  folders.
- While setting up, use the staging service so mistakes don't use up those limits. Its
  certificates aren't trusted, so switch back and clear `cache_dir` when it works:

  ```hcl
  directory = "https://acme-staging-v02.api.letsencrypt.org/directory"
  ```

## Agents

Agents check the server's certificate. Point them at the `wss://` address:

```hcl
server {
  url = "wss://maxnines.example.com/ws"
}
```

For a certificate from a private authority, tell them who to trust with
`ca_file = "/etc/maxnines/ca.pem"` in that block. An agent that doesn't trust the
certificate logs `invalid peer certificate` and keeps trying.

## Command line tools

`maxnines-server users` and `api-keys` work on the main database directly.
`maxnines-server agents` talks to the running server, as that's where the agent list
lives, with the API key in `MAXNINES_API_KEY`. With a `tls` block it connects to
`public_url` and checks the certificate like anything else. That name has to work from
the server itself. If they report `invalid peer certificate: UnknownIssuer`, the
certificate is from a private authority and the `tls` block needs its `ca_file`.

## Checking it works

```sh
curl https://maxnines.example.com/health
```
