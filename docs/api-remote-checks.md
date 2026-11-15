# Remote checks API

Checks the server runs itself, against remote sites. Each is about a host: a
[host without an agent](agentless-hosts.md), or the server itself. Its results and
alerts go under that host.

| Field | Description |
| --- | --- |
| `host_id` | The host it's about, which has to be one without an agent. Leave it out, or give `server`, for a check that isn't about any one host |
| `check` | Required. What to check, as below |
| `interval_secs` | Required. How often it runs |
| `enabled` | Defaults to `true` |
| `username` | For a check that [signs in](checks.md#signing-in): who as |
| `password` | Its password, which can be set but is never given back |
| `password_env` | Or the server's environment variable that holds it. Its name has to start with `MAXNINES_SECRET_` |
| `private_key` | For SSH instead of a password: a private key in OpenSSH's format, without a passphrase. It can be set but is never given back |
| `private_key_env` | Or the server's environment variable that holds it, named as `password_env` is |
| `sign_in` | How it signs in: `none`, `password` or `key`. Left out, it's worked out from the fields above |

What comes back has `sign_in`, `username`, `password_env` and `private_key_env`, and
`has_password` and `has_private_key`, which say whether one is saved. A change that
gives none of a password, its variable, a key or its variable keeps the one saved,
as long as `sign_in` says, or the fields given show, that it still signs in that way.

| `check` field | For | Description |
| --- | --- | --- |
| `name` | All | Required. What it's called on charts and in alerts. Two checks about the same host can't have the same one |
| `kind` | All | Required. `tcp`, `http`, `tls`, `dns`, `ping`, `postgres`, `mysql`, `redis`, `mongodb`, `ssh`, `smtp`, `imap` or `pop3` |
| `target` | All | Required. An address for http, a host for dns and ping, and `host:port` for the rest |
| `timeout_secs` | All | How long it gets, up to a minute |
| `interval_secs` | All | For a check an agent runs, how often it runs, up to a day. It runs with every sample without one, and never more often than samples are sent, as it's rounded up to whole samples. Between runs, each sample repeats its last result. A remote check's interval goes beside `check` instead |
| `method` | http | Defaults to `GET` |
| `body` | http | What to send, for methods like `POST` |
| `regex` | http | A regular expression the page has to match |
| `domain_expiry` | http | `false` stops it looking up when the site's [domain](checks.md#domain-expiry) expires, which it does otherwise |
| `insecure` | http, tls, postgres, mysql, redis, mongodb, smtp, imap, pop3 | Measure a server whose certificate can't be verified, without counting that as down. Without it, a check never sends its request, or a password, to a server that fails the certificate check |
| `database` | postgres, mongodb | For postgres, the database to sign in to, defaulting to `postgres`. For mongodb, the database the account was made in, defaulting to `admin` |
| `tls` | mysql, redis, mongodb, smtp, imap, pop3 | Connect over TLS from the start. PostgreSQL uses TLS whenever the server offers it, and mail checks without this upgrade with STARTTLS before signing in |
| `host_key` | ssh | The server's host key, as `ssh-keygen -l` prints it, such as `SHA256:Dfij…`. Any other key counts as down, and nothing is signed in with |
| `server` | dns | Ask this server instead of the system's resolver |
| `record` | dns | The record type to ask for, with `server`. Defaults to `A` |
| `count` | ping | How many packets to send. Defaults to 1 |

## List remote checks

`GET /api/v1/remote-checks`

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/remote-checks"
```

## Add a remote check

`POST /api/v1/remote-checks`

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "check": {"name": "Home page", "kind": "http", "target": "https://example.com"},
    "interval_secs": 60
  }' \
  "$MAXNINES_URL/api/v1/remote-checks"
```

```json
{ "id": 1 }
```

## Get a remote check

`GET /api/v1/remote-checks/{id}`

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/remote-checks/1"
```

```json
{
  "id": 1,
  "host_id": "server",
  "check": { "name": "Home page", "kind": "http", "target": "https://example.com" },
  "interval_secs": 60,
  "enabled": true
}
```

## Update a remote check

`PUT /api/v1/remote-checks/{id}`

Replaces the whole check.

```sh
curl -X PUT -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "check": {"name": "Home page", "kind": "http", "target": "https://example.com"},
    "interval_secs": 300
  }' \
  "$MAXNINES_URL/api/v1/remote-checks/1"
```

## Delete a remote check

`DELETE /api/v1/remote-checks/{id}`

```sh
curl -X DELETE -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/remote-checks/1"
```
