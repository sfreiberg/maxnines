# Remote checks API

Checks the server runs itself, against remote sites. Each is about a
[host without an agent](agentless-hosts.md), and its results and alerts go under
that host. A check added without a host gets a new host of its own.

| Field | Description |
| --- | --- |
| `host_id` | The host it's about, which has to be one without an agent. Leave it out, or give `null`, when adding a check, and a new host is made for it, as **Add a host** makes one. Left out when changing a check, the check stays on its host |
| `hostname` | When adding a check without `host_id`: what the new host is called. Left out, it's named after the host the check reaches, as [Checks](checks.md#a-host-for-each-check) describes. Refused with `host_id` and when changing a check |
| `check` | Required. What to check, as below |
| `interval_secs` | Required. How often it runs, from 10 seconds to a day. For a heartbeat, how often it should be pinged, from a minute to 31 days |
| `grace_secs` | For a heartbeat: how much later than `interval_secs` a ping can come before it's down, up to 7 days. Left out, none |
| `enabled` | Defaults to `true` |
| `read_stats` | For a PostgreSQL, MySQL, MongoDB or ClickHouse check: `true` also reads the database's health and replication, saved under the check's host, as described in [database stats](database-stats.md#hosts-without-an-agent) |
| `extras` | With `read_stats`, what else to read, such as `["sizes"]`. Not for PostgreSQL, whose built-in template's queries are turned on on its page instead |
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

It also has `latest`, how the check last went: `up`, `ran_at`, when it ran, and
`error`, why it was down. It's `null` until the check has run since the server
started, and a paused check keeps the result from before it was paused.

| `check` field | For | Description |
| --- | --- | --- |
| `name` | All | Required. What it's called on charts and in alerts. Two checks about the same host can't have the same one, which for checks the server runs is ignoring case |
| `kind` | All | Required. `tcp`, `http`, `tls`, `dns`, `ping`, `postgres`, `mysql`, `redis`, `memcached`, `mongodb`, `clickhouse`, `ssh`, `smtp`, `imap`, `pop3`, `ftp` or `heartbeat` |
| `target` | All | Required. An address for http, a host for dns and ping, and `host:port` for the rest, which for clickhouse is its HTTP port. A heartbeat has none, so it's `""` |
| `timeout_secs` | All but heartbeat | How long it gets, up to a minute |
| `interval_secs` | All | For a check an agent runs, how often it runs, up to a day. It runs with every sample without one, and never more often than samples are sent, as it's rounded up to whole samples. Between runs, each sample repeats its last result. A remote check's interval goes beside `check` instead |
| `method` | http | Defaults to `GET` |
| `body` | http | What to send, for methods like `POST` |
| `regex` | http | A regular expression the page has to match |
| `domain_expiry` | http | `false` stops it looking up when the site's [domain](checks.md#domain-expiry) expires, which it does otherwise |
| `insecure` | http, tls, postgres, mysql, redis, memcached, mongodb, clickhouse, smtp, imap, pop3, ftp | Measure a server whose certificate can't be verified, without counting that as down. Without it, a check never sends its request, or a password, to a server that fails the certificate check |
| `database` | postgres, mongodb | For postgres, the database to sign in to, defaulting to `postgres`. For mongodb, the database the account was made in, defaulting to `admin` |
| `tls` | mysql, redis, memcached, mongodb, clickhouse, smtp, imap, pop3, ftp | Connect over TLS from the start, which for clickhouse means HTTPS. PostgreSQL uses TLS whenever the server offers it, mail checks without this upgrade with STARTTLS before signing in, and ftp checks with AUTH TLS |
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

It answers with the check's `id` and the `host_id` of the host it's about, here a
new one called `example.com`:

```json
{ "id": 1, "host_id": "5f0c1d6f2a8e4b7790d3c1a2b4e6f809" }
```

Two checks added without a host get two hosts, even with the same name, as hosts
are never matched by name. To add another check to the same host, give its
`host_id`.

A [heartbeat](checks.md#heartbeats) waits to be pinged rather than reaching
anything, and a new host for one is named after the check:

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "check": {"name": "Nightly backup", "kind": "heartbeat", "target": ""},
    "interval_secs": 86400,
    "grace_secs": 3600
  }' \
  "$MAXNINES_URL/api/v1/remote-checks"
```

What comes back also has `ping_url`, the address the work pings. It's only given
here and when a new one is made, as reading a check needs less than changing one:

```json
{
  "id": 2,
  "host_id": "9b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e",
  "ping_url": "https://monitor.example.com/ping/0f3c9a6e5b1d4c7a8e2f6b9d1a3c5e7f"
}
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
  "host_id": "5f0c1d6f2a8e4b7790d3c1a2b4e6f809",
  "check": { "name": "Home page", "kind": "http", "target": "https://example.com" },
  "interval_secs": 60,
  "enabled": true,
  "read_stats": false,
  "sign_in": "none",
  "has_password": false,
  "has_private_key": false,
  "latest": { "up": false, "ran_at": "2026-11-06T04:44:39.545Z", "error": "connection refused" }
}
```

## Update a remote check

`PUT /api/v1/remote-checks/{id}`

Replaces the whole check. Without `host_id` it stays on its host, and with one it
moves there, keeping none of its history on the host it left.

```sh
curl -X PUT -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "check": {"name": "Home page", "kind": "http", "target": "https://example.com"},
    "interval_secs": 300
  }' \
  "$MAXNINES_URL/api/v1/remote-checks/1"
```

## Give a heartbeat a new address

`POST /api/v1/remote-checks/{id}/ping-address`

Makes a new address for a heartbeat to be pinged at, and stops the old one working
at once. It answers with the new `ping_url`, or `404` for a check that isn't a
heartbeat. The audit log records that it was done, but never the address.

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/remote-checks/2/ping-address"
```

```json
{ "ping_url": "https://monitor.example.com/ping/7d2e4b6a8c0f1e3d5b7a9c2e4f6a8b0d" }
```

## Delete a remote check

`DELETE /api/v1/remote-checks/{id}`

Its host stays, with everything the check found. Deleting the host deletes its
checks with it.

```sh
curl -X DELETE -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/remote-checks/1"
```
