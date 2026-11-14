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

| `check` field | For | Description |
| --- | --- | --- |
| `name` | All | Required. What it's called on charts and in alerts |
| `kind` | All | Required. `tcp`, `http`, `tls`, `dns` or `ping` |
| `target` | All | Required. `host:port` for tcp and tls, an address for http, and a host for dns and ping |
| `timeout_secs` | All | How long it gets, up to a minute |
| `interval_secs` | All | For a check an agent runs, how often it runs, up to a day. It runs with every sample without one, and never more often than samples are sent, as it's rounded up to whole samples. Between runs, each sample repeats its last result. A remote check's interval goes beside `check` instead |
| `method` | http | Defaults to `GET` |
| `body` | http | What to send, for methods like `POST` |
| `regex` | http | A regular expression the page has to match |
| `insecure` | http, tls | Measure a site whose certificate can't be verified, without counting that as down. Without it, an HTTP check never sends its request to a server that fails the certificate check |
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
