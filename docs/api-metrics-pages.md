# Metrics pages API

The [OpenMetrics](openmetrics.md) pages the server reads itself, for
[hosts without an agent](agentless-hosts.md). A page belongs to one host. Pages an
agent reads are part of its [config rules](api-config-rules.md) instead.

| Field | Description |
| --- | --- |
| `url` | Required. The page's address, starting `http://` or `https://`, with no username or password in it |
| `interval_secs` | Required. How often it's read, from 10 to 86400 |
| `names` | The metrics to keep, with `*` and `?` for anything. Leave it out for all of them |
| `enabled` | Defaults to `true` |
| `username` | For a page that asks who's reading. It needs one of the two below |
| `password` | The password itself. It can be set but is never given back |
| `password_env` | The server's environment variable that holds the password. Its name has to start with `MAXNINES_SECRET_` |

What comes back also has the page's `id`, its `host_id`, the `name` its series
start with, and `has_password`, which says whether a password is saved.

## List a host's metrics pages

`GET /api/v1/hosts/{id}/metrics-pages`

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/hosts/$HOST_ID/metrics-pages"
```

```json
[
  {
    "id": 1,
    "host_id": "5f0c1d6f2a8e4b7790d3c1a2b4e6f809",
    "name": "db.example.com:9187",
    "url": "https://db.example.com:9187/metrics",
    "names": ["pg_*"],
    "interval_secs": 60,
    "enabled": true,
    "username": "metrics",
    "has_password": false,
    "password_env": "MAXNINES_SECRET_ORDERS_DB"
  }
]
```

## Add a metrics page

`POST /api/v1/hosts/{id}/metrics-pages`

Only a host without an agent can have one, and any other gives `409`.

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://db.example.com:9187/metrics",
    "interval_secs": 60,
    "names": ["pg_*"],
    "username": "metrics",
    "password_env": "MAXNINES_SECRET_ORDERS_DB"
  }' \
  "$MAXNINES_URL/api/v1/hosts/$HOST_ID/metrics-pages"
```

```json
{ "id": 1 }
```

## Get a metrics page

`GET /api/v1/metrics-pages/{id}`

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/metrics-pages/1"
```

## Update a metrics page

`PUT /api/v1/metrics-pages/{id}`

Replaces the whole page, apart from its password: one that gives a `username` but
neither `password` nor `password_env` keeps the password it has. Leaving `username`
out removes the login.

```sh
curl -X PUT -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://db.example.com:9187/metrics",
    "interval_secs": 300,
    "username": "metrics"
  }' \
  "$MAXNINES_URL/api/v1/metrics-pages/1"
```

## Delete a metrics page

`DELETE /api/v1/metrics-pages/{id}`

What it reported so far is kept with its host.

```sh
curl -X DELETE -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/metrics-pages/1"
```
