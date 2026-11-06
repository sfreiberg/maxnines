# MaxNines API

Everything the web pages can see and do is available as JSON. The API shares the
server's one port, under `/api/v1`.

## Getting started

Make a key, then send it as a bearer token with every request:

```sh
export MAXNINES_URL=http://localhost:9000
export MAXNINES_API_KEY=$(maxnines-server api-keys create "My script" --expires-in 30d)

curl -H "Authorization: Bearer $MAXNINES_API_KEY" "$MAXNINES_URL/api/v1/agents"
```

The examples below use those two variables. Where one needs an agent, it uses
`$AGENT_ID`, which you can set like this:

```sh
export AGENT_ID=$(curl -s -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/agents" | jq -r '.[0].id')
```

## How the API works

**Authentication.** Every request needs an `Authorization: Bearer` header holding an
API key. A key can do everything the API can, so give each tool its own. Without a
valid key, the answer is `401`. The token from `maxnines-server admin-token` also
works, but it can't be revoked, so it's better kept for the server's own commands.

**Encryption.** The server doesn't handle TLS itself. Anywhere beyond one machine,
put it behind a proxy that does, so that keys aren't sent in the clear.

**Requests and responses.** Requests with a body are JSON, with
`Content-Type: application/json`. Responses are JSON unless noted.

**Times** are milliseconds since the Unix epoch, in fields ending in `_ms`.

**Versions.** A change that would break a client goes in a new version, such as
`/api/v2`. Adding a field isn't a breaking change, so ignore fields you don't know.

**Lists** return everything at once, except where noted. The API isn't rate limited.

### Status codes

| Status | Meaning |
| --- | --- |
| `200` | It worked, and the answer is in the body |
| `201` | It was created, and the body holds its `id` |
| `204` | It worked, and there's nothing to return |
| `400` | The request couldn't be understood, such as a filter that can't be read |
| `401` | The key is missing, wrong, revoked or expired |
| `404` | There's nothing at that address, or no such item |
| `422` | The request was understood but refused, such as an invalid rule |
| `500` | Something went wrong on the server |
| `502` | A test notification couldn't be delivered |

Where there's an explanation, it's in an `error` field:

```json
{ "error": "A key needs a name." }
```

## Agents

An agent is a machine reporting to this server. An agent's `state` is `pending`,
`approved` or `revoked`. Its `health` is `critical`, `warning`, `offline` or `online`,
and problems outrank being online.

### List agents

`GET /api/v1/agents`

| Parameter | Description |
| --- | --- |
| `q` | Only agents matching this [filter](#filters) |

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/agents?q=os%3Dlinux"
```

```json
[
  {
    "id": "22ad9264b6eb708ffdbedcd5cc073e5c",
    "public_key": "912e3122b606a9c2776e065d87dc31eefacde1d7dcad18e1cf88349eb32db35f",
    "host": "web-1",
    "state": "approved",
    "decided_by": "admin",
    "first_seen_ms": 1793940264215,
    "decided_at_ms": 1793940265752,
    "online": true,
    "health": "online",
    "last_seen_ms": 1793940282225
  }
]
```

### Get an agent

`GET /api/v1/agents/{id}`

Gives one agent, as above.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/agents/$AGENT_ID"
```

### Approve an agent

`POST /api/v1/agents/{id}/approve`

Lets an agent connect, and gives back the agent's record.

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/agents/$AGENT_ID/approve"
```

### Revoke an agent

`POST /api/v1/agents/{id}/revoke`

Stops an agent connecting and drops it if it's connected, and gives back the agent's
record. This is the same for rejecting a waiting agent. The agent can't be approved
by a rule afterwards.

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/agents/REVOKED_AGENT_ID/revoke"
```

### Get an agent's facts

`GET /api/v1/agents/{id}/facts`

`trusted` is what the server knows for itself. `reported` is only what the agent
claims, so don't use it for anything to do with security.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/agents/$AGENT_ID/facts"
```

```json
{
  "trusted": {
    "agent_id": "22ad9264b6eb708ffdbedcd5cc073e5c",
    "state": "approved",
    "decided_by": "admin",
    "online": true,
    "source_address": "10.0.0.12"
  },
  "reported": {
    "os": { "family": "linux", "name": "Ubuntu", "version": "24.04" },
    "cpu": { "logical_cores": 8, "model": "AMD EPYC" },
    "custom": { "role": "web", "tags": ["eu", "prod"] }
  }
}
```

### Get the history of an agent's facts

`GET /api/v1/agents/{id}/facts/history`

Every value each fact has had, oldest first. `valid_to_ms` is empty for current values.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/agents/$AGENT_ID/facts/history"
```

```json
[
  {
    "name": "os.version",
    "value": "24.04",
    "valid_from_ms": 1793940267223,
    "valid_to_ms": null
  }
]
```

### Get an agent's config

`GET /api/v1/agents/{id}/config`

`desired` is what the [config rules](#config-rules) come to for this agent. `reported`
is what it last said it's running, with `error` set if it refused the config.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/agents/$AGENT_ID/config"
```

```json
{
  "desired": {
    "version": "3810e917a2f5c7e9",
    "config": {
      "interval_secs": 15,
      "facts_interval_secs": 3600,
      "collectors": { "cpu": { "enabled": true } }
    },
    "matched_rules": ["Default"],
    "skipped_collectors": []
  },
  "reported": {
    "version": "3810e917a2f5c7e9",
    "error": null,
    "reported_at_ms": 1793940267263
  }
}
```

### Get an agent's metric

`GET /api/v1/agents/{id}/metrics/{metric}`

One metric from the [catalog](#list-metrics) over a period of time. The server
chooses `step_ms` to suit the period. A metric can have several series, such as one
for each disk, and `hidden` says how many were left out.

| Parameter | Description |
| --- | --- |
| `from_ms` | The start. Defaults to an hour before `to_ms` |
| `to_ms` | The end. Defaults to now |

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/agents/$AGENT_ID/metrics/cpu.usage"
```

```json
{
  "metric": "cpu.usage",
  "unit": "percent",
  "from_ms": 1793936685969,
  "to_ms": 1793940285969,
  "step_ms": 15000,
  "series": [
    {
      "name": "CPU",
      "points": [
        { "time_ms": 1793940270000, "avg": 19.4, "min": 19.4, "max": 19.4 }
      ]
    }
  ],
  "hidden": 0
}
```

## Filters

Filters find hosts the same way as the box on the agents page. Separate terms with
spaces, and every term has to match. Remember to URL-encode them, so `os=linux`
becomes `os%3Dlinux`. With curl, `-G --data-urlencode` does this for you.

| Filter | Finds |
| --- | --- |
| `web` | Host names containing "web" |
| `hostname=web*` | Host names starting with "web" |
| `os=linux` | That operating system family. `os` is short for `os.family` |
| `os!=windows` | Everything else, including hosts that haven't said |
| `cpu.logical_cores=8` | Any fact by its full name |
| `custom.tags=eu` | A list containing that value |
| `os.long_version="Ubuntu 24*"` | A value with spaces, in double quotes |
| `os=linux custom.role=web` | Hosts matching both |

Values ignore case, and can use `*` for anything and `?` for one character. Facts from
an agent's own config are under `custom.`, so `role` in its config is `custom.role`.

```sh
curl -G -H "Authorization: Bearer $MAXNINES_API_KEY" \
  --data-urlencode 'q=os=linux hostname=web*' \
  "$MAXNINES_URL/api/v1/agents"
```

A filter that can't be read gets a `400` saying why.

### Get filter suggestions

`GET /api/v1/agents/filter-options`

What the filter box offers for the word being typed: fact names, or values once there's
an `=`. Put `text` in place of the word.

| Parameter | Description |
| --- | --- |
| `term` | The word being typed |

```sh
curl -G -H "Authorization: Bearer $MAXNINES_API_KEY" \
  --data-urlencode 'term=os=' \
  "$MAXNINES_URL/api/v1/agents/filter-options"
```

```json
[
  { "text": "os=linux", "label": "linux" },
  { "text": "os=macos", "label": "macos" }
]
```

## Metrics

### List metrics

`GET /api/v1/metrics`

Everything that can be charted or alerted on, for use in `{metric}` above and in
[alert rules](#alert-rules).

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" "$MAXNINES_URL/api/v1/metrics"
```

```json
[
  {
    "name": "cpu.usage",
    "title": "CPU usage",
    "unit": "percent",
    "collector": "cpu"
  }
]
```

### Get current values

`GET /api/v1/metrics/current`

The latest headline numbers from every agent, by agent ID. Agents with nothing in the
last 5 minutes are left out.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/metrics/current"
```

```json
{
  "22ad9264b6eb708ffdbedcd5cc073e5c": {
    "time_ms": 1793940279545,
    "cpu_percent": 19.4,
    "memory_percent": 75.6,
    "disk_percent": 84.5,
    "disk_mount_point": "/"
  }
}
```

## Config rules

Config rules decide what each agent monitors. Every rule matching an agent applies,
lowest priority first, so higher priorities win.

| Field | Description |
| --- | --- |
| `name` | Required |
| `priority` | Required. Higher priorities apply later |
| `condition` | A [CEL](https://cel.dev) expression over `facts`. Empty matches every agent |
| `enabled` | Defaults to `true` |
| `settings` | Required. What to apply, as below |

| Setting | Description |
| --- | --- |
| `interval_secs` | How often agents send a sample |
| `facts_interval_secs` | How often agents report their facts |
| `collectors` | What to collect, by name, each with `enabled` and the options below |

| Collector option | For | Description |
| --- | --- | --- |
| `mount_points` | `disk` | Only these disks |
| `names` | `processes`, `services`, `custom` | What to watch. Custom metrics must be defined in the agent's own config |
| `paths` | `files` | The files and folders to watch |
| `checks` | `checks` | What to try reaching, as in [remote checks](#remote-checks) |

The collectors are `checks`, `cpu`, `custom`, `disk`, `files`, `host`, `memory`,
`network`, `processes`, `sensors`, `services` and `system`.

### List config rules

`GET /api/v1/rules`

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" "$MAXNINES_URL/api/v1/rules"
```

### Get a config rule

`GET /api/v1/rules/{id}`

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" "$MAXNINES_URL/api/v1/rules/1"
```

```json
{
  "id": 1,
  "name": "Default",
  "priority": 0,
  "condition": null,
  "enabled": true,
  "settings": {
    "interval_secs": 15,
    "facts_interval_secs": 3600,
    "collectors": { "cpu": { "enabled": true } }
  }
}
```

### Preview a config rule

`POST /api/v1/rules/preview`

Shows what saving a rule would do, without saving it. Takes the same body as creating
one, with `?id=` to try it in place of a saved rule.

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "Slower", "priority": 10, "settings": {"interval_secs": 60}}' \
  "$MAXNINES_URL/api/v1/rules/preview"
```

```json
{
  "enabled": true,
  "total": 1,
  "matching": 1,
  "changing": 1,
  "agents": [
    {
      "host": "web-1",
      "online": true,
      "matches": true,
      "changes": ["Sample interval: 15s → 60s"],
      "note": null
    }
  ],
  "hidden": 0
}
```

### Create a config rule

`POST /api/v1/rules`

Agents get the change straight away. Gives back the rule's `id`.

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Slower on Linux",
    "priority": 10,
    "condition": "facts.os.family == \"linux\"",
    "settings": {"interval_secs": 60}
  }' \
  "$MAXNINES_URL/api/v1/rules"
```

```json
{ "id": 2 }
```

### Update a config rule

`PUT /api/v1/rules/{id}`

Replaces the whole rule.

```sh
curl -X PUT -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Slower on Linux",
    "priority": 10,
    "condition": "facts.os.family == \"linux\"",
    "settings": {"interval_secs": 30}
  }' \
  "$MAXNINES_URL/api/v1/rules/2"
```

### Delete a config rule

`DELETE /api/v1/rules/{id}`

```sh
curl -X DELETE -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/rules/2"
```

## Alerts

### List alerts

`GET /api/v1/alerts`

Everything firing now, and the latest 200 that have ended.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" "$MAXNINES_URL/api/v1/alerts"
```

```json
{
  "open": [
    {
      "id": 7,
      "rule_id": 1,
      "rule_name": "High CPU",
      "severity": "warning",
      "agent_id": "22ad9264b6eb708ffdbedcd5cc073e5c",
      "host": "web-1",
      "series": "",
      "value": 97.2,
      "summary": "High CPU on web-1",
      "started_ms": 1793940279545,
      "resolved_ms": null,
      "resolve_reason": null
    }
  ],
  "resolved": []
}
```

## Alert rules

| Field | Description |
| --- | --- |
| `name` | Required |
| `kind` | Required. `metric` or `offline` |
| `metric` | For metric rules, a name from the [catalog](#list-metrics) |
| `series` | Limits a metric rule to matching series, with `*` and `?` wildcards |
| `comparison` | For metric rules, `above` or `below` |
| `threshold` | For metric rules, the value to compare with |
| `for_secs` | Required. How long a problem lasts before firing, and how long it has to stay gone before resolving |
| `severity` | Required. `warning` or `critical` |
| `condition` | A CEL expression limiting which agents this covers |
| `enabled` | Defaults to `true` |
| `channels` | IDs of the [channels](#notification-channels) to tell. With none, an alert only shows in the web interface |

### List alert rules

`GET /api/v1/alert-rules`

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" "$MAXNINES_URL/api/v1/alert-rules"
```

### Create an alert rule

`POST /api/v1/alert-rules`

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "High CPU",
    "kind": "metric",
    "metric": "cpu.usage",
    "comparison": "above",
    "threshold": 90,
    "for_secs": 300,
    "severity": "warning"
  }' \
  "$MAXNINES_URL/api/v1/alert-rules"
```

```json
{ "id": 1 }
```

### Get an alert rule

`GET /api/v1/alert-rules/{id}`

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/alert-rules/1"
```

```json
{
  "id": 1,
  "name": "High CPU",
  "kind": "metric",
  "metric": "cpu.usage",
  "series": null,
  "comparison": "above",
  "threshold": 90.0,
  "for_secs": 300,
  "severity": "warning",
  "condition": null,
  "enabled": true,
  "channels": []
}
```

### Update an alert rule

`PUT /api/v1/alert-rules/{id}`

Replaces the whole rule.

```sh
curl -X PUT -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "High CPU",
    "kind": "metric",
    "metric": "cpu.usage",
    "comparison": "above",
    "threshold": 95,
    "for_secs": 300,
    "severity": "critical"
  }' \
  "$MAXNINES_URL/api/v1/alert-rules/1"
```

### Delete an alert rule

`DELETE /api/v1/alert-rules/{id}`

```sh
curl -X DELETE -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/alert-rules/1"
```

## Notification channels

Where alerts go. Webhook addresses and Slack tokens can be set but never read back, so
`target_preview` only shows enough to recognize a channel.

| Field | Description |
| --- | --- |
| `name` | Required |
| `kind` | Required. `webhook`, `email`, `discord` or `slack` |
| `target` | Required. A webhook's address, email addresses separated by commas, or a Slack channel |
| `credential` | Slack's bot token |

### List notification channels

`GET /api/v1/notification-channels`

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/notification-channels"
```

### Create a notification channel

`POST /api/v1/notification-channels`

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "Ops", "kind": "webhook", "target": "https://hooks.example.com/abc"}' \
  "$MAXNINES_URL/api/v1/notification-channels"
```

```json
{ "id": 1 }
```

### Get a notification channel

`GET /api/v1/notification-channels/{id}`

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/notification-channels/1"
```

```json
{
  "id": 1,
  "name": "Ops",
  "kind": "webhook",
  "target_preview": "https://hooks.example.com/…"
}
```

### Update a notification channel

`PUT /api/v1/notification-channels/{id}`

Replaces the whole channel, including its target and credential.

```sh
curl -X PUT -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "On call", "kind": "webhook", "target": "https://hooks.example.com/abc"}' \
  "$MAXNINES_URL/api/v1/notification-channels/1"
```

### Test a notification channel

`POST /api/v1/notification-channels/{id}/test`

Sends a test notification. Gives `204` if it was delivered, or `502` with an `error`.

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/notification-channels/1/test"
```

### Delete a notification channel

`DELETE /api/v1/notification-channels/{id}`

```sh
curl -X DELETE -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/notification-channels/1"
```

## Remote checks

Checks the server runs itself, against remote sites.

| Field | Description |
| --- | --- |
| `check` | Required. What to check, as below |
| `interval_secs` | Required. How often it runs |
| `enabled` | Defaults to `true` |

| `check` field | For | Description |
| --- | --- | --- |
| `name` | All | Required. What it's called on charts and in alerts |
| `kind` | All | Required. `tcp`, `http`, `tls`, `dns` or `ping` |
| `target` | All | Required. `host:port` for tcp and tls, an address for http, and a host for dns and ping |
| `timeout_secs` | All | How long it gets, up to a minute |
| `method` | http | Defaults to `GET` |
| `body` | http | What to send, for methods like `POST` |
| `regex` | http | A regular expression the page has to match |
| `insecure` | http, tls | Measure a site whose certificate can't be verified, without counting that as down |
| `server` | dns | Ask this server instead of the system's resolver |
| `record` | dns | The record type to ask for, with `server`. Defaults to `A` |
| `count` | ping | How many packets to send. Defaults to 1 |

### List remote checks

`GET /api/v1/remote-checks`

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/remote-checks"
```

### Create a remote check

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

### Get a remote check

`GET /api/v1/remote-checks/{id}`

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/remote-checks/1"
```

```json
{
  "id": 1,
  "check": { "name": "Home page", "kind": "http", "target": "https://example.com" },
  "interval_secs": 60,
  "enabled": true
}
```

### Update a remote check

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

### Delete a remote check

`DELETE /api/v1/remote-checks/{id}`

```sh
curl -X DELETE -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/remote-checks/1"
```

## Server

### Get server status

`GET /api/v1/server`

How the server is doing, including its CPU, memory, databases and activity. Each part
is read on its own, so one that's unavailable is empty and the rest still answer.
`cpu_percent` is a share of the whole machine, and empty on the first request after a
start. `memory_bytes` can read high on macOS, which counts memory that's been freed
until something else needs it.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" "$MAXNINES_URL/api/v1/server"
```

```json
{
  "version": "0.1.0",
  "commit": "770de39",
  "built_at": "2026-11-06T04:42:04.427542000Z",
  "started_ms": 1793940264095,
  "uptime_secs": 22,
  "os": "Ubuntu 24.04",
  "process": {
    "memory_bytes": 53641216,
    "cpu_percent": 5.2,
    "open_files": 17,
    "machine_memory_total_bytes": 51539607552,
    "machine_memory_used_bytes": 39138967552,
    "cores": 12
  },
  "disk": {
    "mount_point": "/",
    "total_bytes": 994662584320,
    "available_bytes": 266447943341
  },
  "metrics": {
    "engine": "DuckDB",
    "size": "417.5 MiB",
    "write_ahead_log": "9.9 KiB",
    "memory_used": "718.0 KiB",
    "memory_limit": "953.6 MiB",
    "collectors": [
      {
        "name": "cpu",
        "rows": 295967,
        "rows_last_hour": 295967,
        "oldest_ms": 1793936249223,
        "newest_ms": 1793937138143
      }
    ]
  },
  "database": {
    "engine": "SQLite",
    "size_bytes": 28397568,
    "response_ms": 0.03,
    "latest_migration": "m20261105_000008_create_api_keys",
    "tables": [{ "name": "Agents", "rows": 5001 }],
    "notifications_waiting": 0,
    "notifications_failed": 0
  },
  "activity": {
    "agents_online": 5000,
    "agents_approved": 5000,
    "agents_waiting": 0,
    "samples_written": 119757,
    "samples_failed": 0,
    "samples_queued": 0,
    "queue_capacity": 1024,
    "alerts_firing": 0,
    "last_alert_pass_ms": 1793937144561
  }
}
```

### The server's own history

The server records its own numbers every 15 seconds as the built-in agent `server`,
so they work like any agent's metrics, including in alert rules. Read them with the
same route, using metrics such as `server.memory`, `server.cpu`, `server.samples`,
`server.write_queue`, `server.agents`, `server.alerts`, `server.database_size` and
`server.open_files`:

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/agents/server/metrics/server.memory"
```

## API keys

Keys can also be managed on the Settings page, and with `maxnines-server api-keys`.
Only a hash of each key is kept, so a key can only be seen when it's created. `hint` is
the start of it, to tell keys apart.

### List API keys

`GET /api/v1/api-keys`

Every key, newest first, including revoked and expired ones.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" "$MAXNINES_URL/api/v1/api-keys"
```

```json
[
  {
    "id": 1,
    "name": "My script",
    "hint": "mxn_9689a740",
    "created_ms": 1793940265767,
    "expires_ms": 1793943865767,
    "last_used_ms": 1793940285797,
    "revoked_ms": null
  }
]
```

`last_used_ms` is accurate to about a minute.

### Create an API key

`POST /api/v1/api-keys`

| Field | Description |
| --- | --- |
| `name` | Required. What the key is for, up to 100 characters |
| `expires_in_secs` | How long it lasts. Leave it out for a key that never expires |

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "Deploy job", "expires_in_secs": 3600}' \
  "$MAXNINES_URL/api/v1/api-keys"
```

```json
{
  "id": 2,
  "name": "Deploy job",
  "hint": "mxn_6ffd6467",
  "key": "mxn_6ffd6467588f1ad1cbdca9b9961ff4be70e64ef4ff330c805ee3015463c00357",
  "created_ms": 1793940286623,
  "expires_ms": 1793943886623,
  "last_used_ms": null,
  "revoked_ms": null
}
```

Save `key` now, because this is the only time it's shown.

### Revoke an API key

`DELETE /api/v1/api-keys/{id}`

Stops a key working straight away. It stays in the list, to show what existed.

```sh
curl -X DELETE -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/api-keys/2"
```

## Users

Everyone who can sign in to the web pages. Nobody can sign up, so people are only
added here, on the Settings page, or with `maxnines-server users`. Passwords can't
be read or set through the API: someone new gets a link to set their own.

### List users

`GET /api/v1/users`

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" "$MAXNINES_URL/api/v1/users"
```

```json
[
  {
    "id": 1,
    "email": "sam@example.com",
    "name": "Sam",
    "theme": "carbon",
    "has_password": true,
    "created_ms": 1793977895109,
    "last_sign_in_ms": 1793978000000,
    "disabled_ms": null
  }
]
```

### Add a user

`POST /api/v1/users`

The answer holds a link for them to set a password. It works once, lasts 7 days and
can't be seen again, so pass it on.

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"email": "alex@example.com", "name": "Alex"}' \
  "$MAXNINES_URL/api/v1/users"
```

```json
{
  "user": {
    "id": 2,
    "email": "alex@example.com",
    "name": "Alex",
    "theme": "carbon",
    "has_password": false,
    "created_ms": 1793977895109,
    "last_sign_in_ms": null,
    "disabled_ms": null
  },
  "setup_url": "http://localhost:9000/setup/8f3a…"
}
```

An address that's already in use gives `409`.

### Get a user

`GET /api/v1/users/{id}`

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" "$MAXNINES_URL/api/v1/users/2"
```

### Change a user's theme

`PUT /api/v1/users/{id}`

`theme` can be `carbon`, `midnight`, `dusk`, `paper`, `contrast` or `system`.

```sh
curl -X PUT -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"theme": "paper"}' \
  "$MAXNINES_URL/api/v1/users/2"
```

### Make a new setup link

`POST /api/v1/users/{id}/setup-link`

This is how a forgotten password is reset. It replaces any earlier link, and their
current password keeps working until the new link is used.

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/users/2/setup-link"
```

```json
{ "setup_url": "http://localhost:9000/setup/2c91…" }
```

### Enable a user

`POST /api/v1/users/{id}/enable`

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/users/2/enable"
```

### Disable a user

`POST /api/v1/users/{id}/disable`

This stops them signing in and signs them out straight away. Disabling the last
enabled user gives `409`, so someone can always sign in.

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/users/2/disable"
```

### Delete a user

`DELETE /api/v1/users/{id}`

Only a disabled user can be deleted. Anyone else gives `409`.

```sh
curl -X DELETE -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/users/2"
```
