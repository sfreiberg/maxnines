# MaxNines API

Everything the web pages can see and do is available as JSON. The API shares the
server's one port, under `/api/v1`.

## Getting started

Make a key, then send it as a bearer token with every request:

```sh
export MAXNINES_URL=http://localhost:9000
export MAXNINES_API_KEY=$(maxnines-server api-keys create "My script" --user you@example.com --expires-in 30d)

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
API key. Each key belongs to a user and acts as them: what it does is recorded in the
[audit log](audit-log.md) as that person, via the key, and it stops working while
they're disabled. Give each tool its own key. Without a valid key, the answer is
`401`.

**Roles.** A key has a [role](users.md#roles), its owner's or lower, and can do
what that role can: reading needs a viewer, acknowledging and silencing a responder,
changing the setup an editor, and users, the audit log and deleting agents an admin. Anything else gives `403`. Keys are made on the Settings page, through this API, or with
`maxnines-server api-keys create --user <email>`, which writes to the main database
directly, so it works while the server is stopped. For a script that isn't anyone's,
add a user for it, such as `ci@example.com`, which never needs a password.

**Encryption.** Use the server's own TLS, either your certificates or automatic ones
through ACME, or put it behind a proxy that terminates TLS. Anywhere beyond one
machine, keys shouldn't cross the network in the clear.

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
| `401` | The key is missing, wrong, revoked or expired, or its owner is disabled |
| `403` | The key's role doesn't allow it. The `error` says which role it needs |
| `404` | There's nothing at that address, or no such item |
| `409` | It clashes with what's there, such as a user with that email already, or disabling the last admin |
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

### Delete an agent

`DELETE /api/v1/agents/{id}`

Deletes a revoked agent with all its metrics, facts and alerts, and its place on the
map if it has one of its own. It can't be undone. An agent that isn't revoked gives
`409`, so it always takes two steps.

If the machine still runs the agent, it comes back as a new agent waiting to be
approved, and a rule can approve it like any other.

```sh
curl -X DELETE -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/agents/REVOKED_AGENT_ID"
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
| `id=3f2a1c9d*` | The agent whose ID starts like that, as names needn't be unique |
| `os=linux` | That operating system family. `os` is short for `os.family` |
| `networking.addresses=10.0.*` | Any of the machine's IP addresses. Loopback and link-local addresses aren't listed |
| `networking.fqdn=*.leeds.example.com` | The machine's fully qualified name, as its resolver gives it. `networking.hostname` is the short name and `networking.domain` the rest |
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
| `mount_points` | `disk` | Only these disks, even ones left out by default, like disk images |
| `names` | `processes`, `services`, `custom` | What to watch. Custom metrics must be defined in the agent's own config |
| `paths` | `files` | The files and folders to watch |
| `checks` | `checks` | What to try reaching, as in [remote checks](#remote-checks) |
| `urls` | `apache`, `nginx`, `php_fpm` | The status pages to read. Leave it out for the usual page on the machine itself |

The collectors are `apache`, `checks`, `containers`, `cpu`, `custom`, `disk`, `files`, `host`,
`memory`, `network`, `nginx`, `php_fpm`, `processes`, `sensors`, `services` and
`system`.

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
      "resolve_reason": null,
      "acknowledged_by": null,
      "acknowledged_ms": null,
      "silenced_by": null,
      "maintenance_window": null
    }
  ],
  "resolved": []
}
```

`silenced_by` is the ID of the silence keeping an open alert's notifications back, and
`maintenance_window` is the ID of the [window](#maintenance-windows) doing so.

### List delivery problems

`GET /api/v1/alerts/delivery-problems`

Notifications that haven't arrived: the latest 20 that are being retried or were given
up on, newest first. `state` is `pending` while retries continue and `failed` once the
server has given up, after a day.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/alerts/delivery-problems"
```

```json
[
  {
    "channel": "Ops",
    "summary": "High CPU on web-1",
    "event": "firing",
    "state": "pending",
    "attempts": 3,
    "error": "the webhook returned status 500",
    "created_ms": 1793940279545
  }
]
```

### Acknowledge an alert

`POST /api/v1/alerts/{id}/acknowledge`

Says someone is dealing with it, which shows on the Alerts page and stops its reminders.
The first to acknowledge stays on it. Through the API, `acknowledged_by` is `api`. Returns
`204`, or `404` if it isn't firing.

### Undo acknowledging an alert

`POST /api/v1/alerts/{id}/unacknowledge`

Returns `204`, or `404` if it isn't firing.

## Silences

While a silence runs, alerts it covers still fire and show, but nobody is notified. If
one is still firing when the silence ends, its notifications go out then. Anyone who was
already told about an alert still hears when it ends.

| Field | Meaning |
|---|---|
| `rule_id` | The alert rule it covers. Leave it out for every rule. |
| `filter` | Which hosts it covers, written as in [Filters](#filters). Leave it out for every host. Alerts about a group of machines have no host, so a filter leaves them out. |
| `reason` | Why, which is required. |
| `duration_secs` | How long it lasts from now, up to 30 days. |

Deleting a rule deletes its silences too.

### List silences

`GET /api/v1/silences`

Everything running, and the latest 200 that have ended.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" "$MAXNINES_URL/api/v1/silences"
```

```json
{
  "active": [
    {
      "id": 3,
      "rule_id": null,
      "filter": "hostname=db*",
      "reason": "Upgrading Postgres",
      "created_by": "api",
      "starts_ms": 1793940279545,
      "ends_ms": 1793947479545
    }
  ],
  "ended": []
}
```

### Start a silence

`POST /api/v1/silences`

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"filter": "hostname=db*", "reason": "Upgrading Postgres", "duration_secs": 7200}' \
  "$MAXNINES_URL/api/v1/silences"
```

Returns `201` with the new `id`.

### Get a silence

`GET /api/v1/silences/{id}`

### End a silence

`POST /api/v1/silences/{id}/end`

Ends it now, and keeps it in the list of ended silences. Returns `204`, or `404` if it
isn't running.

## Maintenance windows

A maintenance window is a silence that comes round on a schedule. Times are wall clock
times in the window's time zone, so it keeps its place in the day when the clocks change.

| Field | Meaning |
|---|---|
| `name` | Required. |
| `rule_id` | The alert rule it covers. Leave it out for every rule. |
| `filter` | Which hosts it covers, as for a [silence](#silences). |
| `days` | Required. The days it starts on: `mon`, `tue`, `wed`, `thu`, `fri`, `sat` or `sun`. |
| `start_time` | Required. When it starts, like `02:00`. |
| `duration_minutes` | Required. How long it lasts, up to 7 days. |
| `time_zone` | Required. A time zone database name, like `Europe/London` or `UTC`. |

Deleting a rule deletes its windows too.

### List maintenance windows

`GET /api/v1/maintenance-windows`

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" "$MAXNINES_URL/api/v1/maintenance-windows"
```

### Create a maintenance window

`POST /api/v1/maintenance-windows`

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "Weekly patching", "filter": "env=staging", "days": ["sun"], "start_time": "02:00", "duration_minutes": 120, "time_zone": "Europe/London"}' \
  "$MAXNINES_URL/api/v1/maintenance-windows"
```

Returns `201` with the new `id`.

### Get a maintenance window

`GET /api/v1/maintenance-windows/{id}`

### Update a maintenance window

`PUT /api/v1/maintenance-windows/{id}`

Takes the same fields as creating one, and returns `204`.

### Delete a maintenance window

`DELETE /api/v1/maintenance-windows/{id}`

Returns `204`.

## Alert rules

| Field | Description |
| --- | --- |
| `name` | Required |
| `kind` | Required. `metric`, `offline`, `calculation` or `forecast` |
| `metric` | For metric, calculation and forecast rules, a name from the [catalog](#list-metrics) |
| `series` | Limits a metric or forecast rule to matching series, with `*` and `?` wildcards |
| `comparison` | For metric and calculation rules, `above` or `below`. For a forecast, `above` means rising to `threshold` and `below` falling to it |
| `threshold` | For metric and calculation rules, the value to compare with. For a forecast, the level it's heading for |
| `warning_threshold` | Optional, for a critical metric or calculation rule. Where it's a warning first, before `threshold`. One alert covers both, at the worse of the two, as in [warning, then critical](alerts.md#warning-then-critical) |
| `for_secs` | Required. How long a problem lasts before firing, and how long it has to stay gone before resolving |
| `severity` | Required. `warning` or `critical`, for crossing `threshold` |
| `condition` | A CEL expression limiting which agents this covers |
| `enabled` | Defaults to `true` |
| `channels` | IDs of the [channels](#notification-channels) to tell. With none, an alert only shows in the web interface |
| `all_channels` | `true` to tell every channel instead, including ones added later. Leave `channels` empty with it. Defaults to `false` |
| `calculation` | For calculation rules, `avg`, `sum`, `min`, `max` or `count`, as in [a query](#ask-about-many-machines-at-once) |
| `group_by` | For calculation rules, what's watched separately: `nothing`, `host`, `series` or `fact:<name>` |
| `filter` | For calculation rules, which machines, as on the host list. It takes the place of `condition` |
| `window_secs` | For calculation rules, how far back to look, from 60 to 86400. Defaults to 300. For a forecast, how far back the line is drawn through, from 3600 to 86400. Defaults to 21600 |
| `forecast_secs` | Required for a forecast. How soon the metric has to be on course to reach `threshold`, for `severity`, from 60 to 2592000 |
| `warning_forecast_secs` | Optional, for a critical forecast. A longer time ahead that's a warning first, as in [forecasts](alerts.md#forecasts) |
| `remind_every_secs` | How often to say the alert is still firing, until someone acknowledges it, at most every 300 seconds. Leave it out for no reminders. On-call services are left out, as they repeat for themselves. |

A forecast rule alerts when a metric is on course to reach a level soon, judging by the
straight line through its recent readings, as in [forecasts](alerts.md#forecasts). This
warns when a disk is on course to be full within a day, and is critical within 4 hours:

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Disk will be full soon",
    "kind": "forecast",
    "metric": "disk.usage",
    "comparison": "above",
    "threshold": 100,
    "forecast_secs": 14400,
    "warning_forecast_secs": 86400,
    "window_secs": 21600,
    "for_secs": 1800,
    "severity": "critical",
    "all_channels": true
  }' \
  "$MAXNINES_URL/api/v1/alert-rules"
```

A calculation rule watches something across machines, such as the average CPU of every
Linux host, and gives one alert for the group rather than one per machine. `min` and
`max` use the lowest or highest moment in the window, and the rest use the average over
it. An alert about a group has the `agent_id` `fleet`, and its `series` says which group.
A `count` that finds nothing reporting counts as 0, so a rule can catch machines going
quiet. Rules wait out the first two minutes after a server starts, while agents
reconnect.

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Busy web servers",
    "kind": "calculation",
    "metric": "cpu.usage",
    "calculation": "avg",
    "filter": "role=web",
    "comparison": "above",
    "threshold": 80,
    "window_secs": 600,
    "for_secs": 300,
    "severity": "warning"
  }' \
  "$MAXNINES_URL/api/v1/alert-rules"
```

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
  "warning_threshold": null,
  "for_secs": 300,
  "severity": "warning",
  "condition": null,
  "enabled": true,
  "channels": [],
  "all_channels": false
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

Where alerts go. Webhook addresses, custom webhook headers, Teams workflow URLs, PagerDuty keys, AlertOps and SIGNL4 URLs, Slack
and Telegram tokens, mail server passwords and Resend API keys can be set but never read back, so
`target_preview` only shows enough to recognize a channel.

| Field | Description |
| --- | --- |
| `name` | Required |
| `kind` | Required. `webhook`, `custom_webhook`, `email`, `resend`, `discord`, `slack`, `teams`, `pagerduty`, `alertops`, `signl4` or `telegram` |
| `target` | Required. A webhook's address, a Teams workflow's URL, email addresses separated by commas for email and Resend, a Slack channel, a PagerDuty integration key, the URL from AlertOps or SIGNL4, or a Telegram chat ID such as `-1001234567890` or `@channel` |
| `credential` | Slack's or Telegram's bot token, the mail server's password for email, the API key for Resend, or a custom webhook's headers, one to a line as `Name: value` |
| `mail` | Email and Resend only. See below |
| `request` | Custom webhooks only, and required for them. See below |
| `app_token` | Optional, Slack only. The app-level token, starting `xapp-`, that adds Acknowledge and Silence buttons |
| `severities` | Which alerts it's sent: `["warning", "critical"]`, the default, or one of them, as in [which channels hear what](alerts.md#which-channels-hear-what) |

Email and Resend channels have `mail`:

| Field | Description |
| --- | --- |
| `from` | Required. Who the email comes from, like `MaxNines <alerts@example.com>`. For Resend, on a domain verified there |
| `server` | Email only, and required for it. The mail server it goes through |
| `server.host` | Required. Like `smtp.example.com` |
| `server.port` | The usual port for `security` if left out: 587 for `starttls`, 465 for `tls`, 25 for `none` |
| `server.security` | `starttls`, the default, `tls`, or `none` for a relay on a trusted network |
| `server.username` | For a server that asks you to sign in. The password goes in `credential`, and needs `starttls` or `tls` |

Custom webhooks have `request`, as in [custom webhooks](notifications.md#custom-webhooks):

| Field | Description |
| --- | --- |
| `method` | `POST`, the default, `PUT` or `PATCH` |
| `content_type` | Required. Like `application/json`, which has what's filled in escaped for JSON |
| `body` | Required. A Tera template, up to 16 KB. It's checked when saved, and a JSON body has to come out as valid JSON |

Reading a custom webhook back gives `header_names`, the names of its headers, but never
their values.

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "Status board", "kind": "custom_webhook",
       "target": "https://status.example.com/api/events",
       "credential": "Authorization: Bearer abc123",
       "request": {"method": "POST", "content_type": "application/json",
                   "body": "{\"title\": \"{{ alert.rule_name }} on {{ alert.host }}\", \"status\": \"{{ event }}\"}"}}' \
  "$MAXNINES_URL/api/v1/notification-channels"
```

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "Ops email", "kind": "email", "target": "ops@example.com",
       "credential": "the password",
       "mail": {"from": "MaxNines <alerts@example.com>",
                "server": {"host": "smtp.example.com", "username": "alerts@example.com"}}}' \
  "$MAXNINES_URL/api/v1/notification-channels"
```

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
  "target_preview": "https://hooks.example.com/…",
  "severities": ["warning", "critical"],
  "mail": null,
  "request": null,
  "header_names": null
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
| `insecure` | http, tls | Measure a site whose certificate can't be verified, without counting that as down. Without it, an HTTP check never sends its request to a server that fails the certificate check |
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

## Map

The map puts machines in places with location rules. Each rule has a filter, in the
same form as the host list, and a point on the map. Where several rules match a
machine, the one with the highest `priority` decides, and of two with the same
priority the older one. A machine placed from its own page is a rule whose filter is
`id=` and its agent ID, at priority 100.

| Field | Meaning |
|---|---|
| `name` | Required. What the map calls the machines the rule covers, such as `Leeds office`. |
| `filter` | Which machines, as in the host list. Leave it out for every machine. |
| `place` | Where it is in words, such as `Leeds, England, United Kingdom`. |
| `latitude` | Required. From -90 to 90. |
| `longitude` | Required. From -180 to 180. |
| `priority` | A whole number. Defaults to 0. |

### Get the map

`GET /api/v1/map`

Every place with machines in it, those most in need of attention first, and the
approved machines no rule places. A place's `health` is that of its worst machine:
`critical`, `warning`, `offline` or `online`.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" "$MAXNINES_URL/api/v1/map"
```

```json
{
  "sites": [
    {
      "rule_id": 1,
      "name": "Leeds office",
      "place": "Leeds, England, United Kingdom",
      "latitude": 53.79648,
      "longitude": -1.54785,
      "health": "warning",
      "counts": { "critical": 0, "warning": 1, "offline": 0, "online": 3 },
      "machines": [
        { "id": "8c1f…", "short_id": "8c1f02ab", "host": "web-1", "health": "warning" }
      ]
    }
  ],
  "unplaced": []
}
```

### List location rules

`GET /api/v1/location-rules`

Highest priority first.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" "$MAXNINES_URL/api/v1/location-rules"
```

### Create a location rule

`POST /api/v1/location-rules`

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "Leeds office", "filter": "networking.addresses=10.1.*", "place": "Leeds, England, United Kingdom", "latitude": 53.79648, "longitude": -1.54785}' \
  "$MAXNINES_URL/api/v1/location-rules"
```

Returns `201` with the new `id`.

### Get a location rule

`GET /api/v1/location-rules/{id}`

```json
{
  "id": 1,
  "name": "Leeds office",
  "filter": "networking.addresses=10.1.*",
  "place": "Leeds, England, United Kingdom",
  "latitude": 53.79648,
  "longitude": -1.54785,
  "priority": 0
}
```

### Update a location rule

`PUT /api/v1/location-rules/{id}`

Takes the same fields as creating one, and returns `204`.

### Delete a location rule

`DELETE /api/v1/location-rules/{id}`

Returns `204`.

### Search for a place

`GET /api/v1/places`

Towns and cities whose name starts with the `q` parameter, up to 10, an exact name first and then
the biggest. Words after a comma narrow it to a region or country, as in
`portland, maine` or `paris, us`. The list is every place with 1,000 people or more,
from [GeoNames](https://www.geonames.org/) under CC BY 4.0, and is built into the
server, so searching never leaves it.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/places?q=portland,%20maine"
```

```json
[
  {
    "name": "Portland",
    "region": "Maine",
    "country": "United States",
    "country_code": "US",
    "latitude": 43.66147,
    "longitude": -70.25533,
    "population": 68408,
    "label": "Portland, Maine, United States"
  }
]
```

### Find the nearest place

`GET /api/v1/places/nearest`

The listed place closest to the point given by the `lat` and `lon` parameters, in the same form as a search result.

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
along with `cpu`, `memory`, `disk` and `network` for the machine it's on. Nothing has
to be installed for this. They work like any agent's metrics, including in alert
rules. Read them with the same route, using metrics such as `server.metrics` (metrics
stored per second), `server.samples`, `server.write_queue`, `server.write_time`,
`server.agents`, `server.alerts`, `server.database_size`, `server.series`,
`server.memory`, `server.cpu`, `server.open_files` and `cpu.usage`:

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/agents/server/metrics/server.memory"
```

## Health

`GET /health` or `HEAD /health`

For load balancers and uptime monitors. It's at the top of the site rather than under
`/api/v1`, and needs no key. It answers `200` when everything works and `503` when
something doesn't, and says which part without giving any detail. Each check has two
seconds to answer. `HEAD` gives the same status with no body, for monitors that can only
send that.

| Check | What it means |
| --- | --- |
| `database` | The main database answers |
| `metrics` | The metrics database answers |
| `writer` | Samples can still be saved |
| `alerts` | Alert rules have run in the last minute |

```json
{
  "status": "ok",
  "checks": { "database": "ok", "metrics": "ok", "writer": "ok", "alerts": "ok" }
}
```

## Calculations

### Ask about many machines at once

`GET /api/v1/query`

Combines a metric across machines, the same way dashboards do. Each series is averaged
within a moment first, so a machine reporting more often doesn't count for more. Only
approved machines count, and the server itself isn't one of them. Machines are combined
over whole minutes, leaving out the one still filling up. A metric that measures several
things, like memory and swap, uses the first unless `group_by` is `series`.

| Parameter | Meaning |
| --- | --- |
| `metric` | Required. A name from `GET /api/v1/metrics`. |
| `calculation` | `avg`, `sum`, `min`, `max` or `count`, which is how many series are reporting. Defaults to `avg`. |
| `group_by` | What gets a line of its own: `nothing`, `host`, `series` or `fact:<name>`. Defaults to `nothing`. |
| `filter` | Which machines, in the same form as the host list, such as `os=linux hostname=web*`. Defaults to all of them. |
| `from_ms`, `to_ms` | The time range. Defaults to the last hour. |

The result has the same shape as an agent's metric. The highest 100 lines are kept, and
`hidden` says how many more there were. A question that makes no sense gets a `422`.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/query?metric=cpu.usage&calculation=avg&group_by=fact:role"
```

## Dashboards

Everyone signed in shares dashboards. A widget sits on a grid 12 columns wide, and
asks one question, using the same `metric`, `calculation`, `group_by` and `filter` as
`GET /api/v1/query`.

| Widget field | Meaning |
| --- | --- |
| `title` | What it's called. Empty uses the metric's name. |
| `kind` | `chart`, `number` or `table`. Defaults to `chart`. A number always combines everything. |
| `x`, `y`, `w`, `h` | Where it sits, in grid cells. Defaults to the top left, 6 wide and 4 high. |

### List dashboards

`GET /api/v1/dashboards`

Each dashboard's `id`, `name` and how many `widgets` it has, sorted by name.

### Create a dashboard

`POST /api/v1/dashboards`

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -d '{"name": "Fleet"}' "$MAXNINES_URL/api/v1/dashboards"
```

### Get a dashboard

`GET /api/v1/dashboards/{id}`

The dashboard with its `widgets`, from the top of the page down.

### Rename a dashboard

`PUT /api/v1/dashboards/{id}`

Takes a `name`.

### Delete a dashboard

`DELETE /api/v1/dashboards/{id}`

Deletes its widgets too.

### Add a widget

`POST /api/v1/dashboards/{id}/widgets`

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -d '{"metric": "cpu.usage", "calculation": "avg", "group_by": "host", "filter": "os=linux"}' \
  "$MAXNINES_URL/api/v1/dashboards/1/widgets"
```

### Change or remove a widget

`PUT /api/v1/dashboards/{id}/widgets/{widget}`

`DELETE /api/v1/dashboards/{id}/widgets/{widget}`

Changing a widget replaces all of it, including where it sits.

### Move widgets

`PUT /api/v1/dashboards/{id}/layout`

Takes a list of widgets' `id`, `x`, `y`, `w` and `h`, and saves them together.

## API keys

Keys can also be managed on the Settings page, and with `maxnines-server api-keys`.
Only a hash of each key is kept, so a key can only be seen when it's created. `hint` is
the start of it, to tell keys apart. Each key acts as its owner, `user_id`, whose
email address is `owner`, with at most its `role`. Deleting a user deletes their keys.
Admins see and revoke everyone's keys, and everyone else only their own.

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
    "user_id": 1,
    "owner": "you@example.com",
    "role": "admin",
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
| `name` | Required. What the key is for, up to 100 characters. The key belongs to whoever owns the key making it |
| `expires_in_secs` | How long it lasts. Leave it out for a key that never expires |
| `role` | `viewer`, `responder`, `editor` or `admin`: the most it can do, up to the role of the key making it, which is what it gets if left out. More than that gives `403` |

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
  "user_id": 1,
  "owner": "you@example.com",
  "role": "admin",
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
    "time_zone": "Europe/London",
    "has_password": true,
    "created_ms": 1793977895109,
    "last_sign_in_ms": 1793978000000,
    "disabled_ms": null
  }
]
```

### Add a user

`POST /api/v1/users`

Takes an `email`, a `name`, and a `role`: `viewer`, the default, `responder`, `editor`
or `admin`. The answer holds a link for them to set a password. It works once, lasts
7 days and can't be seen again, so pass it on.

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
    "role": "viewer",
    "theme": "carbon",
    "time_zone": "UTC",
    "has_password": false,
    "two_factor": false,
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

### Change a user's role, theme or time zone

`PUT /api/v1/users/{id}`

Give any of them. `role` is `viewer`, `responder`, `editor` or `admin`, and taking it
from the last admin gives `409`. `theme` can be `carbon`, `midnight`, `dusk`, `paper`, `contrast`
or `system`. `time_zone` is a name from the time zone database, like
`America/New_York`, and is what the pages show times in. Everyone starts on `UTC`.

```sh
curl -X PUT -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"theme": "paper", "time_zone": "America/New_York"}' \
  "$MAXNINES_URL/api/v1/users/2"
```

### Reset a user's two-factor sign-in

`POST /api/v1/users/{id}/two-factor/reset`

Turns off [two-factor sign-in](users.md#two-factor-sign-in) for someone who's lost
their phone and their recovery codes, so they can sign in with their password and set
it up again. A user's `two_factor` says whether they have it on. Setting it up needs
the person and their phone, so it's only done on their profile page.

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/users/2/two-factor/reset"
```

### Require two-factor for everyone

`GET /api/v1/users/two-factor`

`PUT /api/v1/users/two-factor`

Whether everyone has to set up two-factor before using the pages, as
`{"required": true}`. Requiring it gives `409` unless the key's owner has two-factor
themselves. API keys keep working either way.

```sh
curl -X PUT -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"required": true}' \
  "$MAXNINES_URL/api/v1/users/two-factor"
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

## Audit log

Who changed what, and who signed in, as on the Audit log page in Settings. See
[Audit log](audit-log.md) for what's recorded.

### Read the audit log

`GET /api/v1/audit-log`

Newest first.

| Parameter | Description |
| --- | --- |
| `before` | Only entries older than the one with this `id`. Pass the last `id` of a page to get the next |
| `limit` | How many entries, from 1 to 1000. 100 if left out |

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/audit-log?limit=2"
```

```json
[
  {
    "id": 42,
    "at_ms": 1794180214377,
    "actor": { "kind": "person", "id": "1", "name": "sam@example.com" },
    "via": { "kind": "api_key", "id": "3", "name": "Deploy job" },
    "source": "192.168.0.20",
    "action": "changed",
    "subject": { "kind": "alert_rule", "id": "3", "name": "Disk filling up" },
    "changes": [
      { "field": "threshold", "before": 90.0, "after": 95.0 },
      { "field": "channels", "before": ["Ops email"], "after": ["Ops email", "PagerDuty"] }
    ]
  },
  {
    "id": 41,
    "at_ms": 1794180190012,
    "actor": { "kind": "person", "id": "1", "name": "sam@example.com" },
    "via": null,
    "source": "192.168.0.20",
    "action": "signed_in",
    "subject": { "kind": "user", "id": "1", "name": "sam@example.com" },
    "changes": []
  }
]
```

`actor.kind` is one of:

| Kind | Who |
| --- | --- |
| `person` | A user. `name` is their email address |
| `command_line` | A `maxnines-server` command run on the server's machine |
| `maxnines` | The server itself, like a registration rule approving an agent |
| `nobody` | Someone who isn't signed in, like a failed sign in |

`via` says how a person acted when it wasn't on the pages: `api_key`, with the key's
`id` and `name`, or `slack`, for an alert's buttons in Slack, matched to the user by
email address.

`action` is `created`, `changed`, `deleted`, `signed_in`, `sign_in_failed`,
`signed_out`, `new_setup_link`, `acknowledged` or `unacknowledged`. `subject.kind` is
`user`, `api_key`, `agent`, `config_rule`, `alert_rule`, `notification_channel`,
`alert`, `silence`, `maintenance_window`, `remote_check`, `location_rule` or
`dashboard`. Names are as they were at the time.

`source` is the address the request came from, which is empty for changes that
didn't come from a request. Behind a proxy, it's the address the proxy passed on, if
the proxy is in `trusted_proxies`.

In `changes`, a field that had no value leaves out `before`, and one that has none
now leaves out `after`. Nested fields are named with dots, like `settings.disk.interval`.
Secrets have `"secret": true` and say `"hidden"` in place of their values.
