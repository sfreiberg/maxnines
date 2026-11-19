# Hosts API

A host is a computer whose agent reports to this server, or something with no agent
that the server reads from itself. Its `kind` says which: `agent` or `agentless`. A
host's `state` is `pending`, `approved` or `revoked`. Its `health` is `critical`,
`warning`, `offline`, `online` or `not_read`, and problems outrank being online. A
host with no agent is `not_read` while it has no page being read or check being run,
as it's then neither online nor offline.

## List hosts

`GET /api/v1/hosts`

| Parameter | Description |
| --- | --- |
| `filter` | Only hosts matching this [filter](api-filters.md) |

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/hosts?filter=os%3Dlinux"
```

```json
[
  {
    "id": "22ad9264b6eb708ffdbedcd5cc073e5c",
    "kind": "agent",
    "public_key": "912e3122b606a9c2776e065d87dc31eefacde1d7dcad18e1cf88349eb32db35f",
    "hostname": "web-1",
    "state": "approved",
    "decided_by": "you@example.com",
    "first_seen_at": "2026-11-06T04:44:24.215Z",
    "decided_at": "2026-11-06T04:44:25.752Z",
    "online": true,
    "health": "online",
    "last_seen_at": "2026-11-06T04:44:42.225Z"
  }
]
```

`last_seen_at` is `null` for a host the server hasn't heard from since it started,
which for one with no agent means none of its pages or checks has answered yet.

## Add a host without an agent

`POST /api/v1/hosts`

Adds a [host without an agent](agentless-hosts.md), already approved, and gives it
back with its new `id`. Give it [metrics pages](api-metrics-pages.md) for the server
to read. A host with an agent adds itself when its agent first connects.

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"hostname": "orders-db"}' \
  "$MAXNINES_URL/api/v1/hosts"
```

```json
{
  "id": "5f0c1d6f2a8e4b7790d3c1a2b4e6f809",
  "kind": "agentless",
  "public_key": "",
  "hostname": "orders-db",
  "state": "approved",
  "decided_by": "you@example.com",
  "first_seen_at": "2026-11-06T04:44:24.215Z",
  "decided_at": "2026-11-06T04:44:24.215Z"
}
```

## Get a host

`GET /api/v1/hosts/{id}`

Gives one host, as above.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/hosts/$HOST_ID"
```

## Rename a host without an agent

`PUT /api/v1/hosts/{id}`

A host with an agent is called what its agent says, so renaming one gives `409`.

```sh
curl -X PUT -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"hostname": "orders-db-eu"}' \
  "$MAXNINES_URL/api/v1/hosts/$HOST_ID"
```

## Approve a host

`POST /api/v1/hosts/{id}/approve`

Lets a host's agent connect, and gives back the host's record.

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/hosts/$HOST_ID/approve"
```

## Revoke a host

`POST /api/v1/hosts/{id}/revoke`

Stops a host's agent connecting and drops it if it's connected, and gives back the
host's record. This is the same for rejecting a waiting host. The host can't be approved
by a rule afterwards.

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/hosts/REVOKED_HOST_ID/revoke"
```

## Delete a host

`DELETE /api/v1/hosts/{id}`

Deletes a revoked host with all its metrics, facts and alerts, and its place on the
map if it has one of its own. It can't be undone. A host that isn't revoked gives
`409`, so it always takes two steps. A host without an agent has no agent to revoke,
so it's deleted in one, along with its metrics pages and checks.

If the host still runs the agent, it comes back as a new host waiting to be
approved, and a rule can approve it like any other.

```sh
curl -X DELETE -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/hosts/REVOKED_HOST_ID"
```

## Get a host's facts

`GET /api/v1/hosts/{id}/facts`

`trusted` is what the server knows for itself. `reported` is only what the agent
claims, so don't use it for anything to do with security.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/hosts/$HOST_ID/facts"
```

```json
{
  "trusted": {
    "host_id": "22ad9264b6eb708ffdbedcd5cc073e5c",
    "state": "approved",
    "decided_by": "you@example.com",
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

## Get the history of a host's facts

`GET /api/v1/hosts/{id}/facts/history`

Every value each fact has had, oldest first. `valid_to` is empty for current values.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/hosts/$HOST_ID/facts/history"
```

```json
[
  {
    "name": "os.version",
    "value": "24.04",
    "valid_from": "2026-11-06T04:44:27.223Z",
    "valid_to": null
  }
]
```

## Get a host's config

`GET /api/v1/hosts/{id}/config`

`desired` is what the [config rules](api-config-rules.md) come to for this host. `reported`
is what its agent last said it's running, with `error` set if it refused the config.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/hosts/$HOST_ID/config"
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
    "reported_at": "2026-11-06T04:44:27.263Z"
  }
}
```

## Get a host's metric

`GET /api/v1/hosts/{id}/metrics/{metric}`

One metric from the [catalog](api-metrics.md#list-metrics) over a period of time. The server
chooses `step_secs` to suit the period. Each point covers one step from its `time`: `avg` is the average
of what was reported in it, and `min` and `max` the lowest and highest, so a short spike
shows in `max` however long the step. Long periods are read from what's
[kept](databases.md#how-long-metrics-are-kept) 5 minutes or an hour at a time. A metric can
have several series, such as one for each disk, and `hidden` says how many were left out.

| Parameter | Description |
| --- | --- |
| `from` | The start, such as `2026-11-06T03:00:00Z`. Defaults to an hour before `to` |
| `to` | The end. Defaults to now |

A period has to start after it ends, start no earlier than 1970, end before 2300 and
last no more than 366 days, or it's refused with `400`.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/hosts/$HOST_ID/metrics/cpu.usage"
```

```json
{
  "metric": "cpu.usage",
  "unit": "percent",
  "from": "2026-11-06T03:44:45.969Z",
  "to": "2026-11-06T04:44:45.969Z",
  "step_secs": 15,
  "series": [
    {
      "name": "CPU",
      "points": [
        { "time": "2026-11-06T04:44:30Z", "avg": 19.4, "min": 19.4, "max": 19.4 }
      ]
    }
  ],
  "hidden": 0
}
```
