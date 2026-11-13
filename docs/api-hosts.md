# Hosts API

A host is a computer whose agent reports to this server. A host's `state` is `pending`,
`approved` or `revoked`. Its `health` is `critical`, `warning`, `offline` or `online`,
and problems outrank being online.

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
    "public_key": "912e3122b606a9c2776e065d87dc31eefacde1d7dcad18e1cf88349eb32db35f",
    "hostname": "web-1",
    "state": "approved",
    "decided_by": "you@example.com",
    "first_seen_ms": 1793940264215,
    "decided_ms": 1793940265752,
    "online": true,
    "health": "online",
    "last_seen_ms": 1793940282225
  }
]
```

## Get a host

`GET /api/v1/hosts/{id}`

Gives one host, as above.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
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
`409`, so it always takes two steps.

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

Every value each fact has had, oldest first. `valid_to_ms` is empty for current values.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/hosts/$HOST_ID/facts/history"
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
    "reported_ms": 1793940267263
  }
}
```

## Get a host's metric

`GET /api/v1/hosts/{id}/metrics/{metric}`

One metric from the [catalog](api-metrics.md#list-metrics) over a period of time. The server
chooses `step_ms` to suit the period. Each point covers one step: `avg` is the average
of what was reported in it, and `min` and `max` the lowest and highest, so a short spike
shows in `max` however long the step. Long periods are read from what's
[kept](databases.md#how-long-metrics-are-kept) 5 minutes or an hour at a time. A metric can
have several series, such as one for each disk, and `hidden` says how many were left out.

| Parameter | Description |
| --- | --- |
| `from_ms` | The start. Defaults to an hour before `to_ms` |
| `to_ms` | The end. Defaults to now |

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/hosts/$HOST_ID/metrics/cpu.usage"
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
