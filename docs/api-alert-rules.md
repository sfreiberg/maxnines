# Alert rules API

| Field | Description |
| --- | --- |
| `name` | Required |
| `kind` | Required. `metric`, `offline`, `calculation` or `forecast` |
| `metric` | For metric, calculation and forecast rules, a name from the [catalog](api-metrics.md#list-metrics) |
| `series` | Limits a metric or forecast rule to matching series, with `*` and `?` wildcards |
| `comparison` | For metric and calculation rules, `above` or `below`. For a forecast, `above` means rising to `threshold` and `below` falling to it |
| `threshold` | For metric and calculation rules, the value to compare with. For a forecast, the level it's heading for |
| `warning_threshold` | Optional, for a critical metric or calculation rule. Where it's a warning first, before `threshold`. One alert covers both, at the worse of the two, as in [warning, then critical](alerts.md#warning-then-critical) |
| `for_secs` | Required. How long a problem lasts before firing. The alert resolves as soon as the problem is gone |
| `severity` | Required. `warning` or `critical`, for crossing `threshold` |
| `condition` | A CEL expression limiting which hosts this covers |
| `enabled` | Defaults to `true` |
| `channels` | IDs of the [channels](api-notification-channels.md) to tell. With none, an alert only shows in the web interface |
| `all_channels` | `true` to tell every channel instead, including ones added later. Leave `channels` empty with it. Defaults to `false` |
| `actions` | For metric and forecast rules, [actions](api-actions.md) to run on the alert's host, up to 8. Each has an `action`, the name hosts report, and optionally `run_on`: `first` for when the alert starts, which is the default, or `warning` or `critical` for the first time it's that severe; and `timeout_secs`, from 1 to 600, 30 if left out. Each runs once per alert. Saving is refused if no host has the action, or it needs something this rule's alerts can't give, such as `{disk}` for a CPU rule |
| `calculation` | For calculation rules, `avg`, `sum`, `min`, `max` or `count`, as in [a query](api-calculations.md#ask-about-many-hosts-at-once) |
| `group_by` | For calculation rules, what's watched separately: `nothing`, `host`, `series` or `fact:<name>` |
| `filter` | For calculation rules, which hosts, as on the Hosts list. It takes the place of `condition` |
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

A calculation rule watches something across hosts, such as the average CPU of every
Linux host, and gives one alert for the group rather than one per host. `min` and
`max` use the lowest or highest moment in the window, and the rest use the average over
it. An alert about a group has the `host_id` `fleet`, and its `series` says which group.
A `count` that finds nothing reporting counts as 0, so a rule can catch hosts going
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

## List alert rules

`GET /api/v1/alert-rules`

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" "$MAXNINES_URL/api/v1/alert-rules"
```

## Add an alert rule

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

## Get an alert rule

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

## Update an alert rule

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

## Delete an alert rule

`DELETE /api/v1/alert-rules/{id}`

The rule stops watching, its open alerts end, and its silences that haven't ended and its
maintenance windows go. It's kept, marked deleted, so its alerts still say which rule
raised them as `rule_id`, but it's no longer listed or found, and its name is free for a
new rule.

```sh
curl -X DELETE -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/alert-rules/1"
```
