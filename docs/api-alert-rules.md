# Alert rules API

| Field | Description |
| --- | --- |
| `name` | Required. No two rules can have the same name, ignoring case, or saving gives `422` |
| `warning` | When it's a warning: a [condition](alerts.md#conditions) in CEL, such as `disk.usage > 80`. A rule needs `warning`, `critical` or both |
| `critical` | When it's critical, the same way. With both, one alert covers both, at the worse of the two, as in [warning, then critical](alerts.md#warning-then-critical) |
| `summary` | What alerts say, filled in like a [custom webhook's body](notifications.md#custom-webhooks): `{{ hostname }}`, `{{ series }}`, `{{ value }}` and the metrics the conditions use, such as `{{ disk.usage }}`, each written in its unit. Without it, the rule's name, the host and the reading |
| `resolved_summary` | What alerts say as they clear, the same way |
| `for_secs` | Required. How long a problem lasts before firing. The alert resolves as soon as the problem is gone |
| `applies_to` | A CEL expression over facts limiting which hosts this covers, such as `facts.os.family == "linux"` |
| `enabled` | Defaults to `true` |
| `channels` | IDs of the [channels](api-notification-channels.md) to tell. With none, an alert only shows in the web interface |
| `all_channels` | `true` to tell every channel instead, including ones added later. Leave `channels` empty with it. Defaults to `false` |
| `actions` | Not for a calculation. [Actions](api-actions.md) to run on the alert's host, up to 8. Each has an `action`, the name hosts report, and optionally `run_on`: `first` for when the alert starts, which is the default, or `warning` or `critical` for the first time it's that severe; and `timeout_secs`, from 1 to 600, 30 if left out. Each runs once per alert. Saving is refused if no host has the action, or it needs something this rule's alerts can't give, such as `{disk}` for a CPU rule |
| `calculation` | For a rule about a group of hosts rather than each one: `avg`, `sum`, `min`, `max` or `count`, as in [a query](api-calculations.md#ask-about-many-hosts-at-once). Its conditions are about the calculated `value`, such as `value > 80` |
| `metric` | With a calculation, what it combines, a name from the [catalog](api-metrics.md#list-metrics) |
| `group_by` | With a calculation, what's watched separately: `nothing`, `host`, `series` or `fact:<name>` |
| `filter` | With a calculation, which hosts, as on the Hosts list. It takes the place of `applies_to` |
| `window_secs` | With a calculation, how far back to look, from 60 to 86400, 300 if left out. For a rule using `forecast()`, how far back its line is drawn through, from 3600 to 86400, 21600 if left out |
| `remind_every_secs` | How often to say the alert is still firing, until someone acknowledges it, at most every 300 seconds. Leave it out for no reminders. On-call services are left out, as they repeat for themselves. |

Conditions are checked as a rule is saved: a mistake in one, a name that isn't a metric,
or something that can't work, such as a length of time compared with a number, gives
`422` with what's wrong.

A rule for a host that's connected but whose samples have stopped, as in
[connected but sending no metrics](alerts.md#connected-but-sending-no-metrics):

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Host sending no metrics",
    "critical": "!reporting",
    "summary": "{{ hostname }} is connected but sending no metrics",
    "for_secs": 300,
    "all_channels": true
  }' \
  "$MAXNINES_URL/api/v1/alert-rules"
```

A forecast warns when a disk is on course to be full within a day, and is critical within
4 hours, judging by the straight line through its last 6 hours, as in
[forecasts](alerts.md#forecasts):

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Disk will be full soon",
    "warning": "forecast(disk.usage, duration(\"24h\")) >= 100",
    "critical": "forecast(disk.usage, duration(\"4h\")) >= 100",
    "window_secs": 21600,
    "for_secs": 1800,
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
    "calculation": "avg",
    "metric": "cpu.usage",
    "filter": "role=web",
    "warning": "value > 80",
    "window_secs": 600,
    "for_secs": 300
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
    "warning": "cpu.usage > 90",
    "for_secs": 300
  }' \
  "$MAXNINES_URL/api/v1/alert-rules"
```

```json
{ "id": 1 }
```

## Try an alert rule on the last day

`POST /api/v1/alert-rules/replay`

Works a rule out on the last 24 hours of what's stored, without saving it, as **Try it
on the last day** on its form does. The body is a rule, as for adding one, and one that
couldn't be saved gives `422` with why. `alerted` has only the hosts, or a
calculation's lines, it would have alerted on, the most first, with how many times it
would have started as a warning and how many it would have started critical or become
it. `tried` is how many had anything stored to try it on. It's worked out on each
`step_minutes` of what's stored, so something shorter may not show, `forecast()` is
drawn through those steps, and hosts are taken to have been `online` and `reporting`,
which `notes` say when they apply. It tries at most 100 hosts.

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{ "name": "Disk", "warning": "disk.usage > 80", "critical": "disk.usage > 90", "for_secs": 300 }' \
  "$MAXNINES_URL/api/v1/alert-rules/replay"
```

```json
{
  "alerted": [{ "name": "web-1", "warned": 2, "critical": 1 }],
  "warned": 2,
  "critical": 1,
  "tried": 12,
  "step_minutes": 10,
  "notes": []
}
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
  "warning": "cpu.usage > 90",
  "critical": null,
  "summary": null,
  "resolved_summary": null,
  "for_secs": 300,
  "applies_to": null,
  "enabled": true,
  "channels": [],
  "all_channels": false,
  "calculation": null,
  "metric": null,
  "group_by": null,
  "filter": null,
  "window_secs": null,
  "remind_every_secs": null,
  "actions": []
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
    "warning": "cpu.usage > 90",
    "critical": "cpu.usage > 95",
    "for_secs": 300
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
