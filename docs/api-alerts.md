# Alerts API

## List alerts

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
      "host_id": "22ad9264b6eb708ffdbedcd5cc073e5c",
      "hostname": "web-1",
      "series": "",
      "value": 97.2,
      "summary": "High CPU on web-1",
      "started_ms": 1793940279545,
      "breached_ms": 1793939979545,
      "resolved_ms": null,
      "resolve_reason": null,
      "resolved_summary": null,
      "acknowledged_by": null,
      "acknowledged_ms": null,
      "silence_id": null,
      "maintenance_window_id": null
    }
  ],
  "resolved": []
}
```

`started_ms` is when the alert fired, and `breached_ms` when its problem began, such
as when a host went offline. An alert fires once its rule's condition has held for the
rule's `for_secs`, so `breached_ms` is that much earlier, or more, as checks run on a
schedule. It's when the page says the problem has lasted since.

`silence_id` is the ID of the silence keeping an open alert's notifications back, and
`maintenance_window_id` is the ID of the [window](api-maintenance-windows.md) doing so.
`resolved_summary` says where things stood as a resolved alert's problem cleared, like
`CPU usage on web-1 is now 42%, no longer above 90%`, and is `null` for one that resolved
for another reason, given in `resolve_reason`.

## List delivery problems

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

## Get an alert's series

`GET /api/v1/alerts/{id}/series`

What an alert watches over a period of time, as its chart on the Alerts page shows it:
only the alert's own series, with the rule's `thresholds`. Points are as for
[a host's metric](api-hosts.md#get-a-hosts-metric), and for a calculation rule they're
the calculation's answer. Returns `404` if there's no such alert, or nothing to chart:
an offline alert, or one whose rule has been deleted.

| Parameter | Description |
| --- | --- |
| `from_ms` | The start. Defaults to a quarter as long again before the alert started as since, and at least an hour before `to_ms` |
| `to_ms` | The end. Defaults to now |

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/alerts/7/series"
```

```json
{
  "alert_id": 7,
  "metric": "disk.usage",
  "unit": "percent",
  "thresholds": [
    { "severity": "warning", "value": 80.0 },
    { "severity": "critical", "value": 90.0 }
  ],
  "from_ms": 1793936685969,
  "to_ms": 1793940285969,
  "step_ms": 15000,
  "series": [
    {
      "name": "/",
      "points": [
        { "time_ms": 1793940270000, "avg": 83.9, "min": 83.9, "max": 83.9 }
      ]
    }
  ],
  "hidden": 0
}
```

## Acknowledge an alert

`POST /api/v1/alerts/{id}/acknowledge`

Says someone is dealing with it, which shows on the Alerts page and stops its reminders.
The first to acknowledge stays on it. Through the API, `acknowledged_by` is the email of the key's owner. Returns
`204`, or `404` if it isn't firing.

## Undo acknowledging an alert

`POST /api/v1/alerts/{id}/unacknowledge`

Returns `204`, or `404` if it isn't firing.
