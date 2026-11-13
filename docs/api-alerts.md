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
      "resolved_ms": null,
      "resolve_reason": null,
      "acknowledged_by": null,
      "acknowledged_ms": null,
      "silence_id": null,
      "maintenance_window_id": null
    }
  ],
  "resolved": []
}
```

`silence_id` is the ID of the silence keeping an open alert's notifications back, and
`maintenance_window_id` is the ID of the [window](api-maintenance-windows.md) doing so.

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

## Acknowledge an alert

`POST /api/v1/alerts/{id}/acknowledge`

Says someone is dealing with it, which shows on the Alerts page and stops its reminders.
The first to acknowledge stays on it. Through the API, `acknowledged_by` is the email of the key's owner. Returns
`204`, or `404` if it isn't firing.

## Undo acknowledging an alert

`POST /api/v1/alerts/{id}/unacknowledge`

Returns `204`, or `404` if it isn't firing.
