# Maintenance windows API

A maintenance window is a silence that comes round on a schedule. Times are wall clock
times in the window's time zone, so it keeps its place in the day when the clocks change.

| Field | Meaning |
|---|---|
| `name` | Required. |
| `rule_id` | The alert rule it covers. Leave it out for every rule. |
| `filter` | Which hosts it covers, as for a [silence](api-silences.md). |
| `days` | Required. The days it starts on: `mon`, `tue`, `wed`, `thu`, `fri`, `sat` or `sun`. |
| `start_time` | Required. When it starts, like `02:00`. |
| `duration_secs` | Required. How long it lasts, in whole minutes up to 7 days, so a multiple of 60. |
| `time_zone` | Required. A time zone database name, like `Europe/London` or `UTC`. |

Deleting a rule deletes its windows too.

## List maintenance windows

`GET /api/v1/maintenance-windows`

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" "$MAXNINES_URL/api/v1/maintenance-windows"
```

## Add a maintenance window

`POST /api/v1/maintenance-windows`

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "Weekly patching", "filter": "env=staging", "days": ["sun"], "start_time": "02:00", "duration_secs": 7200, "time_zone": "Europe/London"}' \
  "$MAXNINES_URL/api/v1/maintenance-windows"
```

Returns `201` with the new `id`.

## Get a maintenance window

`GET /api/v1/maintenance-windows/{id}`

## Update a maintenance window

`PUT /api/v1/maintenance-windows/{id}`

Takes the same fields as creating one, and returns `204`.

## Delete a maintenance window

`DELETE /api/v1/maintenance-windows/{id}`

Returns `204`.
