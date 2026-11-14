# Metrics API

## List metrics

`GET /api/v1/metrics`

Everything that can be charted or alerted on, for use in `{metric}` above and in
[alert rules](api-alert-rules.md).

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

## Get current values

`GET /api/v1/metrics/current`

The latest headline numbers from every host, by host ID. Hosts with nothing in the
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
