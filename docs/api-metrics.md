# Metrics API

## List metrics

`GET /api/v1/metrics`

Everything that can be charted or alerted on, for use in `{metric}` above and in
[alert rules](api-alert-rules.md): the metrics MaxNines has built in, then those of
every [template](templates.md) that's on, by their full names, such as `myapp.lag`.
One of a template's has the template's `key` as `template`, and the `description` the
template gives it; for a built-in one both are `null`.

A metric's name is two or more parts joined by dots, each of lowercase letters,
digits and underscores, starting with a letter, and up to 255 characters in all.
The first part is a template's key, or one of the
[keys MaxNines' own metrics start with](templates.md#the-format).

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" "$MAXNINES_URL/api/v1/metrics"
```

```json
[
  {
    "name": "cpu.usage",
    "title": "CPU usage",
    "unit": "percent",
    "collector": "cpu",
    "description": null,
    "template": null
  }
]
```

## Get current values

`GET /api/v1/metrics/current`

The latest headline numbers from every host, by host ID, with when each last sent a
sample. Hosts with nothing in the last 5 minutes are left out.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/metrics/current"
```

```json
{
  "22ad9264b6eb708ffdbedcd5cc073e5c": {
    "last_sample_at": "2026-11-06T04:44:39.545Z",
    "cpu_percent": 19.4,
    "memory_percent": 75.6,
    "disk_percent": 84.5,
    "disk_mount_point": "/"
  }
}
```
