# Annotations API

Deploys, upgrades and notes, marked on the charts of the hosts their filter picks.
See [Annotations](annotations.md). Adding and deleting them needs the responder role.

| Field | Meaning |
|---|---|
| `kind` | `deploy` or `note`, which is the default. |
| `title` | What happened, which is required. Up to 200 characters. |
| `detail` | More about it, up to 2,000 characters. |
| `time_ms` | When it happened, from a year ago to now. Defaults to now. |
| `filter` | Which hosts, written as in [Filters](api-filters.md). Leave it out for every host. It's matched against each host whenever a chart is drawn, so a host added later shows it too, and one that matches nothing yet is fine. |

## Add an annotation

`POST /api/v1/annotations`

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"kind": "deploy", "title": "Shop v2.3", "detail": "Build 812", "filter": "role=web"}' \
  "$MAXNINES_URL/api/v1/annotations"
```

Returns `201` with the new `id`. Reading it back gives:

```json
{
  "id": 14,
  "time_ms": 1793940279545,
  "kind": "deploy",
  "title": "Shop v2.3",
  "detail": "Build 812",
  "filter": "role=web",
  "created_by": "deploy@example.com",
  "created_ms": 1793940279545
}
```

## List annotations

`GET /api/v1/annotations`

Newest first. `from_ms` and `to_ms` choose the period, which is the last 7 days unless
given, and `limit` how many, which is 200 unless given, up to 1,000.

## Get an annotation

`GET /api/v1/annotations/{id}`

## Delete an annotation

`DELETE /api/v1/annotations/{id}`

Returns `204`, or `404` if there's no such annotation.

## Get a host's events

`GET /api/v1/hosts/{id}/events`

Everything that happened to one host, newest first, as its page shows them: the
annotations whose filter matches it, restarts, config changes, alerts starting
(`alert`) and ending (`resolved`), and updates. `from_ms` and `to_ms` choose the period,
which is the last 24 hours unless given. Only what was recorded has an `id`, and `created_by` is
who added an annotation, or `null` for what the server worked out.

```json
[
  {
    "time_ms": 1793940279545,
    "kind": "restart",
    "title": "Host started",
    "detail": null,
    "created_by": null,
    "id": 15
  },
  {
    "time_ms": 1793936685969,
    "kind": "update",
    "title": "Agent updated to 0.1.0-alpha.3",
    "detail": "It was 0.1.0-alpha.2.",
    "created_by": null,
    "id": null
  }
]
```
