# Annotations API

Deploys, upgrades and notes, marked on the charts of the hosts their filter picks.
See [Annotations](annotations.md). Adding and deleting them needs the responder role.

| Field | Meaning |
|---|---|
| `kind` | `deploy` or `note`, which is the default. |
| `title` | What happened, which is required. Up to 200 characters. |
| `detail` | More about it, up to 2,000 characters. |
| `filter` | Which hosts, written as in [Filters](api-filters.md). Leave it out for every host. It's matched when the annotation is added, against the approved hosts there are then, and the annotation stays on those: a host added later doesn't show it, and one whose facts change keeps it. One that matches no host is refused with `422`. |

An annotation always happens when it's added: `occurred_at` is the time it was added,
and one can't be given.

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
  "occurred_at": "2026-11-06T04:44:39.545Z",
  "kind": "deploy",
  "title": "Shop v2.3",
  "detail": "Build 812",
  "filter": "role=web",
  "created_by": "deploy@example.com",
  "created_at": "2026-11-06T04:44:39.545Z"
}
```

## List annotations

`GET /api/v1/annotations`

Newest first. `from` and `to`, ISO 8601 times such as `2026-11-19T01:57:17Z`, choose the
period, both included, which is the last 7 days up to now unless given, and `limit` how many, which is 200 unless
given. `from` has to be before `to` and at most 366 days before it, and `limit` from 1 to
1,000, or the answer is `400`.

## Get an annotation

`GET /api/v1/annotations/{id}`

Returns `404` if there's no such annotation. What the server records about a host,
such as a restart, has an `id` in [the host's events](#get-a-hosts-events) but isn't an
annotation, so it can't be read or deleted here.

## Delete an annotation

`DELETE /api/v1/annotations/{id}`

Returns `204`, or `404` if there's no such annotation.

## Get a host's events

`GET /api/v1/hosts/{id}/events`

Everything that happened to one host, newest first, as its page shows them: the
annotations added for it, restarts, config changes, alerts starting
(`alert`) and ending (`resolved`), and updates. `from` and `to`, ISO 8601 times, choose
the period, both included, which is the last 24 hours up to now unless given, and `limit` how many, the newest,
which is 500 unless given. `from` has to be before `to` and at most 366 days before it,
and `limit` from 1 to 500, or the answer is `400`. Only what was recorded has an `id`,
and `created_by` is who added an annotation, or `null` for what the server worked out.

```json
[
  {
    "occurred_at": "2026-11-06T04:44:39.545Z",
    "kind": "restart",
    "title": "Host started",
    "detail": null,
    "created_by": null,
    "id": 15
  },
  {
    "occurred_at": "2026-11-06T03:44:45.969Z",
    "kind": "update",
    "title": "Agent updated to 0.1.0-alpha.3",
    "detail": "It was 0.1.0-alpha.2.",
    "created_by": null,
    "id": null
  }
]
```
