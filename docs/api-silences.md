# Silences API

While a silence runs, alerts it covers still fire and show, but nobody is notified. If
one is still firing when the silence ends, its notifications go out then. Anyone who was
already told about an alert still hears when it ends.

| Field | Meaning |
|---|---|
| `rule_id` | The alert rule it covers. Leave it out for every rule. |
| `filter` | Which hosts it covers, written as in [Filters](api-filters.md). Leave it out for every host. Alerts about a group of hosts have no single host, so a filter leaves them out. |
| `reason` | Why, which is required. |
| `duration_secs` | How long it lasts from now, up to 30 days. |

Deleting a rule deletes its silences that haven't ended. Ones that have ended stay, still
naming the rule.

**Start maintenance** on a host's page is a silence with no `rule_id` and the filter
`id=` followed by the host ID, so the same request does it through the API:

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"filter": "id=7f3c2a9e5b1d4c6a", "reason": "Rebooting", "duration_secs": 3600}' \
  "$MAXNINES_URL/api/v1/silences"
```

## List silences

`GET /api/v1/silences`

Everything running, and the latest 200 that have ended.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" "$MAXNINES_URL/api/v1/silences"
```

```json
{
  "active": [
    {
      "id": 3,
      "rule_id": null,
      "filter": "hostname=db*",
      "reason": "Upgrading Postgres",
      "created_by": "you@example.com",
      "starts_ms": 1793940279545,
      "ends_ms": 1793947479545
    }
  ],
  "ended": []
}
```

## Start a silence

`POST /api/v1/silences`

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"filter": "hostname=db*", "reason": "Upgrading Postgres", "duration_secs": 7200}' \
  "$MAXNINES_URL/api/v1/silences"
```

Returns `201` with the new `id`.

## Get a silence

`GET /api/v1/silences/{id}`

## End a silence

`POST /api/v1/silences/{id}/end`

Ends it now, and keeps it in the list of ended silences. Returns `204`, or `404` if it
isn't running.
