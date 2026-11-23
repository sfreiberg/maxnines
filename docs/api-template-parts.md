# Template parts API

A [template's](api-templates.md) discover blocks, queries and counters blocks can be
changed and turned on or off on their own, as on its page, and what each template
reads on each host, and what's going wrong there, can be read.

## Change a template's discover block, query or counters block

`GET`, `PUT` and `DELETE /api/v1/templates/{id}/discover/{key}`, `/queries/{key}` and `/counters/{key}`

`GET` gives the part as it runs, field by field as `template` has it, with `copied`,
`enabled_choice` and `original_changed_at` as in `choices`, and for your own copy, the
template's own as `template_part`.

`PUT` changes it. The body is the part as `GET` gives it; its key is the address's,
whatever the body says, and whether it's on isn't changed here. It's checked in the
template, in place of what it changes, so a column one of the template's alerts uses
can't go, and everything wrong is in the `error`. For a built-in or imported
template, the first change makes your own copy, used in place of the template's own
from then on, which newer versions leave alone; later changes update the copy, and a
body that says what the template's own does deletes it. For a template of your own,
the template itself is changed. Gives back `204`.

```sh
curl -X PUT -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"sql": "SELECT count(*) AS tills FROM tills WHERE open", "interval": "1m", "enabled": true}' \
  "$MAXNINES_URL/api/v1/templates/4/queries/tills"
```

`DELETE`, or `POST …/reset`, puts a built-in or imported template's part back: it
deletes your copy and forgets whether you chose it on or off. `404` if there's
neither.

`POST /api/v1/templates/{id}/queries/{key}/enable` and `…/disable`, and the same for
`counters`, turn a query or counters block on or off: your choice for a built-in or
imported template, which newer versions leave alone, or the template itself for one of
your own. A discover block can't be turned off, as what it finds is waited on.

## Where a template runs

`GET /api/v1/templates/{id}/runs`

Each host the template is on and for, and each database it reads there, or the host
itself for a template that runs once on it: what its agent, or the server for a host
with no agent, is sent to read now. Those with anything going wrong come first.

| Field | Description |
| --- | --- |
| `host_id`, `hostname` | The host |
| `template_id`, `template_key`, `template_name` | The template |
| `database` | The database it reads, by its name in the agent's config or the database check's name, or `null` for the host itself |
| `found` | What its discovery last found there, by name, or `{}` before it's found anything |
| `discover`, `queries`, `counters` | The keys of its discover blocks, queries and counters blocks read there now, as what discovery found picks them |
| `errors` | What's going wrong there: each with its `part`, `connecting`, `account`, or a part such as `query sessions`, the `message` the database or Windows gave, and `since`, when it first said that |

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" "$MAXNINES_URL/api/v1/templates/4/runs"
```

`GET /api/v1/hosts/{id}/templates` gives the same for every template on one host.

```json
[
  {
    "host_id": "3f2a1c9d…",
    "hostname": "orders-db",
    "template_id": 4,
    "template_key": "pg",
    "template_name": "PostgreSQL",
    "database": "orders",
    "found": { "version": "16.4", "role": "primary" },
    "discover": ["server", "role"],
    "queries": ["sessions", "throughput"],
    "counters": [],
    "errors": [
      {
        "part": "query sessions",
        "message": "permission denied for view pg_stat_activity",
        "since": "2026-11-22T09:00:00.000Z"
      }
    ]
  }
]
```
