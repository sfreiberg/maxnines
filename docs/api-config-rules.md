# Config rules API

Config rules decide what each host's agent monitors. Every rule matching a host applies,
lowest priority first, so higher priorities win.

| Field | Description |
| --- | --- |
| `name` | Required |
| `priority` | Required. Higher priorities apply later |
| `condition` | A [CEL](https://cel.dev) expression over `facts`. Empty matches every host |
| `enabled` | Defaults to `true` |
| `settings` | Required. What to apply, as below |

| Setting | Description |
| --- | --- |
| `interval_secs` | How often agents send a sample |
| `facts_interval_secs` | How often agents report their facts |
| `collectors` | What to collect, by name, each with `enabled` and the options below |

| Collector option | For | Description |
| --- | --- | --- |
| `mount_points` | `disk` | Only these disks, even ones left out by default, like disk images |
| `names` | `processes`, `services`, `custom`, `counters`, `openmetrics` | What to watch. Custom metrics must be defined in the agent's own config, and counters are Windows performance counter paths, such as `\Memory\Available MBytes`. For `openmetrics` they're the metrics to keep, with `*` and `?` for anything, and leaving it out keeps them all |
| `paths` | `files` | The files and folders to watch |
| `checks` | `checks` | What to try reaching, as in [remote checks](api-remote-checks.md), each with its own `interval_secs` if it should run less often than every sample |
| `urls` | `apache`, `nginx`, `php_fpm`, `openmetrics` | The status pages to read. Leave it out for the usual page on the host itself. For `openmetrics` they're the [metrics pages](openmetrics.md) to read, which have no usual address |

The collectors are `apache`, `checks`, `containers`, `counters`, `cpu`, `custom`, `disk`, `files`, `host`,
`memory`, `network`, `nginx`, `openmetrics`, `php_fpm`, `processes`, `sensors`, `services`,
`system` and `top_processes`.

## List config rules

`GET /api/v1/rules`

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" "$MAXNINES_URL/api/v1/rules"
```

## Get a config rule

`GET /api/v1/rules/{id}`

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" "$MAXNINES_URL/api/v1/rules/1"
```

```json
{
  "id": 1,
  "name": "Default",
  "priority": 0,
  "condition": null,
  "enabled": true,
  "settings": {
    "interval_secs": 15,
    "facts_interval_secs": 3600,
    "collectors": { "cpu": { "enabled": true } }
  }
}
```

## Preview a config rule

`POST /api/v1/rules/preview`

Shows what saving a rule would do, without saving it. Takes the same body as creating
one, with `?id=` to try it in place of a saved rule.

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "Slower", "priority": 10, "settings": {"interval_secs": 60}}' \
  "$MAXNINES_URL/api/v1/rules/preview"
```

```json
{
  "enabled": true,
  "total": 1,
  "matching": 1,
  "changing": 1,
  "hosts": [
    {
      "hostname": "web-1",
      "online": true,
      "matches": true,
      "changes": ["Sample interval: 15s → 60s"],
      "note": null
    }
  ],
  "hidden": 0
}
```

## Add a config rule

`POST /api/v1/rules`

Agents get the change straight away. Gives back the rule's `id`.

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Slower on Linux",
    "priority": 10,
    "condition": "facts.os.family == \"linux\"",
    "settings": {"interval_secs": 60}
  }' \
  "$MAXNINES_URL/api/v1/rules"
```

```json
{ "id": 2 }
```

## Update a config rule

`PUT /api/v1/rules/{id}`

Replaces the whole rule.

```sh
curl -X PUT -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Slower on Linux",
    "priority": 10,
    "condition": "facts.os.family == \"linux\"",
    "settings": {"interval_secs": 30}
  }' \
  "$MAXNINES_URL/api/v1/rules/2"
```

## Delete a config rule

`DELETE /api/v1/rules/{id}`

```sh
curl -X DELETE -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/rules/2"
```
