# Config rules API

Config rules decide what each host's agent monitors. Every rule matching a host applies,
lowest priority first, so higher priorities win.

| Field | Description |
| --- | --- |
| `name` | Required. No two rules can have the same name, ignoring case, or saving gives `422` |
| `priority` | Required. Higher priorities apply later |
| `applies_to` | Which hosts, as a [CEL](https://cel.dev) expression over `facts`. Empty matches every host |
| `operating_systems` | The systems it's for, from `freebsd`, `linux`, `macos` and `windows`, which `facts.os.family` has to be one of as well as `applies_to` matching. Empty or left out for every system |
| `enabled` | Defaults to `true` |
| `settings` | Required. What to apply, as below |
| `built_in` | Given back, never set: which built-in rule it is, such as `macos`, or `null` for one of your own |

Built-in rules come with MaxNines, and upgrades change them. See
[Built-in rules](agents.md#built-in-rules). Only `enabled` can change on one, so an update
has to give everything else as it is, and one can't be deleted. Either gives `422`.
Rules of the same priority apply built-in rules first.

| Setting | Description |
| --- | --- |
| `interval_secs` | How often agents send a sample |
| `facts_interval_secs` | How often agents report their facts |
| `collectors` | What to collect, by name, each with `enabled` and the options below |

| Collector option | For | Description |
| --- | --- | --- |
| `mount_points` | `disk` | Only these disks, even ones left out by default, like disk images |
| `names` | `processes`, `services`, `custom`, `commands`, `counters`, `openmetrics` | What to watch. Custom metrics and [check commands](check-commands.md) must be defined in the agent's own config, and counters are Windows performance counter paths, such as `\Memory\Available MBytes`. For `openmetrics` they're the metrics to keep, with `*` and `?` for anything and `!` in front to leave one out, and leaving it out keeps them all |
| `paths` | `files` | The files and folders to watch |
| `checks` | `checks` | What to try reaching, as in [remote checks](api-remote-checks.md), each with its own `interval_secs` if it should run less often than every sample. These never sign in, and can't be heartbeats, which only the server watches |
| `local_pages` | `openmetrics` | Pages the agent's own config defines, which sign in, by name. The agent lists the ones it has in its `agent.openmetrics` fact. See [pages that need signing in](openmetrics.md#pages-that-need-signing-in) |
| `databases` | `databases` | Databases the agent's own config defines, by name, each with any extras to read, as `{"name": "orders", "extras": ["sizes"]}`. The agent lists the ones it has, each with its kind, in its `agent.databases` fact, as `{"orders": "postgres"}`. PostgreSQL databases needn't be listed, as the built-in PostgreSQL template reads every one. See [database stats](database-stats.md) |
| `local_checks` | `checks` | Checks the agent's own config defines, which sign in, as `{"name": "bastion", "interval_secs": 300, "timeout_secs": 5}` with the times optional. The agent lists the ones it has in its `agent.checks` fact. See [signing in on an agent](checks.md#on-an-agent) |
| `urls` | `apache`, `nginx`, `php_fpm`, `openmetrics` | The status pages to read. Leave it out for the usual page on the host itself. For `openmetrics` they're the [metrics pages](openmetrics.md) to read, which have no usual address |

The collectors are `apache`, `checks`, `containers`, `counters`, `cpu`, `custom`, `databases`, `disk`, `files`, `gpu`, `host`,
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
  "built_in": "default",
  "name": "Default",
  "priority": 0,
  "applies_to": null,
  "operating_systems": [],
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
    "operating_systems": ["linux"],
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
    "operating_systems": ["linux"],
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
