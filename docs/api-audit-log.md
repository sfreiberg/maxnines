# Audit log API

Who changed what, and who signed in, as on the Audit log page in Settings. See
[Audit log](audit-log.md) for what's recorded.

## List the audit log

`GET /api/v1/audit-log`

Newest first.

| Parameter | Description |
| --- | --- |
| `before` | Only entries older than the one with this `id`. Pass the last `id` of a page to get the next |
| `limit` | How many entries, from 1 to 1000. 100 if left out |

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/audit-log?limit=2"
```

```json
[
  {
    "id": 42,
    "time_ms": 1794180214377,
    "actor": { "kind": "person", "id": "1", "name": "sam@example.com" },
    "via": { "kind": "api_key", "id": "3", "name": "Deploy job" },
    "source": "192.168.0.20",
    "action": "changed",
    "subject": { "kind": "alert_rule", "id": "3", "name": "Disk filling up" },
    "changes": [
      { "field": "threshold", "before": 90.0, "after": 95.0 },
      { "field": "channels", "before": ["Ops email"], "after": ["Ops email", "PagerDuty"] }
    ]
  },
  {
    "id": 41,
    "time_ms": 1794180190012,
    "actor": { "kind": "person", "id": "1", "name": "sam@example.com" },
    "via": null,
    "source": "192.168.0.20",
    "action": "signed_in",
    "subject": { "kind": "user", "id": "1", "name": "sam@example.com" },
    "changes": []
  }
]
```

`actor.kind` is one of:

| Kind | Who |
| --- | --- |
| `person` | A user. `name` is their email address |
| `command_line` | A `maxnines-server` command run on the server's host |
| `maxnines` | The server itself, like a registration rule approving a host |
| `nobody` | Someone who isn't signed in, like a failed sign in |

`via` says how a person acted when it wasn't on the pages: `api_key`, with the key's
`id` and `name`, or `slack`, for an alert's buttons in Slack, matched to the user by
email address.

`action` is `created`, `changed`, `deleted`, `signed_in`, `sign_in_failed`,
`signed_out`, `new_setup_link`, `acknowledged`, `unacknowledged` or `ran_action`,
which is someone running an action on a host. `subject.kind` is
`user`, `api_key`, `host`, `config_rule`, `alert_rule`, `notification_channel`,
`alert`, `silence`, `maintenance_window`, `remote_check`, `location_rule`,
`dashboard`, `annotation` or `setting`. Names are as they were at the time.

`source` is the address the request came from, which is empty for changes that
didn't come from a request. Behind a proxy, it's the address the proxy passed on, if
the proxy is in `trusted_proxies`.

In `changes`, a field that had no value leaves out `before`, and one that has none
now leaves out `after`. Nested fields are named with dots, like `settings.disk.interval`.
Secrets have `"secret": true` and say `"hidden"` in place of their values.
