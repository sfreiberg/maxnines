# Templates API

[Templates](templates.md) are sent and given back as HCL. The server keeps a template as
its parts, not as text, so comments and layout in HCL you send aren't kept, and the HCL
given back is written out from the parts. The built-in ones can be turned on and off,
and their alerts changed by making your own copy of one, but not changed or deleted
themselves, which gives `422`.

| Field | Description |
| --- | --- |
| `id` | Given back |
| `key` | The template's key, which starts its metrics' names |
| `name`, `description` | From the HCL |
| `built_in` | Whether it comes with MaxNines |
| `enabled` | Whether it's on. Turning it off turns off its alerts |
| `target` | What it runs for: `{"kind": "database", "value": "postgres"}`, `service`, or `os` with a list of systems, or `null` for every host |
| `created_at`, `updated_at` | When it was added, and last changed |
| `upgraded_at` | When an upgrade last changed a built-in one, or `null` |
| `changed` | Whether you have your own copy of any of its alerts |

## List templates

`GET /api/v1/templates`

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" "$MAXNINES_URL/api/v1/templates"
```

```json
[
  {
    "id": 1,
    "key": "host",
    "name": "Host",
    "description": "Whether each host is online and sending metrics, and its disks, clock, services and containers.",
    "built_in": true,
    "enabled": true,
    "target": null,
    "created_at": "2026-11-21T09:00:00.000Z",
    "updated_at": "2026-11-21T09:00:00.000Z",
    "upgraded_at": null,
    "changed": false
  }
]
```

## Get a template

`GET /api/v1/templates/{id}`

Everything listed, with:

| Field | Description |
| --- | --- |
| `hcl` | The template, written out from its parts |
| `template` | The template read, field by field, as the HCL has it |
| `metrics` | Its own metrics, each with its full `name`, its `kind`, which is `number`, `seconds`, `flag` for yes or no, or `unknown` for a column whose type only the database knows, and its `labels` |
| `alerts` | Each of its alerts, by `key`, with the `rule` in use, as [alert rules](api-alert-rules.md) are given, and where that's your own copy of a built-in template's, the built-in one as `built_in_rule`, `null` otherwise |

A template's rule has a `template` field saying so: the template's `id`, the `alert`'s
key, `replaces_id`, which for your own copy is the built-in rule it's used in place of,
`template_enabled`, `waits_for_agents`, true while it needs what only agents running
the template would send, which leaves it unchecked, and `original_changed_at`, when an
upgrade last changed the built-in rule under a copy.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" "$MAXNINES_URL/api/v1/templates/1"
```

## Add a template

`POST /api/v1/templates`

The body holds the template's HCL as `hcl`. It's checked as the Templates page checks
it, and everything wrong with it is in the `error`, naming the template, block and
field of each: `template "myapp", alert "busy", warning: there's no metric called
conections: did you mean connections?`. A key or name another template has, or an
alert named as another alert rule is, also gives `422`.

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  --data "$(jq -n --rawfile hcl myapp.hcl '{hcl: $hcl}')" \
  "$MAXNINES_URL/api/v1/templates"
```

```json
{ "id": 2 }
```

## Update a template

`PUT /api/v1/templates/{id}`

Replaces a template of your own with the HCL in `hcl`. The alerts it still has, by their
keys, keep their rules, with who each tells. The rules of alerts it no longer has are
deleted.

## Delete a template

`DELETE /api/v1/templates/{id}`

Deletes a template of your own and its alert rules, as [deleting a
rule](api-alert-rules.md#delete-an-alert-rule) does.

## Turn a template on or off

`POST /api/v1/templates/{id}/enable` and `POST /api/v1/templates/{id}/disable`

Turning a built-in template off lasts through upgrades.

## Change one of a template's alerts

`PUT /api/v1/templates/{id}/alerts/{key}`

The body is the whole rule, as for [updating an alert rule](api-alert-rules.md#update-an-alert-rule),
which does the same. Its conditions can use the template's own metrics by their short
names, and it can't have a calculation.

For a built-in template, the first change makes your own copy of the rule, with an `id`
of its own, which is checked in place of the built-in one from then on, and later
changes update the copy. A body that differs from the built-in rule only in `enabled`
sets that on the built-in rule and makes no copy. For a template of your own, the rule
itself, and so the template, is changed.

```sh
curl -X PUT -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Host offline",
    "critical": "!online",
    "summary": "{{ hostname }} is offline",
    "resolved_summary": "{{ hostname }} is back online",
    "for_secs": 120,
    "all_channels": true
  }' \
  "$MAXNINES_URL/api/v1/templates/1/alerts/offline"
```

## Put one of a template's alerts back

`DELETE /api/v1/templates/{id}/alerts/{key}`, or `POST /api/v1/templates/{id}/alerts/{key}/reset`

Deletes your copy of a built-in template's alert, as deleting the copy as an
[alert rule](api-alert-rules.md#delete-an-alert-rule) does, so the built-in rule is
checked again. `404` if there's no copy.

## What an upgrade changed

`GET /api/v1/templates/upgrades` gives the names of the built-in templates an upgrade
changed whose notice admins haven't dismissed, each saying which alerts you have copies
of that it changed, and
`POST /api/v1/templates/upgrades/dismiss` dismisses it. Both need an admin.

```json
{ "templates": ["Host"] }
```
