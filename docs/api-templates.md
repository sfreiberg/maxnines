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
| `origin` | `built_in` for one that comes with MaxNines, `imported`, or `own` |
| `enabled` | Whether it's on. Turning it off turns off its alerts |
| `enabled_choice` | For a built-in or imported one, what you chose, `true` or `false`, or `null` while it follows what the template ships, which a newer version can change |
| `target` | What it runs for: `{"kind": "database", "value": "postgres"}`, `service`, or `os` with a list of systems, or `null` for every host |
| `created_at`, `updated_at` | When it was added, and last changed |
| `upgraded_at` | When a newer version last changed a built-in or imported one, or `null` |
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
    "origin": "built_in",
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

A template's rule has a `template` field saying so: the template's `id` and `key`, the
`alert`'s key, `replaces_id`, which for your own copy is the built-in rule it's used in place of,
`enabled_choice`, what you chose for a built-in or imported template's own rule, or
`null` while it follows the template,
`template_enabled`, `waits_for_discovery`, true for an alert with `when` or `since`,
which pick what it's for by what the template's discovery finds, and which isn't
checked until that's kept, and `original_changed_at`, when an upgrade last changed the
built-in rule under a copy.

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

## Import a template

`POST /api/v1/templates/import`

Imports the template in `hcl`, as **Import** on the Templates page does. One with a key
that's new is added, with `201`; one with the key of a template imported before
replaces it, leaving alone your copies of its alerts and what's turned off, with `200`.
The answer has its `id` and the `outcome`: `added`, `updated`, or `unchanged` when it
says what's there already. A key or name of a built-in template, or the key of one of
your own, gives `422`, as anything wrong with the template does.

With `"dry_run": true` nothing is saved, and the answer is what importing would do:
the `outcome`, or `null` with the `problems` stopping it; its `key`, `name`,
`description` and `target` in words; its `metrics` and `alerts`; every statement of
`sql` it would run, by query, with each version's fills filled in; the `counters` it
would read; and for an update, the `changes`, a part to a line.

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  --data "$(jq -n --rawfile hcl myapp.hcl '{hcl: $hcl, dry_run: true}')" \
  "$MAXNINES_URL/api/v1/templates/import"
```

```json
{ "id": 3, "outcome": "added" }
```

An imported template is deleted as one of your own is.

## Export a template

`GET /api/v1/templates/{id}/export`

Any template as HCL, written out from its parts, as text rather than JSON, ready to
import somewhere else.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/templates/1/export" > host.hcl
```

## Update a template

`PUT /api/v1/templates/{id}`

Replaces a template of your own with the HCL in `hcl`. The alerts it still has, by their
keys, keep their rules, with who each tells. The rules of alerts it no longer has are
deleted.

## Delete a template

`DELETE /api/v1/templates/{id}`

Deletes a template of your own, or an imported one, and its alert rules, as [deleting a
rule](api-alert-rules.md#delete-an-alert-rule) does.

## Turn a template on or off

`POST /api/v1/templates/{id}/enable` and `POST /api/v1/templates/{id}/disable`

For a built-in or imported template this is your choice, which newer versions leave
alone. `POST /api/v1/templates/{id}/follow` forgets it, so the template is on or off as
it comes again.

## Change one of a template's alerts

`PUT /api/v1/templates/{id}/alerts/{key}`

The body is the whole rule, as for [updating an alert rule](api-alert-rules.md#update-an-alert-rule),
which does the same. Its conditions can use the template's own metrics by their short
names, and it can't have a calculation.

For a built-in or imported template, the first change makes your own copy of the rule, with an `id`
of its own, which is checked in place of the built-in one from then on, and later
changes update the copy. Its open alerts, silences and maintenance windows move to the
copy, so an alert that's open stays the same alert and nobody is told again. A body
that differs from the built-in rule only in `enabled` makes no copy: it's kept as your
choice, in `enabled_choice`. For a template of your own, the rule
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

Deletes your copy of a built-in or imported template's alert, as deleting the copy as an
[alert rule](api-alert-rules.md#delete-an-alert-rule) does, so the template's own rule
is checked again, taking the copy's open alerts, silences and maintenance windows with
it. It also forgets whether you chose the alert on or off. `404` if there's neither.

## What an upgrade changed

`GET /api/v1/templates/upgrades` gives the names of the built-in templates an upgrade
changed whose notice admins haven't dismissed, each saying which alerts you have copies
of that it changed, and
`POST /api/v1/templates/upgrades/dismiss` dismisses it. Both need an admin.

```json
{ "templates": ["Host"] }
```
