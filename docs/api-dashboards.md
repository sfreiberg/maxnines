# Dashboards API

Everyone signed in shares dashboards. A widget sits on a grid 12 columns wide, and
asks one question, using the same `metric`, `calculation`, `group_by` and `filter` as
`GET /api/v1/query`. A widget's filter can also use the dashboard's
[variables](#get-or-update-variables), as terms like `$host`.

| Widget field | Meaning |
| --- | --- |
| `title` | What it's called. Empty uses the metric's name. |
| `kind` | `chart`, `number` or `table`. Defaults to `chart`. A number always combines everything. |
| `x`, `y`, `w`, `h` | Where it sits, in grid cells. Defaults to the top left, 6 wide and 4 high. |

## List dashboards

`GET /api/v1/dashboards`

Each dashboard's `id`, `name` and how many `widgets` it has, sorted by name.

## Add a dashboard

`POST /api/v1/dashboards`

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -d '{"name": "Fleet"}' "$MAXNINES_URL/api/v1/dashboards"
```

## Get a dashboard

`GET /api/v1/dashboards/{id}`

The dashboard with its `variables` and its `widgets`, from the top of the page down.

## Rename a dashboard

`PUT /api/v1/dashboards/{id}`

Takes a `name`.

## Delete a dashboard

`DELETE /api/v1/dashboards/{id}`

Deletes its widgets too.

## Add a widget

`POST /api/v1/dashboards/{id}/widgets`

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -d '{"metric": "cpu.usage", "calculation": "avg", "group_by": "host", "filter": "os=linux"}' \
  "$MAXNINES_URL/api/v1/dashboards/1/widgets"
```

## Update or delete a widget

`PUT /api/v1/dashboards/{id}/widgets/{widget}`

`DELETE /api/v1/dashboards/{id}/widgets/{widget}`

Changing a widget replaces all of it, including where it sits.

## Move widgets

`PUT /api/v1/dashboards/{id}/layout`

Takes a list of widgets' `id`, `x`, `y`, `w` and `h`, and saves them together.

## Get what a widget shows

`GET /api/v1/dashboards/{id}/widgets/{widget}`

The widget's answer, as `GET /api/v1/query` gives it, with its `title`, its `kind`
and its `filter` with variables filled in. `from_ms` and `to_ms` pick the time, and
default to the last hour. Each variable is picked with `var-<name>`, as the
dashboard's address does: a value that isn't offered is the same as none, which is
the first host for a host variable and every value for a fact. A host
variable with no host to offer is refused with 422.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/dashboards/1/widgets/2?var-host=5e8e7eb8dd45b90e77472cee36541d9b"
```

## Get or update variables

`GET /api/v1/dashboards/{id}/variables`

`PUT /api/v1/dashboards/{id}/variables`

A dashboard has up to 10 variables, each a picker at the top of the page. Getting
them adds the `choices` each one offers now, each with a `value` and a `label`.
Saving replaces the whole list, in order, and is refused while a widget uses a
variable that would be gone.

| Field | Meaning |
| --- | --- |
| `name` | Written as `$name` in a widget's filter or title. Letters, digits and `_`, starting with a letter, up to 32. |
| `label` | What the picker is called. Empty uses the name. |
| `kind` | `host` picks one host. `fact` picks a value of a fact, or all of them. |
| `fact` | Which fact's values a `fact` variable offers. |
| `filter` | Which hosts it offers, or whose values it offers. Empty for every host. |

```sh
curl -X PUT -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -d '[{"name": "host", "label": "Host", "kind": "host", "filter": "os=windows"}]' \
  "$MAXNINES_URL/api/v1/dashboards/1/variables"
```
