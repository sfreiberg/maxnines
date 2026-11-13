# Calculations API

## Ask about many hosts at once

`GET /api/v1/query`

Combines a metric across hosts, the same way dashboards do. Each series is averaged
within a moment first, so a host reporting more often doesn't count for more. Only
approved hosts count, and the server itself isn't one of them. Hosts are combined
over whole minutes, leaving out the one still filling up. A metric that measures several
things, like memory and swap, uses the first unless `group_by` is `series`.

| Parameter | Meaning |
| --- | --- |
| `metric` | Required. A name from `GET /api/v1/metrics`. |
| `calculation` | `avg`, `sum`, `min`, `max` or `count`, which is how many series are reporting. Defaults to `avg`. |
| `group_by` | What gets a line of its own: `nothing`, `host`, `series` or `fact:<name>`. Defaults to `nothing`. |
| `filter` | Which hosts, in the same form as the Hosts list, such as `os=linux hostname=web*`. Defaults to all of them. |
| `from_ms`, `to_ms` | The time range. Defaults to the last hour. |

The result has the same shape as a host's metric. The highest 100 lines are kept, and
`hidden` says how many more there were. A question that makes no sense gets a `422`.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/query?metric=cpu.usage&calculation=avg&group_by=fact:role"
```
