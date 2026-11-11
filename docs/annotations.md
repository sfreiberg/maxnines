# Annotations

A host's charts mark what happened to it, so a change in a graph can be matched to
what caused it. Each one is a dashed line down every chart, with a dot at the top to
hover over for when and what. The **Events** list under the charts has the same for
the range shown, newest first.

All of these together are the host's events. Annotations are the events people and
automations add; the server records the rest by itself.

| Kind | Where it comes from |
| --- | --- |
| **Deploy** and **Note** | Annotations, added by people or [through the API](api.md#annotations) |
| **Restart** | The server notices when a host's boot time moves on, even if it restarted while it couldn't reach the server |
| **Config change** | An agent applied a different config from its config rules, with which rules it came from |
| **Alert** and **Resolved** | An alert on the host starting and ending |
| **Update** | The agent's version, the operating system's version or the kernel changed |

## Adding an annotation

Under **Metrics > Annotations**, say what happened, choose Deploy or Note,
and give a filter for which hosts it's for, written as in the Hosts list, such as
`role=web`. Leave the filter empty for every host, and the time empty for now. The
list below has the last 30 days of them, and each can be deleted.

On a host's own metrics page, the form under its charts adds one for that host
alone, happening now.

A deploy script adds one through the API instead:

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"kind": "deploy", "title": "Shop v2.3", "detail": "Build 812", "filter": "role=web"}' \
  "$MAXNINES_URL/api/v1/annotations"
```

- **The filter is matched whenever a chart is drawn,** against each host as it is
  then. A web host added next week shows last week's deploy, and one that stops
  being `role=web` stops showing it. A filter that matches no host yet is fine.
- **`time_ms`** records something that happened earlier, up to a year back.
- **Adding and deleting annotations needs the responder role,** and both are kept in the
  [audit log](audit-log.md). What the server records itself isn't.
- **Deleting a host** deletes what was recorded for it alone. Annotations for many
  hosts stay.
