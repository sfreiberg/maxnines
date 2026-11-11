# Events

A machine's charts mark what happened to it, so a change in a graph can be matched to
what caused it. Each event is a dashed line down every chart, with a dot at the top to
hover over for when and what. The **Events** list under the charts has the same events
for the range shown, newest first.

| Kind | Where it comes from |
| --- | --- |
| **Deploy** and **Note** | Recorded by people, on a machine's page or [through the API](api.md#events) |
| **Restart** | The server notices when a machine's boot time moves on, even if it restarted while it couldn't reach the server |
| **Config change** | An agent applied a different config from its config rules, with which rules it came from |
| **Alert** and **Resolved** | An alert on the machine starting and ending |
| **Update** | The agent's version, the operating system's version or the kernel changed |

## Recording a deploy or a note

On a machine's metrics page, choose **Note** or **Deploy**, say what happened, and choose
**Add event**. It's marked at the time it's added, for that machine.

From a deploy script, record it through the API instead, for every machine a
[filter](api.md#filters) picks:

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"kind": "deploy", "title": "Shop v2.3", "detail": "Build 812", "filter": "role=web"}' \
  "$MAXNINES_URL/api/v1/events"
```

- The machines are those the filter picks when it's recorded, so a machine added later
  doesn't get it. Leave the filter out for every machine. A filter that picks none is
  refused.
- `time_ms` records something that happened earlier, up to a year back.
- Recording and deleting events needs the responder role. They're kept in the
  [audit log](audit-log.md), and what the server records itself isn't.
- Any event recorded, including a restart or config change the server noticed, can be
  deleted from the list on a machine's page.
