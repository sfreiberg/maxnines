# Health API

`GET /health` or `HEAD /health`

For load balancers and uptime monitors. It's at the top of the site rather than under
`/api/v1`, and needs no key. It answers `200` when everything works and `503` when
something doesn't, and says which part without giving any detail. Each check has two
seconds to answer. `HEAD` gives the same status with no body, for monitors that can only
send that.

| Check | What it means |
| --- | --- |
| `database` | The main database answers |
| `metrics` | The metrics database answers |
| `writer` | Samples can still be saved |
| `alerts` | Alert rules have run in the last minute |

```json
{
  "status": "ok",
  "checks": { "database": "ok", "metrics": "ok", "writer": "ok", "alerts": "ok" }
}
```
