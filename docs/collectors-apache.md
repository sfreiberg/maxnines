# Apache

The `apache` collector reads Apache's own status page, `mod_status`, which gives
requests a second, traffic and how busy its workers are from a single request.

## Turning it on

1. **On the web server**, enable `mod_status`. Debian and Ubuntu do this already, and
   only let the host itself see the page, as it should be.
2. **In MaxNines**, turn on `apache` in a config rule, under **Collectors**. It reads
   `http://localhost/server-status?auto` unless the rule lists other pages under
   **Apache status pages**, one to a line, which also turns it on.

Keep the page limited to the host itself. Addresses with a username or password in
them aren't accepted, so they never show up on the rules pages. The agent reads each
page every sample, and gives up on one after 10 seconds.

Requests and traffic need `ExtendedStatus`, which is on by default, and connections
are only counted by the event MPM.

## What's reported

Each metric has a series for each page, named by its address without the query, such
as `http://localhost/server-status`.

| Metric | Unit | Series | What it is |
| --- | --- | --- | --- |
| `apache.up` | 1 or 0 | Each page | Whether the status page answered |
| `apache.requests` | A second | Each page | Requests served |
| `apache.traffic` | Bytes a second | Each page | What it sent |
| `apache.worker_usage` | % | Each page | Workers busy, of every worker it could start. Near 100% means requests are about to queue |
| `apache.busy_workers` | Number | Each page | Workers handling a request |
| `apache.idle_workers` | Number | Each page | Workers waiting for one |
| `apache.connections` | Number | Each page | Open connections. The event MPM only |
| `apache.cpu_load` | % | Each page | The CPU Apache's processes are using |
| `apache.uptime` | Seconds | Each page | How long since Apache started |

Running totals are turned into rates between one read and the next, so a page that
stops answering starts afresh when it's back, rather than counting the gap as one
burst.
