# Load testing

`maxnines-loadtest` simulates a fleet of agents against a server and reports how it
held up, so you can size a server before depending on it. The agents are simulated
closely: the same handshake, timers, retries and sample shapes as real ones.

Run it against a test server, because simulated agents are approved and saved like
real ones.

```sh
export MAXNINES_API_KEY=$(maxnines-server api-keys create "Load test" --user you@example.com --expires-in 1d)
maxnines-loadtest --url ws://localhost:9000/ws --agents 5000 --duration 15m
```

It prints a summary, writes `loadtest-report.html`, and exits with 1 if a check
failed. `--strict` fails on warnings as well, and `--json` also writes the results as
JSON. Run `maxnines-loadtest --help` for everything that can be adjusted, including:

| Option | What it does |
| --- | --- |
| `--agents`, `--duration`, `--interval` | How many agents, for how long, sending how often |
| `--ramp` | How long to spread agents connecting over, with `0s` for all at once |
| `--disks`, `--interfaces`, `--cores` | How big each sample is |
| `--churn` | Percent of agents reconnecting each minute |
| `--backlog` | Saved samples each agent starts with, as if after an outage |
| `--outage-at`, `--outage-for` | Drop every connection during the test |
| `--rule-change-at` | Send every agent a new config during the test |
| `--fact-changes`, `--facts-every` | How much facts change, and how often they're sent |
| `--hot-agents` | Percent of agents at 99% CPU, to set off alert rules you've made |
| `--viewers`, `--page-every` | People loading pages during the test |

Each simulated agent takes a connection on the machine running the test, so run it
from a separate machine to keep it from competing with the server. One address can
only make about 28,000 connections to a server.
