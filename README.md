# MaxNines

MaxNines is fast, low-resource, open source monitoring software, written in Rust.
It's meant to be running and useful within minutes of installing it, with great
defaults instead of a pile of configuration.

![The overview, with every machine's health at a glance](docs/screenshots/overview.png)

![An agent's charts, updating live](docs/screenshots/charts.png)

## Goals

- **Fast and light.** A small agent that barely registers on the machines it
  watches, and a server that handles a large fleet on modest hardware.
- **Quick to set up.** Install the server, add agents, and see useful charts and
  alerts straight away.
- **Great defaults.** The things most people need to watch are covered out of the
  box, with sensible alerts, so configuration is for fine-tuning rather than
  getting started.
- **Open source and self-hosted.** It runs on your own machines and your data stays
  with you.

MaxNines is in early development and isn't ready for production use yet.

## Get in touch

If you'd like to help guide the project, we'd love to hear from you. What you need
from monitoring, what gets in your way today, and what you'd leave out are all
welcome and genuinely useful. Open an issue or start a discussion here on GitHub.

## Users

Nobody can sign up. Every page needs someone signed in, and people are only added by
someone already here, so a new server starts with the command line:

```sh
maxnines-server users create you@example.com "Your Name"
```

That prints a link for setting a password. It works once and lasts 7 days. After
that, add people on the Settings page, which gives you a link to send them. The same
command line can recover from a forgotten password with `users setup-link`.

Over plain `http://`, passwords cross the network unencrypted, so put anything beyond
a trusted network behind HTTPS.

## Running an agent by hand

There are no installers yet, so an agent is one file you copy to a machine and start
yourself. Build it with `cargo build --release -p maxnines-agent`, or for an Intel Mac
from an Apple Silicon one, add `--target x86_64-apple-darwin`.

Put `maxnines-agent` in a folder of its own, with an `agent.hcl` beside it that says
where the server is:

```hcl
server {
  url = "ws://your-server:9000/ws"
}

state_dir = "state"
```

The URL has to match the server's `public_url`. Use `wss://` for anything beyond a
trusted network. Everything else about what to monitor comes from the server, and
[`crates/agent/config/agent.hcl`](crates/agent/config/agent.hcl) explains the settings
an agent can have of its own.

Then start it:

```sh
./maxnines-agent
```

It creates a key in `state`, logs its agent ID, and waits to be approved. Approve it
on the Agents page, or on the server with:

```sh
maxnines-server agents approve <agent-id>
```

It starts reporting within a few seconds, and from then on it reconnects by itself.
It stops with Ctrl+C or when the terminal closes, so use `nohup` or `tmux` to keep it
running after you log out. Samples are kept in `state` while the server can't be
reached, and sent when it's back.

- **One key per machine.** Copy the program and `agent.hcl` to another machine, but
  never `state`. The key inside it is the agent's identity, so a copy looks like the
  same machine.
- **Upgrade the server first.** Older agents work with a newer server, but a newer
  agent may need things an older server doesn't have.
- **macOS and downloads:** a file that came through a browser or AirDrop is blocked
  until you run `xattr -d com.apple.quarantine maxnines-agent`.
- **Other commands:** `./maxnines-agent facts` prints what it reports about the
  machine, and `./maxnines-agent identity show` prints its ID once it's been started.
  Use `-c` to point any of them at a config file somewhere else.

## API

Everything the web pages can see and do is available as JSON under `/api/v1`, on the
same port as everything else. Make a key on the Settings page or from the command
line, and choose how long it lasts:

```sh
export MAXNINES_API_KEY=$(maxnines-server api-keys create "My script" --expires-in 30d)
curl -H "Authorization: Bearer $MAXNINES_API_KEY" http://localhost:9000/api/v1/agents
```

See the [API reference](docs/api.md) for everything it can do, with examples.

## Install as an app

MaxNines can run in its own window, with its own icon, and every page works the
same there.

- **Chrome and Edge:** open MaxNines, then choose Install from the address bar or
  the browser's menu. Browsers only offer this over HTTPS or on `localhost`, so a
  server on a plain `http://` address needs to be behind HTTPS first.
- **iPhone and iPad:** open MaxNines in Safari, tap Share, then Add to Home Screen.

## Load testing

`maxnines-loadtest` simulates a fleet of agents against a server and reports how it
held up, so you can size a server before depending on it. The agents are simulated
closely: the same handshake, timers, retries and sample shapes as real ones.

Run it against a test server, because simulated agents are approved and saved like
real ones.

```sh
export MAXNINES_API_KEY=$(maxnines-server api-keys create "Load test" --expires-in 1d)
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
