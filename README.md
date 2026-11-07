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

## HTTPS

Without HTTPS, passwords and agent data cross the network unencrypted, and Chrome won't
offer to install the app. Choose one of these in `server.hcl`:

| Choice | Use it when | In `server.hcl` |
| --- | --- | --- |
| No TLS | A proxy handles HTTPS, or it's a small trusted network | No `tls` block |
| Your own certificate | You already manage certificates, or use a private authority | `tls` block with files |
| Automatic certificates | The server can be reached from the internet | `tls` block with `acme` |

Everything stays on the one port in `listen`. There's no redirect from `http://` on that
port, as it only speaks HTTPS once TLS is on. Binding to port 443 usually needs extra
rights, which depends on how you run the server.

### No TLS

Leave the `tls` block out. Behind a proxy that handles HTTPS, set `public_url` to the
address agents use, and list the proxy so client addresses are read correctly:

```hcl
listen          = "127.0.0.1:9000"
public_url      = "wss://maxnines.example.com/ws"
trusted_proxies = ["127.0.0.1"]
```

### Your own certificate

```hcl
listen     = "0.0.0.0:443"
public_url = "wss://maxnines.example.com/ws"

tls {
  certificate_file = "/etc/maxnines/server.crt"
  key_file         = "/etc/maxnines/server.key"

  # Only for a certificate from a private authority.
  # ca_file = "/etc/maxnines/ca.pem"
}
```

| Setting | Required | Meaning |
| --- | --- | --- |
| `certificate_file` | Yes | The certificate in PEM format, followed by any intermediates |
| `key_file` | Yes | Its private key in PEM format, without a passphrase |
| `ca_file` | For a private authority | Who signed it, for this server's own command line tools |

- `public_url` has to start with `wss://`, and its name has to be on the certificate.
- Replace the files to renew, and the server picks them up within an hour with no
  restart. If a new file can't be read, the old certificate stays in use and it's logged.
- Keep the key readable only by the account running the server.

### Automatic certificates

```hcl
listen     = "0.0.0.0:443"
public_url = "wss://maxnines.example.com/ws"

tls {
  acme {
    domains   = ["maxnines.example.com"]
    email     = "you@example.com"
    cache_dir = "/var/lib/maxnines/acme"
  }
}
```

| Setting | Required | Meaning |
| --- | --- | --- |
| `domains` | Yes | The names to get a certificate for. Each has to point at this server |
| `cache_dir` | Yes | Keeps the certificate and account key. Created if needed |
| `email` | No | Who the certificate service can contact |
| `directory` | No | The ACME service. Defaults to Let's Encrypt |
| `ca_file` | No | Who to trust for a private ACME service |

- **Port 443 has to reach this server from the internet.** Let's Encrypt proves you
  control the name by connecting to it there, on the same port as everything else, so
  port 80 isn't needed. A firewall or router can forward 443 to another `listen` port.
- The first start takes a moment while the certificate is issued, and renewal is
  automatic.
- `cache_dir` has to survive restarts and stay private, because it holds the account key
  and Let's Encrypt limits how many certificates it will issue. Keep it out of synced
  folders.
- While setting up, use the staging service so mistakes don't use up those limits. Its
  certificates aren't trusted, so switch back and clear `cache_dir` when it works:

  ```hcl
  directory = "https://acme-staging-v02.api.letsencrypt.org/directory"
  ```

### Agents

Agents check the server's certificate. Point them at the `wss://` address:

```hcl
server {
  url = "wss://maxnines.example.com/ws"
}
```

For a certificate from a private authority, tell them who to trust with
`ca_file = "/etc/maxnines/ca.pem"` in that block. An agent that doesn't trust the
certificate logs `invalid peer certificate` and keeps trying.

### Command line tools

With a `tls` block, `maxnines-server agents`, `users` and `api-keys` connect to
`public_url` and check the certificate like anything else. That name has to work from
the server itself. If they report `invalid peer certificate: UnknownIssuer`, the
certificate is from a private authority and the `tls` block needs its `ca_file`.

### Checking it works

```sh
curl https://maxnines.example.com/health
```

## Metrics databases

`server.hcl` chooses where metrics are kept, and everything else works the same on
either.

- **DuckDB** is the default. It's built into the server, so there's nothing else to run.
  Use it for smaller installations.
- **ClickHouse** runs as a server of its own. Use it for bigger fleets. Point the
  `metrics "clickhouse"` block at it, and the database and tables are created for you.

Nothing moves between them, so changing later starts metrics afresh.

## On-call services

Alerts can open incidents in PagerDuty, AlertOps and SIGNL4, and close them again when
they resolve. Each alert is one incident.

Set them up in the web interface: go to Settings, then notification channels, add a
channel of that type, then add the channel to the alert rules that should use it. The
form has these steps too.

Sending a test opens an incident and closes it straight away, which can notify whoever
is on call. Keys and URLs work like passwords, so they can't be read back once saved.

### PagerDuty

1. In PagerDuty, open the service that should get the alerts, then its Integrations tab.
2. Add an integration, choose Events API V2, and copy its Integration Key.
3. Use that key as the channel's destination.

A rule's severity carries over.

### AlertOps

AlertOps lets you choose what each field in an incoming alert means, so there's a little
mapping to do. Custom integrations may depend on your AlertOps plan.

1. In AlertOps, go to Configuration, then Integrations. Under Inbound Integrations,
   choose API and add one using the Custom card, with the escalation policy you want.
2. Open its rules for opening and closing an alert. Keep the method as POST and the
   content as JSON.
3. Paste this in as the sample data:

   ```json
   {
     "alert_id": "maxnines-test",
     "host": "MaxNines",
     "link": "https://maxnines.example.com/alerts",
     "message": "This is a test notification from MaxNines.",
     "severity": "info",
     "status": "open",
     "subject": "Test"
   }
   ```

4. Map `alert_id` to both Source Name and Source Id, so each alert stays separate. A
   fixed Source Name would merge them into one.
5. Map `status` as the status field. Open an alert when it contains `open`, and close it
   when it contains `closed`.
6. Map `subject` and `message` to the text fields you want, and `link` to Source URL.
7. Leave the authorization header off, then copy the integration's URL. Do this last, as
   changing its source changes the URL.
8. Use that URL as the channel's destination.

### SIGNL4

Use `https://connect.signl4.com/webhook/` followed by your SIGNL4 team or integration
secret as the channel's destination.

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
