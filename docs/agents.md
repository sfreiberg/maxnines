# Running an agent

Without a package, an agent is one file you copy to a host and start yourself. On
Windows, use [the installer](installing.md#windows) instead. Download it
from a [release](https://github.com/sfreiberg/maxnines/releases), or build it with
`cargo build --release -p maxnines-agent`.

Put `maxnines-agent` in a folder of its own, with an `agent.hcl` beside it that says
where the server is:

```hcl
server {
  url = "ws://your-server:9000/ws"
}

state_dir = "state"
```

The URL has to match the server's `public_url`. Use `wss://` for anything beyond a
trusted network. Everything else about what to monitor comes from the server, and the
example `agent.hcl` in each download explains the settings an agent can have of its
own.

Then start it:

```sh
./maxnines-agent
```

It creates a key in `state`, logs its host ID, and waits to be approved. Every
relative path in `agent.hcl`, such as `state_dir`, `token_file`, `ca_file` or a
check's `private_key_file`, is from the config file's folder, wherever the agent is
started from. Approve it
on the Hosts page, or from the command line with an API key:

```sh
export MAXNINES_API_KEY=$(maxnines-server api-keys create "Admin" --user you@example.com)
maxnines-server hosts approve <host-id>
```

It starts reporting within a few seconds, and from then on it reconnects by itself.
It stops with Ctrl+C or when the terminal closes, so use `nohup` or `tmux` to keep it
running after you log out. Samples are kept in `state` while the server can't be
reached, and sent when it's back.

- **One key per host.** Copy the program and `agent.hcl` to another host, but
  never `state`. The key inside it is the host's identity, so a copy looks like the
  same host. If two hosts do share a key, each connection knocks the other off,
  and the Hosts page shows the host reconnecting over and over.
- **Hostnames aren't unique.** The key is the host's identity, so two hosts can share
  a hostname, such as a caching name server in every office, and a renamed host
  simply reports under its new hostname.
- **Only administrators should be able to change `agent.hcl`.** Custom metrics and
  [check commands](check-commands.md) in it are commands the agent runs, so anyone who can edit the file can run commands as
  the agent. Keep it owned by the agent's user or root and not writable by others.
  It can also hold passwords and tokens for [OpenMetrics pages](openmetrics.md#pages-that-need-signing-in)
  and [checks that sign in](checks.md#signing-in),
  so it shouldn't be readable by others either, unless those come from the
  environment.
- **Upgrade the server first.** Agents a release behind keep working with a newer
  server, but a newer agent may need things an older server doesn't have. See
  [Upgrading](#upgrading).
- **macOS and downloads:** a file that came through a browser or AirDrop is blocked
  until you run `xattr -d com.apple.quarantine maxnines-agent`.
- **Other commands:** `./maxnines-agent facts` prints what it reports about the
  host, and `./maxnines-agent identity show` prints its ID once it's been started.
  Use `-c` to point any of them at a config file somewhere else.

## Config rules

What each agent monitors comes from config rules, under **Settings > Config rules**.
Every rule that matches a host applies, lowest priority first, so a higher priority
wins. A rule can be limited to some operating systems, by ticking them under
**Applies to**, and to hosts whose facts match conditions.

When what an agent's sent changes, it changes only what's different: a collector
whose settings are the same carries on with what it holds, such as connections and
running totals, and each database a template reads keeps its connection, what
discovery found, and the totals of each query that's the same. A changed interval
starts every collector again.

### Built-in rules

Some rules come with MaxNines, and are marked **Comes with MaxNines**. Each is a
built-in [template's](templates.md#agent-settings) agent settings, named after it, at
priority 0, so a rule of your own at a higher priority applies over it:

| Rule | Applies to | Sets |
|---|---|---|
| **Host** | Every host | A sample every 15 seconds, facts every hour, and the host, CPU, memory, disk, network and system collectors |
| **macOS** | Macs | The [GPU](collectors-operating-system.md#gpus) collector |

An upgrade can change them, add more or remove one, and the audit log and the Config
rules page say when it did. They can be turned off, which lasts through upgrades, but
not changed or deleted. To change what one sets, open it and follow the link to add a
rule of your own after it: that rule applies to the same hosts, one priority higher,
and holds only your changes, so upgrades never touch them.

If an upgrade brings a built-in rule with the same name as one of yours, ignoring
case, yours is kept as it is and renamed, such as `Default (yours)`.

## What it reports

What an agent reads, and every metric it reports, is under [Collectors](collectors.md):
the [operating system](collectors-operating-system.md), [containers](collectors-containers.md),
[Windows performance counters](collectors-windows-counters.md) and web servers such as
[Apache](collectors-apache.md), [nginx](collectors-nginx.md) and [PHP-FPM](collectors-php-fpm.md).

## Actions

An action is something the server can ask this host to run, by name, whose output it
keeps: for an [alert](alerts.md#actions), or when someone presses **Run** on the
host's Actions page. Five are built into the agent and only look: `top_cpu`,
`top_memory`, `disk_io`, `disk_space` and `connections`.

Your own go in the agent's config file, which is the only place one can be added:

```hcl
action "largest_folders" {
  command = ["/usr/bin/du", "-x", "-h", "--max-depth=2", "{disk}"]
}

action "restart_nginx" {
  command = ["/usr/bin/sudo", "-n", "/usr/bin/systemctl", "restart", "nginx"]
}
```

- **The server can only pick from this list**, and say how long an action gets. The
  agent tells it the names, never the commands.
- **A command runs directly, not through a shell,** and always as the agent's
  user. For pipes, use `["/bin/sh", "-c", "..."]`.
- **Values from the alert** go where an argument names them in braces, like `{disk}`.
  Each stays inside its own argument whatever it holds, and can't start one with a
  dash. The program itself can't be a variable.
- **An action that needs more than the agent's user can do uses `sudo`**, as
  [below](#actions-that-need-root).
- **What it prints goes back to the server**, standard output and then standard
  error, up to 64 KiB. Don't print secrets.
- **One runs at a time.** Others wait their turn, up to eight.

### Actions that need root

The agent never runs your commands as root itself. A command that needs it, such as
restarting a service, asks `sudo`, so what the agent's user may do is written in
the system's own rules, where you already look for that. It takes a sudoers rule
for exactly that command, in a file such as `/etc/sudoers.d/maxnines`:

```
maxnines ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx
```

Write the rule for the whole command, not just the program. A rule that takes a
value from an alert, like `{disk}`, lets anyone who can run actions choose that
value, so keep those to commands that are safe whatever they're given.

### Running as root, and giving it up

The Linux packages start the agent as root, and the first thing it does, before it
connects to anything, is stop being root:

- **The agent becomes the `maxnines` user for good.** It talks to the server,
  collects, and runs your commands as that user.
- **A small helper stays root.** It never opens a network connection, and only
  hears from the agent. It does one thing when asked: runs `disk_io`,
  `disk_space` and `connections`, which then see every process and folder.
- **The helper never starts a program.** Those three actions only look, and
  they're all it knows. Someone who took over the agent could ask for them, and nothing
  more.

The helper keeps what `disk_space` saw last time in `/var/lib/maxnines-agent-helper`
(`/var/db` on macOS and FreeBSD), which only root can write to.

The agent's own folder, `state_dir`, has to belong to the user it becomes. A new one
is made that way. If one is already there and belongs to someone else, such as root
after the agent ran as root, the agent says so and doesn't start, with the `chown`
command that hands it over.

Two settings in the agent's config change this: `run_as = "someone"` chooses who it
becomes, and `privileged_helper = false` gives up root without keeping a helper.
Started as root where there's no `maxnines` user and no `run_as`, it stays root, with
a warning in its log.

An agent started as any other user just runs as them, with no helper. The built-in
actions then see what that user can: `disk_io` only its own processes,
`connections` only which of its own processes hold sockets, and `disk_space` only
folders it can read. They say what they couldn't see, and `disk_space` shows the
space it couldn't account for.

On macOS, even root can't read some folders, such as other people's Desktop and
Mail, until the agent is given **Full Disk Access** in System Settings, under Privacy
& Security.

Try one on the host, the way the server would run it:

```sh
sudo maxnines-agent --config /etc/maxnines/agent.hcl action disk_space disk=/var
```

Run as root like that, it splits the way the service does. Run as `maxnines`, it
shows what an agent without a helper would see.

To stop the server asking for the built-in ones, which name programs and folders,
set `built_in_actions = false` in the agent's config.

## Upgrading

Upgrade the server first, then its agents. An agent says which version of the
protocol it speaks each time it connects, and the server checks it before anything
else:

- **The server's own version, or the one before.** The agent works as usual. When the
  protocol's version goes up, a server keeps taking the version before its own for one
  release, so agents carry on while you upgrade them.
- **Older than that.** The server refuses the agent with a message that names the
  agent's version, the versions the server takes, and the version to upgrade the
  agent to. The agent logs it and tries again after 5 to 10 minutes. The host shows
  **Agent needs upgrading** on the Hosts page, not just Offline, with the message on
  its page.
- **Newer than the server.** The agent is refused the same way, and the host shows
  **Server needs upgrading**. Upgrade the server, and the agent connects on its next
  try.

Most releases don't change the protocol's version, as adding something doesn't. An
agent given a kind of [check](checks.md) it doesn't know reports that check as down,
saying the agent needs upgrading, and runs the rest. One given a collector it doesn't
know runs the others, and the host's page says which it skipped and that the agent
needs upgrading to run them.

Even when no agent is refused, the Hosts page marks agents older than the one
released with the server **Update available**, and any newer than the server **Newer
than server**.

## Removing a host

When a host is gone for good, revoke it on its page, then delete it. That
takes its metrics, facts and alerts with it, and can't be undone. From the command
line:

```sh
maxnines-server hosts revoke <host-id>
maxnines-server hosts delete <host-id>
```

Stop the agent on the host first, if it's still there. Otherwise it comes back as
a new host waiting to be approved, and an approval rule may let it straight in.
