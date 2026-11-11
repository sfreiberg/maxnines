# Running an agent

Without a package, an agent is one file you copy to a machine and start yourself. On
Windows, [run it as a service](windows-services.md) instead. Download it
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

It creates a key in `state`, logs its agent ID, and waits to be approved. Approve it
on the Agents page, or from the command line with an API key:

```sh
export MAXNINES_API_KEY=$(maxnines-server api-keys create "Admin" --user you@example.com)
maxnines-server agents approve <agent-id>
```

It starts reporting within a few seconds, and from then on it reconnects by itself.
It stops with Ctrl+C or when the terminal closes, so use `nohup` or `tmux` to keep it
running after you log out. Samples are kept in `state` while the server can't be
reached, and sent when it's back.

- **One key per machine.** Copy the program and `agent.hcl` to another machine, but
  never `state`. The key inside it is the agent's identity, so a copy looks like the
  same machine. If two machines do share a key, each connection knocks the other off,
  and the Agents page shows the agent reconnecting over and over.
- **Names aren't unique.** The key is the agent's identity, so two machines can share
  a name, such as a caching name server in every office, and a renamed machine
  simply reports under its new name.
- **Only administrators should be able to change `agent.hcl`.** Custom metrics in it
  are commands the agent runs, so anyone who can edit the file can run commands as
  the agent. Keep it owned by the agent's user or root and not writable by others.
- **Upgrade the server first.** Older agents work with a newer server, but a newer
  agent may need things an older server doesn't have. The Agents page marks agents
  older than the one released with the server **Update available**, and any newer
  than the server **Newer than server**.
- **macOS and downloads:** a file that came through a browser or AirDrop is blocked
  until you run `xattr -d com.apple.quarantine maxnines-agent`.
- **Other commands:** `./maxnines-agent facts` prints what it reports about the
  machine, and `./maxnines-agent identity show` prints its ID once it's been started.
  Use `-c` to point any of them at a config file somewhere else.

## CPU

Besides the machine's total, an agent reports each core's usage, so one core stuck at
100% shows up on a machine with many, where it barely moves the total. Cores are
numbered from 0. The **CPU usage by core** chart shows the 8 busiest, and an alert
rule on it alerts on each core that crosses its threshold.

## Disks

An agent reports how full each disk is, and how much is read and written, for every
file system on the machine's own storage. Mounts that are really files, memory or
another file system seen again aren't reported at all:

- **macOS:** disk images, such as a mounted installer, network shares, and the system's hidden
  volumes.
- **Linux:** loop devices, such as snaps and mounted image files, container layers,
  network shares, and memory file systems like `tmpfs`.
- **FreeBSD:** memory disks, null mounts such as jails', and memory file systems.
- **Windows:** mounted ISOs. Attached virtual disks, such as a Dev Drive, are reported.

On a Mac, the volumes in one APFS container share its space, so they're always exactly
as full as each other. Only one is reported for each container: `/` for the startup
disk, and otherwise the first by mount point.

To watch only some disks, list their mount points in a config rule under **Disk mount
points**. Those are reported whatever they are, even a disk image or every volume in
a container.

Each disk also reports how hard it's working, which bytes alone can't show, as a disk
doing small random reads is flat out long before it moves many bytes:

| Chart | What it is |
| --- | --- |
| **Disk busy** | The share of the time the disk was doing something |
| **Disk read operations**, **Disk write operations** | Operations a second |
| **Disk read latency**, **Disk write latency** | How long each took, on average |
| **Disk queue length** | How many were waiting or under way, on average |

On Linux and macOS they're worked out from one sample to the next, so they start with
the second. On a
Mac, each volume reports its whole physical disk, and there's no busy time or queue
length. FreeBSD doesn't report these yet.

On Linux, macOS and FreeBSD, each disk also reports how many of its inodes are used.
A disk that runs out of them can't take new files however much space it has left,
which the built-in **Disk running out of inodes** rule warns about. Windows file
systems don't have inodes.

## Top processes

The `top_processes` collector reports the five programs using the most CPU and the five
using the most memory, adding up every process of the same name, so twenty workers of
one server are one line. They're charted as **Top processes by CPU** and **Top
processes by memory**. Only program names are reported, never what they were started
with, which can hold passwords.

It's off unless a config rule turns it on, under **Collectors**, as it says what's
running on a machine. The `processes` collector, by contrast, only answers about the
names it's given.

## Network

Each network interface reports what it received and sent, in bytes and packets, the
packets it found damaged, and the packets it dropped, which had nowhere to wait because
the machine wasn't keeping up. macOS only counts received packets it dropped.

## Processes and logins

Every agent also reports how many processes are running, how many login sessions
there are, how many files are open and its TCP connections, each against the system's
limit where it has one. They come from the `system` collector, which the Default config rule turns on.

- **Processes** are counted the same way on every system, without their threads.
  Linux limits threads rather than processes, so a Linux machine also reports its
  threads, against that limit.
- **Login sessions** come from `who`, and from `quser` on Windows. Each session counts,
  so someone with three terminals open counts three times. Windows Home editions
  don't have `quser`, so they don't report sessions.
- **Tracked connections**, on Linux while its firewall tracks them, against the size of
  its table. When the table is full, new connections are dropped without a word, which
  busy gateways and Docker hosts run into.
- **Failed services** are counted, and named, without listing them first: on Linux, the
  units systemd says have failed, as `systemctl --failed` lists them, and on Windows,
  services that start automatically and stopped with an error. Many of Windows' own
  stop by design once they've done their job, and those stop cleanly, so they don't
  count. macOS and FreeBSD have no such state, so they don't report this.
- **Updates waiting**, and how many are security fixes, from the machine's own package
  lists: `apt-get` on Debian and Ubuntu, `dnf` or `yum` on Red Hat and Fedora, and
  `pkg` on FreeBSD. Nothing is fetched, so they're as current as the machine's own
  update schedule keeps them. FreeBSD doesn't say which are security fixes, and
  Windows and macOS don't report these yet.
- **Restart needed**, as 1 when an update is waiting for one: on Debian and Ubuntu
  when the system has said so, on Red Hat and Fedora from `needs-restarting`, on
  Windows when Windows Update or servicing is waiting, and on FreeBSD when a newer
  kernel is installed than the one running. macOS has no such flag. These two are
  looked at every 15 minutes.
- **TCP connections** are counted by state: established, listening, and two that pile up
  when something's wrong. Thousands in `TIME_WAIT` can use up the ports for new
  connections, and ones in `CLOSE_WAIT` are usually a program that never closed them.
  macOS and FreeBSD count them with `netstat`.
- **Windows** has no system-wide limits like these, so it reports processes, sessions
  and connections only.

## Windows performance counters

A Windows agent can report any of Windows' performance counters. List them in a config
rule under **Windows performance counters**, one per line, by their English path:

```text
\Processor(_Total)\% Processor Time
\Memory\Available MBytes
\PhysicalDisk(*)\Avg. Disk sec/Read
\SQLServer:Buffer Manager\Page life expectancy
```

- **Names are in English** whatever language Windows is in, so one rule works on every
  machine. Windows' `typeperf -q` lists what a machine has, in its own language.
- **`(*)` reports every instance,** such as each disk or each processor, as a series of its
  own, up to 64 for one path. Programs sharing a name are numbered as Windows numbers
  them, like `svchost#1`.
- **Rates are worked out by Windows** between one sample and the next, so a counter like
  `Disk Reads/sec` has a value from the first sample.
- **A path a machine doesn't have** is shown as failing on its page, and looked for again
  on every sample, as software adds its own counters once it's installed.

Each machine's page charts the busiest counters together and lists the latest value of
each. An alert rule on **Performance counters** can watch one of them by its path.
Counters are only ever read, never changed, and only on the machine itself.

## Containers

On Linux, an agent can report on every Docker or Podman container on its machine:
whether it's up, its CPU, memory, network and disk use, and how often it has
restarted. Turn on the `containers` collector in a config rule. It's off until then,
because reading containers needs the agent's user to be allowed Docker's socket, and
that's as good as root on the machine:

```sh
sudo usermod -aG docker maxnines-agent
sudo systemctl restart maxnines-agent
```

The agent finds the socket at `/var/run/docker.sock`, or Podman's at
`/run/podman/podman.sock`, or wherever `DOCKER_HOST` says in the agent's environment.
Containers keep the names Docker gives them, so one that Compose recreates keeps its
history, and an agent reports at most 64.

A container is **up** while it's running and its health check, if it has one, doesn't
call it unhealthy. One that stopped with an error, keeps restarting, or is unhealthy
is down, and the built-in **Container down** rule alerts once it has been for 5
minutes. One that exited cleanly isn't counted either way, as that's a job finishing
or a service stopped on purpose.

Other systems run containers inside a Linux virtual machine, as Docker Desktop does on
macOS and Windows, so only the Linux agent reads them.

## Removing an agent

When a machine is gone for good, revoke its agent on its page, then delete it. That
takes its metrics, facts and alerts with it, and can't be undone. From the command
line:

```sh
maxnines-server agents revoke <agent-id>
maxnines-server agents delete <agent-id>
```

Stop the agent on the machine first, if it's still there. Otherwise it comes back as
a new agent waiting to be approved, and an approval rule may let it straight in.
