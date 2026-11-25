# Operating system

What an agent reads about the host itself: its processors, memory, disks, network,
programs, services and more. Most of it is on by default on every host and needs no
extra rights; each section says when that's not so.

- [CPU](#cpu)
- [Memory](#memory)
- [Disks](#disks)
- [Network](#network)
- [Processes](#processes)
- [Services](#services)
- [Updates](#updates)
- [Logins and open files](#logins-and-open-files)
- [Files and folders](#files-and-folders)
- [GPUs](#gpus)
- [Temperature sensors](#temperature-sensors)
- [Clock](#clock)
- [Uptime and the agent](#uptime-and-the-agent)

## CPU

The `cpu` collector, on by default, reports how busy the processors are, in total and
for each core, and the load average.

Each core is reported on its own as well as the total, so one core stuck at 100%
shows up on a host with many, where it barely moves the total. Cores are numbered
from 0. The **CPU usage by core** chart shows the 8 busiest, and an alert rule on it,
like `cpu.cores > 95`, alerts on each core.

| Metric | Unit | Series | What it is |
| --- | --- | --- | --- |
| `cpu.usage` | % | One | How busy the processors are, all cores together |
| `cpu.cores` | % | Each core, by number | How busy each core is |
| `cpu.load` | Number | `1 minute`, `5 minutes`, `15 minutes` | The load average: how many programs were running or waiting to. Not on Windows, which has none |
| `cpu.time` | % | `User`, `System`, `Nice`, `Interrupt`, `I/O wait`, `Steal`, `Idle` | What the processors' time went on |
| `cpu.context_switches` | A second | One | How often the processors switched between programs. Linux and FreeBSD |
| `cpu.interrupts` | A second | One | Hardware interrupts. Linux and FreeBSD |

What CPU time is split into depends on the system:

- **Linux:** every part. **I/O wait** is time idle while waiting for a disk, and
  **Steal** is time a virtual machine's host gave to others, which a busy cloud host
  shows.
- **macOS and FreeBSD:** user, nice, system, interrupt and idle.
- **Windows:** user, system and idle.

A load average higher than the host's cores for long means work is queueing:
`cpu.load['5 minutes'] > facts.cpu.logical_cores` alerts on that.

## Memory

The `memory` collector, on by default, reports how much memory and swap is in use,
what the memory is being used for, and how much is being swapped.

| Metric | Unit | Series | What it is |
| --- | --- | --- | --- |
| `memory.usage` | % | `Memory`, `Swap` | How much is in use. Memory the system can give back at once, such as its file cache, doesn't count |
| `memory.detail` | Bytes | What it's used for, as the system names it | Where the memory went |
| `memory.swap_activity` | A second | `Pages in`, `Pages out` | Pages moved between memory and swap. Linux and FreeBSD |

Each system keeps its own categories, so **Memory breakdown** shows these:

- **Linux:** active, inactive, cached, buffers, slab, shared and free.
- **macOS:** active, inactive, wired, compressed, speculative, purgeable and free.
- **FreeBSD:** active, inactive, wired, cached, ZFS cache and free.
- **Windows:** how much of its page files is in use. Windows has no figure for memory
  that's truly free, only what's available, which `memory.usage` already counts.

Swap in use isn't a problem by itself. Pages moving in and out all the time is: the
host is short of memory.

## Disks

The `disk` collector, on by default, reports how full each disk is, how much is read
and written, how hard it's working, and how many of its inodes are used.

Every file system on the host's own storage is reported. Mounts that are really
files, memory or another file system seen again aren't reported at all:

- **macOS:** disk images, such as a mounted installer, network shares, and the
  system's hidden volumes.
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

Each metric has a series for each disk, named by its mount point, such as `/` or `C:\`.

| Metric | Unit | Series | What it is |
| --- | --- | --- | --- |
| `disk.usage` | % | Each disk | How full it is |
| `disk.inodes` | % | Each disk | How many of its inodes are used. Not on Windows, whose file systems have none |
| `disk.read` | Bytes a second | Each disk | Read from it |
| `disk.written` | Bytes a second | Each disk | Written to it |
| `disk.busy` | % | Each disk | The share of the time it was doing something. Linux and Windows |
| `disk.read_ops` | A second | Each disk | Reads |
| `disk.write_ops` | A second | Each disk | Writes |
| `disk.read_latency` | Seconds | Each disk | How long each read took, on average |
| `disk.write_latency` | Seconds | Each disk | How long each write took, on average |
| `disk.queue` | Number | Each disk | How many operations were waiting or under way, on average. Linux and Windows |

The operations, latency, busy time and queue length show how hard a disk is working,
which bytes alone can't: a disk doing small random reads is flat out long before it
moves many bytes. On Linux and macOS they're worked out from one sample to the next,
so they start with the second. On a Mac each volume reports its whole physical disk.
FreeBSD doesn't report them yet.

A disk that runs out of inodes can't take new files however much space it has left.

| Built-in alert | When |
| --- | --- |
| **Disk filling up** | Over 80% full for 5 minutes, then critical over 90% |
| **Disk will be full soon** | On course to be full within 24 hours, then critical within 4, from the last 6 hours |
| **Disk running out of inodes** | Over 80% of its inodes used for 5 minutes, then critical over 90% |

## Network

The `network` collector reports what each interface received and sent, its damaged
and dropped packets, and whether its link is up. The `system` collector adds the
host's TCP connections and, on Linux, its table of tracked connections. Both are on
by default.

Two kinds of interface are left out: loopback, and on macOS those with only a
link-local address, which it makes for AirDrop and the like. Every other one is
reported, including one that's idle or has nothing plugged in, so it reads zero
instead of looking like it isn't being watched.

The `network.` metrics have a series for each interface, named as the system names
it, such as `eth0` or `en0`.

| Metric | Unit | Series | What it is |
| --- | --- | --- | --- |
| `network.received` | Bytes a second | Each interface | Received |
| `network.transmitted` | Bytes a second | Each interface | Sent |
| `network.packets.received` | A second | Each interface | Packets received |
| `network.packets.transmitted` | A second | Each interface | Packets sent |
| `network.errors.received` | A second | Each interface | Damaged packets received |
| `network.errors.transmitted` | A second | Each interface | Packets that failed to send |
| `network.drops.received` | A second | Each interface | Packets that arrived with nowhere to wait, because the host wasn't keeping up |
| `network.drops.transmitted` | A second | Each interface | Packets ready to go with nowhere to wait |
| `network.link` | 1 or 0 | Each interface | Whether its link is up, where the system says |
| `system.tcp` | Number | `Established`, `Listening`, `Time wait`, `Close wait` | TCP connections by state |
| `system.tcp_total` | Number | One | Every TCP connection, whatever its state |
| `system.conntrack` | Number | `Tracked`, `Limit` | Connections Linux's firewall is tracking, and the size of its table |
| `system.conntrack_used` | % | One | How full that table is |

- **Dropped packets** an interface reports that can't be true, such as more than it
  ever received, are left out: macOS does that for the interface of a virtual machine.
- **TCP connections in `TIME_WAIT`** pile up when connections open and close fast, and
  thousands of them can use up the ports for new ones. Ones in `CLOSE_WAIT` are
  usually a program that never closed them. macOS and FreeBSD count them with
  `netstat`.
- **Tracked connections** are only on Linux, while its firewall tracks them. When the
  table is full, new connections are dropped without a word, which busy gateways and
  Docker hosts run into.

## Processes

Three collectors report on what's running:

- **`processes`** watches programs by name, and reports how many are running and their
  CPU and memory. It reports nothing until a config rule lists names under
  **Processes**, one to a line, which turns it on.
- **`top_processes`** reports the five programs using the most CPU and the five using
  the most memory. It's off unless a config rule turns it on under **Collectors**, as
  it says what's running on a host.
- **`system`**, on by default, counts every process, and on Linux every thread,
  against the system's limit.

Only program names are reported, never what they were started with, which can hold
passwords.

Each watched name is matched against the program's name, whatever it was started
with, ignoring case and Windows' `.exe`. A name reports how many are running, and their
CPU and memory use added together. A name with nothing running reports 0, which a rule
on `process.count` below 1 alerts on. Programs sharing a name, such as everything run
by `java`, are counted together, so anything that needs telling apart is better run as
a [service](#services). Top processes add up every process of the same name too, so
twenty workers of one server are one line.

| Metric | Unit | Series | What it is |
| --- | --- | --- | --- |
| `process.count` | Number | Each watched name | How many are running |
| `process.cpu` | % | Each watched name | Their CPU use, added together |
| `process.memory` | Bytes | Each watched name | Their memory use, added together |
| `top.cpu` | % | Each of the top five | The programs using the most CPU |
| `top.memory` | Bytes | Each of the top five | The programs using the most memory |
| `system.processes` | Number | `Running`, `Limit` | Every process, without threads, and the most the system allows |
| `system.processes_used` | % | One | How close that is to the limit |
| `system.threads` | Number | `Running`, `Limit` | Every thread, and the most allowed. Linux, which limits threads rather than processes |
| `system.threads_used` | % | One | How close that is to the limit. Linux |

Windows has no system-wide limit, so it reports how many processes are running only.

## Services

The `services` collector watches services by name. It reports nothing until a config
rule lists names under **Services**, one to a line, which turns it on. Each is asked of
the system's own service manager, by the name it knows it by:

| System | Asks | A name looks like |
| --- | --- | --- |
| Linux | systemd | `nginx.service` |
| macOS | launchd | `com.example.orders`, its label |
| FreeBSD | `service` | `nginx` |
| Windows | The service manager | `W3SVC`, its service name, not its display name |

A service that's starting, paused or failed counts as not running, and so does a name
the system doesn't know, so a mistyped name shows as stopped, not as missing. When the
service manager can't be asked, or doesn't answer within 10 seconds, the service has
no value for that sample, as that says nothing about whether it's running, and an
alert on it stays as it was.

The host's metrics page lists them under **Watched services**, each as running or
not, and one that isn't running with its service manager's own word for why, such as
`failed`, or `not found` for a name it doesn't know. Two services that run the same
program, such as two Java ones, are told apart, as each has its own name.

On macOS the system's own services are looked for first, then those of the user the
agent runs as. launchd starts many services only when something needs them, and one of
those counts as not running in between, so watch ones that are meant to stay up.

Services that stopped with an error are also counted by the `system` collector, on by
default, without being named first: on Linux, the units systemd says have failed, as
`systemctl --failed` lists them, and on Windows, services that start automatically and
stopped with an error. Many of Windows' own stop by design once they've done their
job, and those stop cleanly, so they don't count. macOS and FreeBSD have no such
state. The host's page lists them by name under **Failed services**, as do the
**Failed services** chart and its data, or says none have failed. The agent names up
to 32 of them, and counts the rest. The [API](api-host-readings.md#get-a-hosts-services) gives
both these and the watched services.

| Metric | Unit | Series | What it is |
| --- | --- | --- | --- |
| `service.running` | 1 or 0 | Each watched service | Whether it's running |
| `system.failed_services` | Number | One | Services that stopped with an error. Linux and Windows |

| Built-in alert | When |
| --- | --- |
| **Service stopped** | A watched service hasn't been running for a minute, saying why, such as *Service nginx.service on web-1 is failed*. If the reason changes while it's still down, the alert is reworded without telling anyone again |

## Updates

The `system` collector, on by default, reports updates waiting to be installed, from
the host's own package lists, looked at every 15 minutes. Nothing is fetched, so
they're as current as the host's own update schedule keeps them.

| Metric | Unit | Series | What it is |
| --- | --- | --- | --- |
| `system.updates` | Number | `All`, `Security` | Updates waiting, and how many are security fixes |
| `system.reboot_required` | 1 or 0 | One | Whether an installed update is waiting for a restart |

- **Updates** come from `apt-get` on Debian and Ubuntu, `dnf` or `yum` on Red Hat and
  Fedora, and `pkg` on FreeBSD. FreeBSD doesn't say which are security fixes, and
  Windows and macOS don't report updates yet.
- **Restart needed** is 1 on Debian and Ubuntu when the system has said so, on Red Hat
  and Fedora from `needs-restarting`, on Windows when Windows Update or servicing is
  waiting, and on FreeBSD when a newer kernel is installed than the one running.
  macOS has no such flag.

## Logins and open files

The `system` collector, on by default, counts login sessions and open files.

| Metric | Unit | Series | What it is |
| --- | --- | --- | --- |
| `system.sessions` | Number | One | Login sessions |
| `system.open_files` | Number | `Open`, `Limit` | Files open across the system, and the most it allows. Not on Windows |
| `system.open_files_used` | % | One | How close that is to the limit. Not on Windows |

Sessions come from `who`, and from `quser` on Windows. Each counts, so someone with
three terminals open counts three times. Windows Home editions don't have `quser`, so
they don't report sessions.

## Files and folders

The `files` collector watches files and folders by path: whether each exists, its size
and how long since it changed. It reports nothing until a config rule lists paths
under **Files and folders**, one to a line, which turns it on. Contents are never
read, and the agent's user has to be allowed to see the path.

| Metric | Unit | Series | What it is |
| --- | --- | --- | --- |
| `file.exists` | 1 or 0 | Each path | Whether it's there |
| `file.size` | Bytes | Each path | A file's size, or what's directly in a folder added together |
| `file.age` | Seconds | Each path | How long since it changed |

A folder's size counts only the files directly in it, not what's in the folders inside
it, and only its first 100,000 entries. A path that doesn't answer within 10 seconds,
such as one on a network drive that's gone, or one the agent isn't allowed to see, has
no value rather than reading as missing, so an alert on it stays as it was.

A backup that should arrive every night is watched with `file.age > duration('26h')`.

## GPUs

On a Mac, the `gpu` collector reports how busy each GPU is and how much memory it's
using. It's on by default on Macs and needs no extra rights. Other systems don't
report GPUs yet.

| Metric | Unit | Series | What it is |
| --- | --- | --- | --- |
| `gpu.usage` | % | Each GPU, by model | How busy it is |
| `gpu.memory` | Bytes | Each GPU, by model | The memory it's using |

Each GPU is named by its model, such as `Apple M4 Pro`. On Apple silicon the GPU
shares the Mac's memory, so that's the share it's using; a separate graphics card
reports its own.

## Temperature sensors

The `sensors` collector reports every temperature the host's hardware makes
available. It's off unless a config rule turns it on under **Collectors**.

| Metric | Unit | Series | What it is |
| --- | --- | --- | --- |
| `sensor.temperature` | °C | Each sensor, as the hardware names it | Its temperature |

What's there depends heavily on the host. Physical Linux machines and Macs usually
have several, virtual machines usually have none, and few Windows machines tell
programs their temperatures at all. A reading no hardware could survive is left out.

## Clock

A host whose clock is wrong fails sign-ins and certificate checks, and dates its own
metrics wrongly. Nothing needs turning on: once a minute the server asks each
connected agent what its clock says and compares the answer with its own clock. The
agent needs no access to a time server.

The agent answers at once, and the server times how long the answer took: the reading
can be out by half of that, so an answer that took over a second isn't used and is
asked for again a few seconds later. The reading is dated by the server, as the host's
clock is the one in question. It compares with the server's clock, so the server's own
has to be right.

| Metric | Unit | Series | What it is |
| --- | --- | --- | --- |
| `clock.difference` | Seconds | One | How far the host's clock is from the server's, whichever is ahead |

| Built-in alert | When |
| --- | --- |
| **Clock is wrong** | Over 5 seconds out for a minute, then critical over 30 |

Whether a time service is keeping each clock in sync, as the host itself says, is read
by the [Time sync](collectors-time-sync.md) collector, which warns of one that has
stopped before its clock drifts this far.

## Uptime and the agent

The `host` collector, on by default, reports how long the host has been up. Every
agent also reports its own memory and CPU use, so you can see that it stays small.

| Metric | Unit | Series | What it is |
| --- | --- | --- | --- |
| `host.uptime` | Seconds | One | How long since the host started |
| `agent.memory` | Bytes | One | The agent's own memory |
| `agent.cpu` | % | One | The agent's own CPU use |
| `agent.uptime` | Seconds | One | How long since the agent started |

The agent's memory is what the system charges to it alone:

- **macOS:** its physical footprint, the figure Activity Monitor shows.
- **Linux:** its proportional share, where a page shared with other programs counts
  as the agent's part of it.
- **Windows:** its private working set, the figure Task Manager shows.
- **FreeBSD:** its resident size, which also counts shared pages in full.

`ps` and `top` show the resident size everywhere, as does the "Working set (memory)"
column you can add to Task Manager's Details tab. It's around three times larger, as
it takes in the system libraries every program shares.
