# Time sync

The `time_sync` collector reads whether a time service is keeping a host's clock in
sync, as the host itself knows it. It's on for every host, from the built-in **Host**
template's settings, and the built-in **Time sync** template alerts on what it reads.

It asks nothing over the network, so it works on hosts that can't reach a time server
of their own accord, and it warns of a time service that has stopped before the clock
drifts far enough for the [Clock is wrong](collectors-operating-system.md#clock) alert,
which compares each host's clock with the server's. It's read with every sample. The
host's page shows it under **Time sync**, and the
[API](api-host-readings.md#get-a-hosts-time-sync) gives the same.

## What it reads

| System | Reads | Needs |
| --- | --- | --- |
| Linux | The kernel's clock status, with `adjtimex` | Nothing, and no root |
| FreeBSD and macOS | The kernel's clock status, with `ntp_adjtime` | Nothing, and no root |
| Windows | The Windows Time service's performance counters, and whether the service is running | Windows 10 1607 or Windows Server 2016 and later, which every Windows the agent runs on is |

### Linux, FreeBSD and macOS

Every time service tells the kernel when it has the clock in sync, and how far out the
clock could still be: chrony, ntpd and systemd-timesyncd on Linux, ntpd on FreeBSD and
timed on macOS. The agent reads what the kernel was told, with a system call that
changes nothing, so it works whichever service runs and needs no program of its own.

Between corrections, the kernel adds half a millisecond to the clock's largest possible
error every second, which is the most a clock that isn't being corrected is expected to
drift. chrony and systemd-timesyncd correct the clock every minute or two, ntpd every
few minutes and timed about every quarter of an hour, keeping the error under a
second, so a large error means the service has stopped, or can't reach its time
sources. A service that stops leaves the clock marked synced, so the growing error is
what shows it. Linux marks the clock unsynced itself once the error passes 16 seconds,
about 9 hours without a correction.

A Mac with **Set time and date automatically** turned off in System Settings has its
clock unsynced. Between corrections, macOS's kernel was seen to stop growing the error
for minutes at a time, so on a Mac it can be slower to say a time service has stopped.

A FreeBSD host only runs ntpd if the installer was told to, or `ntpd_enable="YES"` is
in `/etc/rc.conf`, so one without it reports its clock as not synced, which it isn't.

### Windows

The Windows Time service publishes how many time sources it's using and how far the
clock is from them. A host with a source is synced, whether it's a time server on the
network, a domain controller or, on a virtual machine, the host it runs on, as Hyper-V
gives its own.

The counters are only there while the service runs, so when it isn't, the agent asks
how the service starts:

- **Set to start with Windows, or turned off:** it should be running, so the clock is
  reported as not synced, and the host's page says the service isn't running.
- **Started only when it's needed:** as on many hosts that aren't in a domain, Windows
  starts it to sync and lets it stop again, so not running isn't a problem. Whether
  the clock is synced isn't known until it runs, and the host's page says so.

## What's reported

| Metric | Unit | Series | What it is |
| --- | --- | --- | --- |
| `time_sync.synced` | 1 or 0 | One | Whether a time service has the clock in sync |
| `time_sync.max_error` | Seconds | One | The most the clock could be out, by the kernel's reckoning, on Linux, FreeBSD and macOS |
| `time_sync.offset` | Seconds | One | How far the clock is from its time source, on Windows, while it has one |
| `time_sync.sources` | Number | One | How many time sources the Windows Time service is using |

## Built-in alerts

The built-in **Time sync** template brings these, for each host:

| Alert | When | Severity |
| --- | --- | --- |
| **Time not synced** | No time service has had the clock in sync for 30 minutes | Warning |
| **Time sync stopped** | The clock's largest possible error has been over 5 seconds for 30 minutes | Warning |

A time service syncs within a minute or two of starting, though ntpd can take a quarter
of an hour before it tells the kernel so, hence the half hour. 5 seconds of error is
nearly 3 hours without a correction, which no time service leaves a working clock
for. A clock first synced after a long time without can start with an error of a
minute or more, which the service's next corrections bring down, so **Time sync
stopped** waits half an hour too. It never fires on Windows, which doesn't publish the
error.

Both only warn: a clock without a time service drifts slowly, and **Clock is wrong**
says when it has actually drifted.
