# Drives

The `smart` collector reads each drive's SMART health: whether the drive passes its own
assessment, its temperature, how long it has been powered on, and the counts that say a
drive is failing or wearing out. It's on for every host, from the built-in **Host**
template's settings, and the built-in **Drives** template alerts on what it reads.

Drives are asked every 15 minutes, and first within a minute of the agent starting. A
disk that's asleep isn't woken to be asked: it keeps what it last said, and the host's
page says it's asleep.

## What it needs

| System | Reads with | Needs |
| --- | --- | --- |
| Linux | `smartctl` | smartmontools 7.0 or later, and root |
| macOS | `smartctl` | smartmontools 7.0 or later, and root |
| FreeBSD | `smartctl` | smartmontools 7.0 or later, and root |
| Windows | Windows' own storage counters | Nothing to install |

### smartctl

smartctl comes with smartmontools, which knows how thousands of drive models report.
Version 7.0 was the first to print JSON, which is what the agent reads.

```sh
sudo apt install smartmontools     # Debian and Ubuntu
sudo dnf install smartmontools     # RHEL, Rocky, Alma and Fedora
sudo pkg install smartmontools     # FreeBSD
brew install smartmontools         # macOS
```

The agent's Linux packages recommend smartmontools, so `apt` and `dnf` install it with
the agent unless told not to. On a host without it, or with an older one, the host's
page says so under **Drives**, with how to install it, and no drive is read.

### Root

smartctl needs root to open drives. An agent started as root [gives that
up](agents.md#running-as-root-and-giving-it-up) and runs as the `maxnines` user, so it asks for
root through `sudo -n`, as [actions](agents.md#actions-that-need-root) do, and never for a password.
Until sudo allows it, the host's page says so under **Drives**, with the rule to add.
Allow exactly the two ways the agent runs smartctl, with a rule in a file such as
`/etc/sudoers.d/maxnines`, made with `sudo visudo -f /etc/sudoers.d/maxnines`:

```text
maxnines ALL=(root) NOPASSWD: /usr/sbin/smartctl --scan-open -j, /usr/sbin/smartctl -j -a -n standby -d *
```

smartctl is in `/usr/sbin` on Linux, `/usr/local/sbin` on FreeBSD and Intel Macs, and
`/opt/homebrew/sbin` on Apple silicon Macs, where it's looked for in that order. The
`*` lets the agent name the drive, and sudo lets anything follow it, so the agent's
user could ask smartctl for more than a reading, such as starting a self-test or
changing a drive's settings. That's no more than the agent's user can do with any rule
that runs smartctl as root.

An agent that runs as root, such as one started as root on a host with no `maxnines`
user, runs smartctl itself, with no rule.

### Windows

On Windows the agent reads `Get-PhysicalDisk` and `Get-StorageReliabilityCounter`
through PowerShell, which needs the rights the agent's service already has. Windows
gives less than smartctl: each drive's health, temperature, power-on time and wear,
but no sector counts.

### Drives it can't read

The agent asks smartctl for every drive `smartctl --scan-open` finds, as the kind of
drive smartctl took it for. In this first version there's no way to tell smartctl
more, as its `-d` option does, so:

- **USB enclosures** are read when their bridge passes SMART through, which most do.
  One that doesn't is listed on the host's page with smartctl's reason.
- **Drives behind a RAID controller**, such as MegaRAID, HP Smart Array or Areca, are
  seen as the controller's volumes, not as drives, and aren't read.
- **Virtual disks** have no SMART, so a virtual machine has nothing to read.

## What's reported

Each metric has a series for each drive, named by its model and serial number, such as
`Samsung SSD 980 PRO 1TB S5GXNF0R654321B`, so a drive keeps its history when the system
names its devices differently after a restart. A metric a drive doesn't report has no
series for it.

| Metric | Unit | Series | What it is |
| --- | --- | --- | --- |
| `smart.healthy` | 1 or 0 | Each drive | Whether the drive passes its own SMART assessment. On Windows, a drive Windows calls Warning or Unhealthy doesn't |
| `smart.temperature` | °C | Each drive | Its temperature |
| `smart.power_on` | Seconds | Each drive | How long it has been powered on, in all |
| `smart.power_cycles` | Number | Each drive | How many times it has been powered on |
| `smart.reallocated` | Number | Each SATA drive | Sectors it has moved elsewhere after failing to write them (attribute 5) |
| `smart.pending` | Number | Each SATA drive | Sectors it couldn't read, waiting to be moved (attribute 197) |
| `smart.uncorrectable` | Number | Each SATA drive | Sectors it found it couldn't read in its own offline scan (attribute 198) |
| `smart.crc_errors` | Number | Each SATA drive | Errors between the drive and its controller, usually a cable (attribute 199) |
| `smart.used` | % | Each NVMe drive, and on Windows | How much of its rated life it has used. It can pass 100 |
| `smart.spare` | % | Each NVMe drive | Spare blocks it has left |
| `smart.spare_threshold` | % | Each NVMe drive | The spare below which the drive says it's in trouble |
| `smart.media_errors` | Number | Each NVMe drive | Errors it couldn't correct |
| `smart.unsafe_shutdowns` | Number | Each NVMe drive | Times it lost power without being told first |
| `smart.critical_warning` | Number | Each NVMe drive | The drive's critical warning, 0 when there's none |

The sector counts are as smartctl reads them, as some drives pack more into an
attribute than the count, which smartctl knows to take apart.

## Built-in alerts

The built-in **Drives** template brings these, for each drive:

| Alert | When | Severity |
| --- | --- | --- |
| **Drive failing** | The drive has failed its own SMART assessment for a minute | Critical |
| **Drive has reallocated sectors** | It has moved any sectors | Warning |
| **Drive has unreadable sectors** | It has sectors it couldn't read, waiting to be moved | Critical |
| **Drive running out of spare** | An NVMe drive's spare is below its threshold, or it has a critical warning | Critical |
| **Drive nearly worn out** | It has used 90% or more of its rated life | Warning |
| **Drive too hot** | It has been over 60 °C for 15 minutes, or over 70 °C | Warning, then critical |

Reallocated and unreadable sectors alert while there are any, not only as the count
grows. Any at all is the best sign there is that a disk is on its way out, so the alert
stays open until the drive is replaced, or the rule is changed or turned off for that
host.
