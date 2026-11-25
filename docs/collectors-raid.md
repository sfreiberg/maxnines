# RAID and ZFS

The `raid` collector reads each software RAID array and ZFS pool on a host: whether it's
whole, degraded or failed, whether it's rebuilding or being scrubbed and how far that
has got, and for ZFS how full each pool is, the errors it has seen and how long since it
was last scrubbed. It's on for every host, from the built-in **Host** template's
settings, and the built-in **RAID and ZFS** template alerts on what it reads.

Arrays and pools are read every minute, and every 5 minutes on Windows, where starting
PowerShell costs more. The first look comes within 15 seconds of the agent starting.
The host's page lists each one under **RAID and ZFS**, and the
[API](api-host-readings.md#get-a-hosts-raid-arrays-and-zfs-pools) gives the same. A host
with no arrays or pools, which is most of them, reports nothing and has no such section:
not having md or ZFS isn't a problem.

## What it reads

| System | What | Reads with | Needs |
| --- | --- | --- | --- |
| Linux | Software RAID (md) | `/proc/mdstat` | Nothing, and no root |
| Linux and FreeBSD | ZFS pools | `zpool list` and `zpool status` | Nothing to install beyond ZFS itself, and no root where `/dev/zfs` lets anyone open it, as OpenZFS sets it up |
| Windows | Storage Spaces virtual disks | `Get-StoragePool`, `Get-VirtualDisk`, `Get-PhysicalDisk` and `Get-StorageJob`, through PowerShell | Nothing to install, and the rights the agent's service already has |
| macOS | AppleRAID sets | `diskutil appleRAID list` | Nothing, and no root |

**Hardware RAID cards**, such as MegaRAID, HP Smart Array or Areca, aren't read: each
maker's cards need the maker's own tool. The operating system sees the card's volumes
as ordinary disks, which the [disk](collectors-operating-system.md#disks) and
[Drives](collectors-smart.md) collectors read where they can.

FreeBSD's GEOM mirrors and RAID, and Linux's LVM RAID and Btrfs RAID, aren't read in
this version.

### Linux software RAID

`/proc/mdstat` is the kernel's own list of md arrays, which anyone may read, so nothing
needs installing and the agent needs no root. Without the md module loaded there's no
`/proc/mdstat`, and nothing to report.

An array is:

- **degraded** when fewer of its devices are working than it should have, which
  `[3/2] [UU_]` says, including while it rebuilds onto a new one;
- **failed** when it has lost more than it can do without: all of a RAID 1's devices,
  more than one of a RAID 4 or 5's, more than two of a RAID 6's, both copies of
  something in a RAID 10, or any device of a RAID 0 or linear array. One that's
  **inactive**, which is how md leaves an array found at boot without enough of its
  devices, has failed too;
- **rebuilding** while it resyncs, after it's created or shut down uncleanly, recovers
  onto a device added to it, or is reshaped;
- **scrubbed** while it's checked or repaired, as the monthly `checkarray` cron job on
  Debian and Ubuntu, or `raid-check` on Red Hat's family, does.

Spares don't count among an array's devices until they're used.

### ZFS

ZFS is read on Linux, with OpenZFS from the distribution's packages, such as
`zfsutils-linux` on Ubuntu, and on FreeBSD, where it's part of the base system. The
agent looks for `zpool` in `/usr/sbin`, `/sbin` and `/usr/local/sbin`, and reads ZFS
only while `/dev/zfs` is there, which it is while ZFS's module is loaded. It runs
exactly:

```sh
zpool list -Hp -o name,health,size,allocated,free,fragmentation,capacity
zpool status -p
```

Neither needs root where `/dev/zfs` lets anyone open it, which OpenZFS's own packages
and FreeBSD do. On a host that doesn't, the agent asks for root through `sudo -n`, as
it does for [smartctl](collectors-smart.md#root), and until sudo allows it the host's
page says so under **RAID and ZFS**, with the rule to add, such as:

```text
maxnines ALL=(root) NOPASSWD: /usr/sbin/zpool list -Hp -o name\,health\,size\,allocated\,free\,fragmentation\,capacity, /usr/sbin/zpool status -p
```

The commas in the list of columns need a backslash before them in a sudoers rule.

`zpool status` gives the same in OpenZFS 2.1, 2.2, 2.3 and 2.4, so the agent reads
its text in each. OpenZFS 2.3 and later can print it as JSON with `zpool status -j`,
but Ubuntu 24.04 and FreeBSD 14 have 2.2, so the text is what every system has.

A pool is degraded when ZFS says it's `DEGRADED`, and failed when it's `FAULTED`,
`UNAVAIL` or `SUSPENDED`. A resilver is a rebuild. Its devices are those in its data,
log, special and dedup vdevs: spares and caches don't count, as a spare is only waiting
and a cache only speeds reads up. A device that isn't `ONLINE`, such as one `OFFLINE`,
`FAULTED`, `UNAVAIL` or `REMOVED`, isn't working, and the host's page lists it by name,
or by where it was for a device that's gone.

The time since the last scrub is from when `zpool status` says it finished, in the
host's time zone. ZFS only says how the last scan ended, so after a resilver, or for a
pool never scrubbed, there's no time since the last scrub to report.

### Storage Spaces

Each Storage Spaces virtual disk is read with its pool, as a virtual disk is what holds
data and loses its redundancy when one of the pool's disks goes. A virtual disk is:

- **degraded** when Windows says it's `Degraded` or `Incomplete`, or its health is
  `Warning` while no repair runs;
- **failed** when its health is `Unhealthy`, or it's `Detached` or has `Lost
  Communication`, as a simple space with a disk gone does;
- **rebuilding** while a repair or regeneration job runs on it, or Windows says it's
  `InService`, with how far the job has got from the bytes it has done and has to do.
  A repair's own percentage can read 400 before it knows how much there is, so it's
  only used when it has no bytes to go by.

Its devices are the pool's physical disks, and the host's page says how many of them
aren't healthy.

### AppleRAID

macOS reads each AppleRAID set with `diskutil appleRAID list`. A set that's `Online` is
whole, one that's `Degraded` is degraded, and anything else, such as `Offline` or
`Failed`, has failed. A member rebuilding makes the set rebuilding, and spares don't
count among its devices.

macOS 26 takes a mirror offline as soon as a member goes, rather than running on the
others, so on recent macOS a mirror missing a member is failed, not degraded.

## What's reported

Each metric has a series for each array or pool, named by its own name: `md0`, a ZFS
pool's name, a virtual disk's friendly name, or an AppleRAID set's. A metric an array
doesn't report has no series for it, so only ZFS pools have the `zfs.` metrics, and
the progress and speed are only there while a rebuild or scrub runs.

| Metric | Unit | Series | What it is |
| --- | --- | --- | --- |
| `raid.degraded` | 1 or 0 | Each array or pool | Whether it's running without all its redundancy |
| `raid.failed` | 1 or 0 | Each array or pool | Whether it can't serve what's on it |
| `raid.rebuilding` | 1 or 0 | Each array or pool | Whether it's rebuilding its redundancy: an md resync, recovery or reshape, a ZFS resilver, a Storage Spaces repair or an AppleRAID rebuild |
| `raid.rebuild_progress` | % | Each array or pool rebuilding | How far the rebuild has got, where its system says |
| `raid.scrub_progress` | % | Each array or pool being scrubbed | How far an md check or repair, or a ZFS scrub, has got |
| `raid.speed` | Bytes/s | Each array or pool rebuilding or scrubbed | How fast the rebuild or scrub goes, on Linux md and ZFS |
| `raid.devices` | Number | Each array or pool | The devices it's made of, leaving out spares and caches |
| `raid.working_devices` | Number | Each array or pool | How many of them are working |
| `zfs.size` | Bytes | Each ZFS pool | Its size |
| `zfs.used` | % | Each ZFS pool | How much of it is used |
| `zfs.fragmentation` | % | Each ZFS pool | How fragmented its free space is |
| `zfs.read_errors` | Number | Each ZFS pool | Read errors on its devices since it was imported or `zpool clear` was run |
| `zfs.write_errors` | Number | Each ZFS pool | Write errors on its devices, counted the same way |
| `zfs.checksum_errors` | Number | Each ZFS pool | Data its devices returned that didn't match its checksum, counted the same way |
| `zfs.data_errors` | Number | Each ZFS pool | Files or metadata with errors ZFS couldn't repair |
| `zfs.scrub_age` | Seconds | Each ZFS pool | How long since its last scrub finished, while the last scan was a scrub |
| `zfs.scrub_repaired` | Bytes | Each ZFS pool | What its last scrub repaired |
| `zfs.scrub_errors` | Number | Each ZFS pool | Errors its last scrub found and couldn't repair |

## Built-in alerts

The built-in **RAID and ZFS** template brings these, for each array or pool:

| Alert | When | Severity |
| --- | --- | --- |
| **RAID failed** | It has failed for a minute | Critical |
| **RAID degraded** | It has been degraded for a minute, rebuilding or not | Critical |
| **RAID rebuilding** | It has been rebuilding for a minute | Warning |
| **ZFS pool has errors** | A pool's devices have had read, write or checksum errors, or it has data errors it couldn't repair | Warning, then critical for data errors |
| **ZFS pool nearly full** | A pool has been over 80% used for 15 minutes, or over 90% | Warning, then critical |
| **ZFS pool not scrubbed** | A pool's last scrub finished over 35 days ago | Warning |

A degraded array is critical even while it rebuilds, as one more failure then loses
data. **RAID rebuilding** only warns, to say redundancy isn't back yet: it's what
should happen after a device is replaced, and md resyncs every new array too.

ZFS counts errors until they're cleared with `zpool clear`, so **ZFS pool has errors**
stays open until someone has looked. ZFS never writes over data in place, so it needs
free space for every write and slows as a pool fills: the long-standing advice is to
keep pools under 80%, past 90% writes slow badly, and ZFS keeps the last few percent
back for itself, at least 128 MiB, so a pool of a few GiB stops taking writes before
90%: the 1 GiB pools tested were full at 86%. Ubuntu scrubs every pool once a month, and FreeBSD's periodic scrub
every 35 days when it's turned on, so 35 days means scrubs have stopped. A pool never
scrubbed doesn't alert.
