# Each software RAID array and ZFS pool, which the agent reads from /proc/mdstat
# and zpool on Linux, zpool on FreeBSD, Storage Spaces on Windows and diskutil on
# macOS. The Host template's settings turn the raid collector on. Hardware RAID
# cards aren't read, as each maker's needs its own tool.

template "raid" {
  name        = "RAID and ZFS"
  description = "Each software RAID array and ZFS pool: whether it's degraded, failed or rebuilding, and for ZFS its errors, how full it is and how long since it was scrubbed."

  # Failed means what's on it can't be read: an md array missing more devices than
  # it can do without, or one that hasn't started, a ZFS pool FAULTED, UNAVAIL or
  # SUSPENDED, a Storage Spaces virtual disk detached, an AppleRAID set offline.
  alert "raid_failed" {
    name     = "RAID failed"
    critical = "raid.failed >= 1"
    for      = "1m"
    summary  = "{{ series }} on {{ hostname }} has failed"
  }

  # Degraded still works, but has lost redundancy, so one more failure loses
  # data. It's critical for that reason, even while it rebuilds.
  alert "raid_degraded" {
    name     = "RAID degraded"
    critical = "raid.degraded >= 1"
    for      = "1m"
    summary  = "{{ series }} on {{ hostname }} is degraded"
  }

  # Rebuilding is what should happen after a device is replaced, so it only warns,
  # to say redundancy isn't back yet. An array a rebuild leaves degraded alerts on
  # its own. md resyncs a new array and one shut down uncleanly too.
  alert "raid_rebuilding" {
    name    = "RAID rebuilding"
    warning = "raid.rebuilding >= 1"
    for     = "1m"
    summary = "{{ series }} on {{ hostname }} is rebuilding"
  }

  # ZFS counts each read, write and checksum error a device has had since the pool
  # was imported or `zpool clear` was run, so this stays open until someone looks
  # and clears them. Data errors are what ZFS couldn't repair, so files are lost.
  alert "zfs_errors" {
    name     = "ZFS pool has errors"
    warning  = "zfs.read_errors > 0 || zfs.write_errors > 0 || zfs.checksum_errors > 0"
    critical = "zfs.data_errors > 0"
    for      = "1m"
    summary  = "ZFS pool {{ series }} on {{ hostname }} has had errors"
  }

  # ZFS never writes over data in place, so it needs free space for every write,
  # and finding it takes longer as a pool fills and what's free is scattered: the
  # long-standing advice is to keep pools under 80%. Past 90% writes slow badly,
  # and ZFS keeps the last few percent back for itself, so writes fail before 100.
  alert "zfs_full" {
    name     = "ZFS pool nearly full"
    warning  = "zfs.used > 80"
    critical = "zfs.used > 90"
    for      = "15m"
    summary  = "ZFS pool {{ series }} on {{ hostname }} is {{ zfs.used }} full"
  }

  # A scrub reads everything and repairs what has gone bad while there's still a
  # good copy. Ubuntu's zfsutils scrubs every pool once a month, and FreeBSD's
  # periodic scrub, when turned on, every 35 days, so 35 days means it has stopped.
  # A pool never scrubbed, or whose last scan was a resilver, has no age to go on.
  alert "zfs_scrub_overdue" {
    name    = "ZFS pool not scrubbed"
    warning = "zfs.scrub_age > duration('840h')"
    for     = "1h"
    summary = "ZFS pool {{ series }} on {{ hostname }} hasn't been scrubbed for {{ zfs.scrub_age }}"
  }
}
