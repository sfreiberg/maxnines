# Whether each host's time service is keeping its clock in sync, as the host itself
# knows it: the kernel's own view on Linux, FreeBSD and macOS, and the Windows Time
# service's counters on Windows. The Host template's settings turn the time_sync
# collector on. How far each clock really is from the server's is the Host
# template's Clock is wrong alert, which this warns of before it happens.

template "time_sync" {
  name        = "Time sync"
  description = "Whether each host's time service is keeping its clock in sync, and how far out the clock could be since it last did."

  # A time service syncs within a minute or two of starting, though ntpd can take
  # a quarter of an hour before it tells the kernel so. Linux marks the clock
  # unsynced once it has gone about 9 hours without a correction, and a Mac with
  # Set time and date automatically turned off has it unsynced.
  alert "time_not_synced" {
    name    = "Time not synced"
    warning = "time_sync.synced < 1"
    for     = "30m"
    summary = "{{ hostname }}'s clock isn't being kept in sync by a time service"
  }

  # The kernel adds half a millisecond to the clock's largest possible error every
  # second until the time service next corrects it. chrony and systemd-timesyncd
  # correct it every minute or two, ntpd every few minutes and macOS's timed about
  # every quarter of an hour, keeping it under a second. 5 seconds means nearly 3
  # hours without a correction: the service has stopped or can't reach its time
  # sources. A clock first synced after a long time unsynced can start with an
  # error of a minute or more, which its next corrections bring down, hence the
  # half hour.
  alert "time_sync_stopped" {
    name    = "Time sync stopped"
    warning = "time_sync.max_error > duration('5s')"
    for     = "30m"
    summary = "{{ hostname }}'s time service hasn't corrected its clock for hours, so it could be {{ time_sync.max_error }} out"
  }
}
