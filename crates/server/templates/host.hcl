# What every host is watched for, whatever runs on it: hosts with an agent and
# hosts with only checks alike. With no database, service or operating systems
# named, a template runs once on every host.

template "host" {
  name        = "Host"
  description = "Whether each host is online and sending metrics, its disks, clock, services and containers, and whether templates read its databases with accounts that can do more than read."

  # The agent settings every host gets, as the config rule named Host. Rules of
  # your own apply over it.
  config {
    interval_secs       = 15
    facts_interval_secs = 3600
    collectors = {
      host    = { enabled = true }
      cpu     = { enabled = true }
      memory  = { enabled = true }
      disk    = { enabled = true }
      network = { enabled = true }
      system  = { enabled = true }
      smart   = { enabled = true }
      raid    = { enabled = true }
      updates = { enabled = true }
    }
  }

  alert "offline" {
    name             = "Host offline"
    critical         = "!online"
    for              = "1m"
    summary          = "{{ hostname }} is offline"
    resolved_summary = "{{ hostname }} is back online"
  }

  alert "disk_filling_up" {
    name     = "Disk filling up"
    warning  = "disk.usage > 80"
    critical = "disk.usage > 90"
    for      = "5m"
  }

  alert "container_down" {
    name     = "Container down"
    critical = "container.up < 1"
    for      = "1m"
  }

  # The straight line through the last 6 hours of each disk's usage.
  alert "disk_full_soon" {
    name     = "Disk will be full soon"
    warning  = "forecast(disk.usage, duration('24h')) >= 100"
    critical = "forecast(disk.usage, duration('4h')) >= 100"
    for      = "30m"
    window   = "6h"
  }

  alert "inodes_running_out" {
    name     = "Disk running out of inodes"
    warning  = "disk.inodes > 80"
    critical = "disk.inodes > 90"
    for      = "5m"
  }

  alert "clock_wrong" {
    name     = "Clock is wrong"
    warning  = "clock.difference > duration('5s')"
    critical = "clock.difference > duration('30s')"
    for      = "1m"
  }

  # Long enough for a restart, and no longer: a service that's down is down.
  alert "service_stopped" {
    name     = "Service stopped"
    critical = "service.running < 1"
    for      = "1m"
  }

  # A connected agent whose samples all stop being stored, such as after a change
  # to what agents send, never goes offline, so nothing else notices.
  alert "no_metrics" {
    name             = "Host sending no metrics"
    critical         = "!reporting"
    for              = "5m"
    summary          = "{{ hostname }} is connected but sending no metrics"
    resolved_summary = "{{ hostname }} is sending metrics again"
  }

  # MaxNines only ever reads, but an account that could do more is one a
  # template's SQL, or anyone with its password, could misuse.
  alert "database_account_overprivileged" {
    name    = "Database account can do more than read"
    warning = "database_account.overprivileged > 0"
    for     = "1m"
  }
}
