# An example template for IIS, written in HCL with CEL for anything dynamic.
#
# Windows performance counters plus one registry read: the whole of it is
# this file, the way you'd write one for an app MaxNines doesn't know. It's
# an example of the format, not a template that comes with MaxNines.
#
# How counters turn into metrics:
#   - Each entry under `metrics` becomes a metric named iis.<entry>. A plain
#     string is the counter's name in that counter set.
#   - Units come from Windows' own naming: "/sec" counters are per second
#     already, names starting "Bytes" are bytes, names starting "%" are
#     percentages. Give a `unit` only when the name doesn't say.
#   - `total = true` marks a running total ("Total ..."), kept as a rate.
#   - `label = "site"` gives each instance (each site, pool, ...) its own series,
#     labelled site. _Total is always left out.
#   - `pattern` does the same with a regular expression whose named groups
#     become labels. Instances it doesn't match are left out.
#   - Series that end up with the same labels add up; percentages take the
#     highest instead.
#
# Choosing: `since = "8.0"` means from IIS 8.0 onwards; `when` is CEL over
# what discovery found.
#
# To see which counters a host has: typeperf -qx "W3SVC_W3WP"

template "iis" {
  name        = "IIS"
  description = "Sites, application pools, request queues and ASP.NET."
  service     = "W3SVC" # once on each Windows host with IIS's web service installed

  # What's installed matters more than the version on Windows: every supported
  # Windows Server ships IIS 10, but ASP.NET and some counter sets may or may
  # not be there. Each counter set below becomes true or false.
  discover "iis" {
    interval = "1h"
    registry "HKLM\\SOFTWARE\\Microsoft\\InetStp" {
      version = "VersionString" # "Version 10.0", read as version 10.0
    }
    counter_sets = {
      asp_net        = "ASP.NET"
      request_queues = "HTTP Service Request Queues"
      process_v2     = "Process V2"
    }
  }

  # For the host's own "Service stopped" alert to watch.
  services = ["W3SVC", "WAS"]

  # ---------------------------------------------------------------------------
  # Sites

  counters "sites" {
    object = "Web Service"
    label  = "site"
    metrics = {
      requests    = "Total Method Requests/sec"
      connections = "Current Connections"
      received    = "Bytes Received/sec"
      sent        = "Bytes Sent/sec"
      not_found   = "Not Found Errors/sec"
      site_uptime = { counter = "Service Uptime", unit = "s" }
    }
  }

  # ---------------------------------------------------------------------------
  # Application pools

  counters "app_pools" {
    object  = "APP_POOL_WAS"
    label   = "pool"
    exclude = [] # pools stopped on purpose; add them from the template's page
    metrics = {
      pool_state = {
        counter = "Current Application Pool State"
        states = {
          "1" = "Uninitialized", "2" = "Initialized", "3" = "Running", "4" = "Disabling",
          "5" = "Disabled", "6" = "Shutdown pending", "7" = "Delete pending"
        }
      }
      # Yes/no, for alerting: anything but Running (3) counts as not running.
      pool_running            = { counter = "Current Application Pool State", value = "value == 3" }
      pool_uptime             = { counter = "Current Application Pool Uptime", unit = "s" }
      worker_processes        = "Current Worker Processes"
      worker_failures         = { counter = "Total Worker Process Failures", total = true }
      worker_startup_failures = { counter = "Total Worker Process Startup Failures", total = true }
      worker_ping_failures    = { counter = "Total Worker Process Ping Failures", total = true }
      pool_recycles           = { counter = "Total Application Pool Recycles", total = true }
    }
  }

  # Worker processes are named "<pid>_<pool>". Only the pool is kept: the pid
  # changes on every recycle, which would start new series each time.
  counters "workers" {
    object  = "W3SVC_W3WP"
    pattern = "^\\d+_(?<pool>.+)$"
    metrics = {
      active_requests = "Active Requests"
      pool_requests   = "Requests / Sec"
      server_errors   = "% 500 HTTP Response Sent"
      websockets      = { counter = "WebSocket Active Requests", since = "8.0" }
    }
  }

  # http.sys queues requests for each pool until a worker process takes them.
  # A long queue means the pool can't keep up; rejected requests get a 503.
  counters "request_queues" {
    when   = "request_queues"
    object = "HTTP Service Request Queues"
    label  = "pool"
    metrics = {
      queue_length   = "CurrentQueueSize"
      queue_rejected = { counter = "RejectedRequests", total = true }
      queue_oldest   = { counter = "MaxQueueItemAge", value = "value / 1000", unit = "s" } # Windows gives ms
    }
  }

  # Memory and CPU per pool. Windows only counts these per process, so worker
  # processes are matched to pools by process ID: a group named in both
  # patterns (pid) joins them, and the other groups (pool) become labels.
  counters "pool_processes" {
    when    = "process_v2"
    object  = "Process V2"
    pattern = "^w3wp:(?<pid>\\d+)$" # newer Windows puts the process ID in the name
    join {
      object  = "W3SVC_W3WP"
      pattern = "^(?<pid>\\d+)_(?<pool>.+)$"
    }
    metrics = {
      pool_memory = { counter = "Working Set - Private", unit = "bytes" }
      pool_cpu    = { counter = "% Processor Time", value = "value / facts.cpu.logical_cores" } # 100% per core otherwise
    }
  }

  # The same on older Windows, which names them w3wp, w3wp#1, w3wp#2, ... and
  # gives the process ID as a counter of its own.
  counters "pool_processes_older" {
    when    = "!process_v2"
    object  = "Process"
    pattern = "^w3wp(#\\d+)?$"
    groups  = { pid = "ID Process" } # a group whose value is read from a counter
    join {
      object  = "W3SVC_W3WP"
      pattern = "^(?<pid>\\d+)_(?<pool>.+)$"
    }
    metrics = {
      pool_memory = { counter = "Working Set - Private", unit = "bytes" }
      pool_cpu    = { counter = "% Processor Time", value = "value / facts.cpu.logical_cores" }
    }
  }

  # ---------------------------------------------------------------------------
  # ASP.NET

  counters "asp_net" {
    when   = "asp_net"
    object = "ASP.NET"
    metrics = {
      aspnet_queued   = "Requests Queued"
      aspnet_rejected = { counter = "Requests Rejected", total = true }
      aspnet_restarts = { counter = "Application Restarts", total = true }
    }
  }

  counters "asp_net_apps" {
    when     = "asp_net"
    object   = "ASP.NET Applications"
    instance = "__Total__" # just the one instance, for all applications together
    metrics = {
      aspnet_requests = "Requests/Sec"
      aspnet_errors   = "Errors Total/Sec"
    }
  }

  # ---------------------------------------------------------------------------
  # Alerts, written as in postgres.hcl: CEL conditions over metrics by name.

  alert "pool_stopped" {
    name             = "Application pool stopped"
    critical         = "!pool_running"
    for              = "1m"
    summary          = "{{ hostname }}: application pool {{ labels.pool }} is {{ pool_state }}"
    resolved_summary = "{{ hostname }}: application pool {{ labels.pool }} is running again"
  }

  alert "workers_crashing" {
    name    = "Worker processes crashing"
    warning = "worker_failures > 0"
    summary = "{{ hostname }}: worker processes in {{ labels.pool }} are crashing; IIS stops the pool if it keeps happening"
  }

  alert "workers_hanging" {
    name    = "Worker processes not answering"
    warning = "worker_ping_failures > 0"
    summary = "{{ hostname }}: a worker process in {{ labels.pool }} stopped answering and was restarted"
  }

  alert "queue_backing_up" {
    name     = "Requests queueing"
    warning  = "queue_length > 100"
    critical = "queue_length > 1000 || queue_oldest > duration('30s')"
    for      = "2m"
    summary  = "{{ hostname }}: {{ queue_length }} requests are waiting for {{ labels.pool }}, the oldest for {{ queue_oldest }}"
  }

  alert "requests_rejected" {
    name     = "Requests turned away"
    critical = "queue_rejected > 0"
    for      = "1m"
    summary  = "{{ hostname }}: {{ labels.pool }}'s queue is full and visitors are getting 503s"
  }

  # Only once there's traffic: 1 error in 3 requests at 3am isn't an outage.
  alert "server_errors" {
    name     = "Server errors"
    warning  = "server_errors > 2 && pool_requests > 1"
    critical = "server_errors > 10 && pool_requests > 1"
    for      = "5m"
    summary  = "{{ hostname }}: {{ server_errors }} of {{ labels.pool }}'s responses are 500 errors"
  }

  # Off until someone says how much is too much for their applications.
  alert "pool_memory" {
    enabled = false
    name    = "Application pool using a lot of memory"
    warning = "pool_memory > gib(2)"
    for     = "10m"
    summary = "{{ hostname }}: {{ labels.pool }} is using {{ pool_memory }} of memory"
  }

  alert "aspnet_queueing" {
    name     = "ASP.NET requests queueing"
    warning  = "aspnet_queued > 100"
    critical = "aspnet_queued > 1000"
    for      = "2m"
    summary  = "{{ hostname }}: {{ aspnet_queued }} ASP.NET requests are waiting for a thread"
  }
}
