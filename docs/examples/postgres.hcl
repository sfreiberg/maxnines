# An example template for PostgreSQL, written in HCL with CEL for anything
# dynamic: health, load, replication and archiving, with the alerts on them.
# It's an example of the format, not a template that comes with MaxNines.
#
# How a query turns into metrics:
#   - Each numeric column becomes a metric named postgres.<column>.
#   - True/false columns become yes/no flags. Interval columns become seconds.
#   - List a column under `metrics` only to say more about it: a running total
#     (`total = true`), a unit, or a description.
#   - Text columns named in `labels` tell rows apart, one series per row. Other
#     text columns are shown on the host page.
#   - NULL gives no sample, rather than zero.
#
# Choosing by version and role:
#   - `since = "13"` means only from version 13 onwards.
#   - `fill` picks a piece of SQL by version, so a query is written only once.
#   - `when` is CEL over what discovery found: role, archiving and so on.
#
# `enabled = false` ships something turned off.

template "postgres" {
  name        = "PostgreSQL"
  description = "Health, load, replication and archiving."
  database    = "postgres" # once for each PostgreSQL database in the agent's config
  min_version = "10"

  # Runs first, then every minute, so a failover switches queries quickly.
  # Its columns are what `when` and `since` look at. `version` is read as a
  # version, so 9.6 < 13 < 16.2.
  discover {
    interval = "1m"
    sql      = <<-SQL
      SELECT current_setting('server_version')                                AS version,
             CASE WHEN pg_is_in_recovery() THEN 'replica' ELSE 'primary' END AS role,
             current_setting('archive_mode') IN ('on', 'always')              AS archiving,
             pg_has_role(current_user, 'pg_read_all_stats', 'MEMBER')         AS sees_all_sessions
    SQL
  }

  notice "cannot_see_sessions" {
    when = "!sees_all_sessions"
    text = "The account can't see other sessions, so session counts are low. Grant it pg_monitor."
  }

  # ---------------------------------------------------------------------------
  # Health and load

  query "sessions" {
    sql = <<-SQL
      SELECT now() - pg_postmaster_start_time()                          AS uptime,
             count(*)                                                    AS connections,
             count(*) * 100.0 / (current_setting('max_connections')::int
                                 - current_setting('superuser_reserved_connections')::int)
                                                                         AS connections_used,
             count(*) FILTER (WHERE state = 'active')                    AS running_queries,
             count(*) FILTER (WHERE state LIKE 'idle in transaction%')   AS idle_in_transaction,
             count(*) FILTER (WHERE wait_event_type = 'Lock')            AS lock_waits,
             coalesce(max(now() - xact_start), '0s')                     AS oldest_transaction,
             coalesce(max(now() - query_start) FILTER (WHERE state = 'active'), '0s')
                                                                         AS oldest_query,
             coalesce(max(now() - state_change) FILTER (WHERE state LIKE 'idle in transaction%'), '0s')
                                                                         AS oldest_idle_in_transaction
      FROM pg_stat_activity
      WHERE backend_type = 'client backend' AND pid <> pg_backend_pid()
    SQL
    metrics = {
      connections_used = { unit = "%", description = "Connections in use, out of those not reserved for superusers" }
    }
  }

  query "throughput" {
    sql = <<-SQL
      SELECT sum(xact_commit + xact_rollback) AS transactions, sum(xact_rollback) AS rollbacks,
             sum(blks_read) AS blocks_read, sum(blks_hit) AS blocks_hit,
             sum(temp_bytes) AS temp_written, sum(deadlocks) AS deadlocks, sum(conflicts) AS conflicts,
             {{ checksums }} AS checksum_failures
      FROM pg_stat_database
    SQL
    fill "checksums" {
      versions = { "12" = "coalesce(sum(checksum_failures), 0)" }
      older    = "NULL"
    }
    metrics = {
      transactions      = { total = true }
      rollbacks         = { total = true }
      temp_written      = { total = true, unit = "bytes" }
      deadlocks         = { total = true }
      conflicts         = { total = true }
      checksum_failures = { total = true }
      blocks_read       = { total = true }
      blocks_hit        = { total = true }
      # Worked out from the other columns as each sample arrives.
      cache_hit = {
        value       = "rate(blocks_hit) / (rate(blocks_hit) + rate(blocks_read)) * 100"
        unit        = "%"
        description = "Reads served from memory rather than disk"
      }
    }
  }

  query "checkpoints" {
    sql = "SELECT {{ checkpoints }}"
    fill "checkpoints" {
      # Moved to a view of its own in 17.
      versions = { "17" = "num_timed AS checkpoints_timed, num_requested AS checkpoints_requested FROM pg_stat_checkpointer" }
      older    = "checkpoints_timed, checkpoints_req AS checkpoints_requested FROM pg_stat_bgwriter"
    }
    metrics = {
      checkpoints_timed     = { total = true }
      checkpoints_requested = { total = true, description = "Checkpoints forced by WAL filling up; often a sign max_wal_size is too small" }
    }
  }

  query "wal" {
    since   = "14"
    sql     = "SELECT wal_bytes AS wal_written FROM pg_stat_wal"
    metrics = { wal_written = { total = true, unit = "bytes" } }
  }

  # What, left alone, ends up stopping the server.
  query "housekeeping" {
    interval = "1m"
    sql      = <<-SQL
      SELECT coalesce(max(age(datfrozenxid)), 0)    AS xid_age,
             coalesce(max(mxid_age(datminmxid)), 0) AS mxid_age,
             (SELECT count(*) FROM pg_prepared_xacts) AS prepared,
             (SELECT coalesce(max(now() - prepared), '0s') FROM pg_prepared_xacts) AS oldest_prepared
      FROM pg_database WHERE datallowconn
    SQL
    metrics = {
      xid_age = { description = "Transactions since the oldest database was last frozen; the server stops near 2.1 billion" }
    }
  }

  # ---------------------------------------------------------------------------
  # Replication, seen from a primary

  # One row per standby. Standbys left at the defaults share an application
  # name, so the address is a label too.
  query "standbys" {
    when   = "role == 'primary'"
    sql    = <<-SQL
      SELECT coalesce(nullif(application_name, ''), 'unnamed') AS application,
             coalesce(host(client_addr), 'local')              AS address,
             state = 'streaming'                               AS standby_streaming,
             sync_state IN ('sync', 'quorum')                  AS standby_synchronous,
             pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn) AS lag_bytes,
             replay_lag                                        AS lag
      FROM pg_stat_replication
    SQL
    labels  = ["application", "address"]
    metrics = { lag_bytes = { unit = "bytes" } }
  }

  # Counted separately: with no standbys the query above returns no rows, and
  # no rows means no samples, not zero.
  query "standby_count" {
    when = "role == 'primary'"
    sql  = <<-SQL
      SELECT count(*) FILTER (WHERE state = 'streaming')              AS standbys,
             count(*) FILTER (WHERE sync_state IN ('sync', 'quorum')) AS synchronous_standbys
      FROM pg_stat_replication
    SQL
  }

  # ---------------------------------------------------------------------------
  # Replication, seen from a replica

  query "replay" {
    when = "role == 'replica'"
    sql  = <<-SQL
      SELECT CASE WHEN pg_last_wal_receive_lsn() = pg_last_wal_replay_lsn() THEN '0s'
                  ELSE greatest('0s', now() - pg_last_xact_replay_timestamp())
             END                                                                  AS lag,
             pg_wal_lsn_diff(pg_last_wal_receive_lsn(), pg_last_wal_replay_lsn()) AS replay_backlog,
             {{ paused }}                                                         AS replay_paused
    SQL
    fill "paused" {
      versions = { "14" = "pg_get_wal_replay_pause_state() <> 'not paused'" }
      older    = "pg_is_wal_replay_paused()"
    }
    metrics = { replay_backlog = { unit = "bytes" } }
  }

  # Caught up says nothing if nothing's arriving. The LEFT JOIN turns "no
  # receiver at all" into a row saying it isn't receiving.
  query "receiver" {
    when = "role == 'replica'"
    sql  = <<-SQL
      SELECT coalesce(r.status = 'streaming', false) AS receiving,
             now() - r.last_msg_receipt_time         AS last_received,
             r.received_tli                          AS timeline
      FROM (SELECT 1) AS one LEFT JOIN pg_stat_wal_receiver AS r ON true
    SQL
  }

  # ---------------------------------------------------------------------------
  # Replication slots, on primaries and replicas

  query "slots" {
    sql = <<-SQL
      SELECT slot_name                AS slot,
             active                   AS slot_in_use,
             {{ wal_status }}         AS wal_status,
             {{ headroom }}           AS slot_headroom,
             pg_wal_lsn_diff(CASE WHEN pg_is_in_recovery() THEN pg_last_wal_replay_lsn()
                                  ELSE pg_current_wal_lsn() END, restart_lsn) AS slot_retained,
             {{ lost }}               AS slot_lost
      FROM pg_replication_slots WHERE NOT temporary
    SQL
    fill "wal_status" {
      versions = { "13" = "wal_status" }
      older    = "NULL"
    }
    fill "headroom" {
      versions = { "13" = "safe_wal_size" }
      older    = "NULL"
    }
    fill "lost" {
      versions = {
        "17" = "invalidation_reason IS NOT NULL OR wal_status = 'lost'"
        "13" = "wal_status = 'lost'"
      }
      older = "NULL" # before 13 a slot can't be lost: it keeps WAL until the disk fills
    }
    labels = ["slot"]
    metrics = {
      slot_retained = { unit = "bytes" }
      slot_headroom = { unit = "bytes", description = "WAL left before the slot is lost; none unless max_slot_wal_keep_size is set" }
    }
  }

  # ---------------------------------------------------------------------------
  # Archiving

  query "archiving" {
    when = "archiving"
    sql  = <<-SQL
      SELECT archived_count AS archived, failed_count AS archive_failures,
             coalesce(last_failed_time > coalesce(last_archived_time, '-infinity'), false) AS archive_failing
      FROM pg_stat_archiver
    SQL
    metrics = {
      archived         = { total = true }
      archive_failures = { total = true }
    }
  }

  query "archive_waiting" {
    when    = "archiving"
    since   = "12"
    sql     = "SELECT count(*) AS archive_waiting FROM pg_ls_archive_statusdir() WHERE name LIKE '%.ready'"
    metrics = { archive_waiting = { description = "WAL files waiting to be archived" } }
  }

  # ---------------------------------------------------------------------------
  # Logical replication into the database signed in to

  query "subscriptions" {
    sql = <<-SQL
      SELECT s.subname AS subscription,
             EXISTS (SELECT 1 FROM pg_stat_subscription w
                     WHERE w.subid = s.oid AND w.pid IS NOT NULL AND w.relid IS NULL) AS subscription_running,
             {{ errors }} AS subscription_errors
      FROM pg_subscription s
      WHERE s.subenabled AND s.subdbid = (SELECT oid FROM pg_database WHERE datname = current_database())
    SQL
    fill "errors" {
      versions = { "15" = "(SELECT apply_error_count + sync_error_count FROM pg_stat_subscription_stats t WHERE t.subid = s.oid)" }
      older    = "NULL"
    }
    labels  = ["subscription"]
    metrics = { subscription_errors = { total = true } }
  }

  # ---------------------------------------------------------------------------
  # Sizes: slow on big servers, so they ship turned off.

  query "sizes" {
    enabled  = false
    interval = "5m"
    sql      = <<-SQL
      SELECT datname AS database, pg_database_size(oid) AS size
      FROM pg_database WHERE datallowconn AND has_database_privilege(oid, 'CONNECT')
    SQL
    labels  = ["database"]
    metrics = { size = { unit = "bytes" } }
  }

  query "wal_size" {
    enabled  = false
    interval = "5m"
    sql      = "SELECT coalesce(sum(size), 0) AS wal_size FROM pg_ls_waldir()"
    metrics  = { wal_size = { unit = "bytes" } }
  }

  # ---------------------------------------------------------------------------
  # Alerts. `warning` and `critical` are CEL conditions; either can be left out.
  #   - Metrics are used by name: `lag` here means postgres.lag, and other
  #     templates' metrics work by their full names (cpu.load). Facts are under
  #     `facts.` (facts.cpu.logical_cores); discovery's columns by their names.
  #   - A metric with labels, used as it is, gives one alert per series: one per
  #     slot, one per standby. `slot_retained['main']` would pick one.
  #   - Durations are duration('5m'); sizes are gib(10), mib(512), ...
  # `summary` is the text channels send. {{ lag }} and the like are written in
  # the metric's unit ("3m 12s", "4.2 GiB").

  # `up` is every database template's: false when the agent can't sign in.
  alert "down" {
    name             = "PostgreSQL down"
    critical         = "!up"
    for              = "1m"
    summary          = "{{ hostname }}: PostgreSQL {{ instance }} isn't answering"
    resolved_summary = "{{ hostname }}: PostgreSQL {{ instance }} is answering again"
  }

  alert "connections_running_out" {
    name     = "PostgreSQL connections running out"
    warning  = "connections_used > 80"
    critical = "connections_used > 90"
    for      = "5m"
    summary  = "{{ hostname }}: {{ instance }} is using {{ connections_used }} of its connections"
  }

  alert "long_transaction" {
    name    = "Long-running transaction"
    warning = "oldest_transaction > duration('1h')"
    for     = "1m"
    summary = "{{ hostname }}: a transaction on {{ instance }} has been open for {{ oldest_transaction }}, holding back vacuum"
  }

  alert "wraparound" {
    name     = "Transaction IDs running out"
    warning  = "xid_age > 1000000000"
    critical = "xid_age > 1500000000"
    for      = "10m"
    summary  = "{{ hostname }}: {{ instance }} is {{ xid_age }} transactions from its last freeze; it stops near 2.1 billion"
  }

  alert "checksum_failures" {
    name     = "Data checksum failures"
    since    = "12"
    critical = "checksum_failures > 0"
    summary  = "{{ hostname }}: {{ instance }} found pages that fail their checksums, which usually means a bad disk"
  }

  alert "replica_lagging" {
    name     = "Replica lagging"
    when     = "role == 'replica'"
    warning  = "lag > duration('30s')"
    critical = "lag > duration('5m')"
    for      = "2m"
    summary  = "{{ hostname }}: replica {{ instance }} is {{ lag }} behind its primary"
  }

  # Lagging but still receiving is a slow replica; not receiving is a broken one.
  alert "replica_not_receiving" {
    name     = "Replica not receiving"
    when     = "role == 'replica'"
    critical = "!receiving"
    for      = "2m"
    summary  = "{{ hostname }}: replica {{ instance }} hasn't received anything from its primary for {{ last_received }}"
  }

  alert "standby_lagging" {
    name     = "Standby falling behind"
    when     = "role == 'primary'"
    warning  = "lag > duration('30s')"
    critical = "lag > duration('5m')"
    for      = "2m"
    summary  = "{{ hostname }}: standby {{ labels.application }} ({{ labels.address }}) is {{ lag }} behind {{ instance }}"
  }

  # Off until someone says how many standbys a primary should have.
  alert "too_few_standbys" {
    enabled  = false
    name     = "Too few standbys"
    when     = "role == 'primary'"
    critical = "standbys < 1"
    for      = "2m"
    summary  = "{{ hostname }}: only {{ standbys }} standbys are streaming from {{ instance }}"
  }

  alert "slot_unused" {
    name    = "Replication slot unused"
    warning = "!slot_in_use"
    for     = "30m"
    summary = "{{ hostname }}: nothing has used slot {{ labels.slot }} on {{ instance }} for 30 minutes; it keeps WAL until something does"
  }

  # Unused and holding a lot is what fills disks; either alone is often fine.
  alert "slot_retaining_wal" {
    name     = "Replication slot holding WAL"
    warning  = "slot_retained > gib(10)"
    critical = "slot_retained > gib(50) || (!slot_in_use && slot_retained > gib(10))"
    for      = "5m"
    summary  = "{{ hostname }}: slot {{ labels.slot }} on {{ instance }} is holding {{ slot_retained }} of WAL"
  }

  alert "slot_lost" {
    name     = "Replication slot lost"
    since    = "13"
    critical = "slot_lost"
    summary  = "{{ hostname }}: slot {{ labels.slot }} on {{ instance }} was lost; whatever used it has to be rebuilt"
  }

  alert "archiving_failing" {
    name     = "WAL archiving failing"
    when     = "archiving"
    critical = "archive_failing"
    for      = "5m"
    summary  = "{{ hostname }}: {{ instance }} can't archive WAL, so it piles up on disk"
  }

  alert "subscription_stopped" {
    name     = "Subscription stopped"
    critical = "!subscription_running"
    for      = "5m"
    summary  = "{{ hostname }}: subscription {{ labels.subscription }} on {{ instance }} isn't running"
  }
}
