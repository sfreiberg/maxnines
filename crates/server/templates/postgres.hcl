# PostgreSQL's health, load, replication and archiving, with the alerts on them.
# It runs once for each PostgreSQL database: each `database` block of that kind in
# an agent's config, each PostgreSQL check that reads stats on a host without an
# agent, and MaxNines' own database when that's PostgreSQL.
#
# Every query works for an account in pg_monitor. Without it, other sessions'
# details and some views are hidden, which the template's notice says.

template "postgres" {
  name        = "PostgreSQL"
  description = "Health, load, replication and archiving, for an account in pg_monitor."
  database    = "postgres"
  min_version = "10"

  # What `when` and `since` look at. `version` is read as a version, so 9.6 < 13 < 16.2.
  discover "server" {
    interval = "1h"
    sql      = <<-SQL
      SELECT current_setting('server_version')                        AS version,
             current_setting('archive_mode') IN ('on', 'always')      AS archiving,
             pg_has_role(current_user, 'pg_read_all_stats', 'MEMBER') AS sees_all_sessions
    SQL
  }

  # Every ten seconds, so a failover switches queries quickly.
  discover "role" {
    interval = "10s"
    sql      = "SELECT CASE WHEN pg_is_in_recovery() THEN 'replica' ELSE 'primary' END AS role"
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
             pg_is_in_recovery()                                         AS replica,
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
      uptime                     = { title = "PostgreSQL uptime", unit = "s" }
      replica                    = { title = "PostgreSQL is a replica", description = "Whether it's a replica, replaying another server's WAL" }
      connections_used           = { title = "PostgreSQL connections used of the limit", unit = "%", description = "Connections in use, out of those not reserved for superusers" }
      oldest_transaction         = { title = "PostgreSQL oldest open transaction", unit = "s", description = "How long the longest open transaction has been open; a long one holds back vacuum" }
      oldest_query               = { title = "PostgreSQL longest-running query", unit = "s" }
      oldest_idle_in_transaction = { title = "PostgreSQL longest idle in a transaction", unit = "s" }
      connections                = { title = "PostgreSQL connections" }
      running_queries            = { title = "PostgreSQL queries running" }
      idle_in_transaction        = { title = "PostgreSQL sessions idle in a transaction" }
      lock_waits                 = { title = "PostgreSQL sessions waiting on locks" }
    }
  }

  # Running totals across every database on the server.
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
      older    = "0"
    }
    metrics = {
      transactions      = { title = "PostgreSQL transactions", total = true }
      rollbacks         = { title = "PostgreSQL rollbacks", total = true }
      temp_written      = { title = "PostgreSQL temporary files written", total = true, unit = "bytes", description = "Temporary files written by queries too big for work_mem" }
      deadlocks         = { title = "PostgreSQL deadlocks", total = true }
      conflicts         = { title = "PostgreSQL queries cancelled by replication", total = true, description = "Queries on a replica cancelled because of what it was replaying" }
      checksum_failures = { title = "PostgreSQL checksum failures", total = true }
      blocks_read       = { title = "PostgreSQL blocks read from disk", total = true, description = "Blocks read from disk rather than memory" }
      blocks_hit        = { title = "PostgreSQL blocks found in memory", total = true, description = "Blocks found in memory" }
      # Worked out from the other columns as each sample arrives.
      cache_hit = {
        title       = "PostgreSQL cache hit rate"
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
      checkpoints_timed     = { title = "PostgreSQL scheduled checkpoints", total = true }
      checkpoints_requested = { title = "PostgreSQL requested checkpoints", total = true, description = "Checkpoints forced by WAL filling up; often a sign max_wal_size is too small" }
    }
  }

  query "wal" {
    since   = "14"
    sql     = "SELECT wal_bytes AS wal_written FROM pg_stat_wal"
    metrics = {
      wal_written = { title = "PostgreSQL WAL written", total = true, unit = "bytes" }
    }
  }

  # What, left alone, ends up stopping the server: transaction IDs running out,
  # and transactions prepared and never finished.
  query "housekeeping" {
    sql = <<-SQL
      SELECT coalesce(max(age(datfrozenxid)), 0)    AS xid_age,
             coalesce(max(mxid_age(datminmxid)), 0) AS mxid_age,
             (SELECT count(*) FROM pg_prepared_xacts) AS prepared,
             (SELECT coalesce(max(now() - prepared), '0s') FROM pg_prepared_xacts) AS oldest_prepared
      FROM pg_database WHERE datallowconn
    SQL
    metrics = {
      xid_age         = { title = "PostgreSQL transaction ID age (wraparound)", description = "Transactions since the oldest database was last frozen; the server stops near 2.1 billion" }
      oldest_prepared = { title = "PostgreSQL oldest prepared transaction", unit = "s" }
      mxid_age        = { title = "PostgreSQL multixact ID age (wraparound)" }
      prepared        = { title = "PostgreSQL prepared transactions" }
    }
  }

  # ---------------------------------------------------------------------------
  # Replication, seen from a primary

  # One row for each standby. Standbys left at the defaults share an application
  # name, so the address is a label too.
  query "standbys" {
    when   = "role == 'primary'"
    sql    = <<-SQL
      SELECT coalesce(nullif(application_name, ''), 'unnamed') AS application,
             coalesce(host(client_addr), 'local')              AS address,
             state = 'streaming'                               AS streaming,
             pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn) AS lag_bytes,
             replay_lag                                        AS lag
      FROM pg_stat_replication
    SQL
    labels = ["application", "address"]
    metrics = {
      lag_bytes = { title = "PostgreSQL standby lag in bytes", unit = "bytes" }
      # Unknown until a standby has replayed something, and again once it's caught
      # up with nothing new, when its bytes behind say it's caught up.
      lag       = { title = "PostgreSQL replication lag", unit = "s", description = "How far behind a replica is, or each standby, as its primary sees it" }
      streaming = { title = "PostgreSQL standby streaming" }
    }
  }

  # Counted on their own: with no standbys the query above has no rows, and no
  # rows means no samples, not zero. A standby is one streaming and replaying what
  # it's sent, which leaves out one still catching up, pg_basebackup and
  # pg_receivewal, which replay nothing, and logical replication's subscribers.
  query "standby_count" {
    when = "role == 'primary'"
    sql  = <<-SQL
      SELECT count(*) FILTER (WHERE state = 'streaming' AND replay_lsn IS NOT NULL
                                AND pid NOT IN (SELECT active_pid FROM pg_replication_slots
                                                WHERE slot_type = 'logical'
                                                  AND active_pid IS NOT NULL)) AS standbys,
             count(*) FILTER (WHERE sync_state IN ('sync', 'quorum'))          AS synchronous_standbys
      FROM pg_stat_replication
    SQL
    metrics = {
      standbys             = { title = "PostgreSQL standbys streaming" }
      synchronous_standbys = { title = "PostgreSQL synchronous standbys" }
    }
  }

  # ---------------------------------------------------------------------------
  # Replication, seen from a replica

  # The time since the last transaction replayed is only lag while there's more
  # to replay. With all of it replayed, an idle primary would otherwise look
  # further and further behind.
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
    metrics = {
      lag            = { title = "PostgreSQL replication lag", unit = "s" }
      replay_backlog = { title = "PostgreSQL WAL received but not replayed", unit = "bytes", description = "WAL received but not replayed yet" }
      replay_paused  = { title = "PostgreSQL replay paused" }
    }
  }

  # Caught up says nothing if nothing's arriving. The LEFT JOIN turns no receiver
  # at all into a row saying it isn't receiving.
  query "receiver" {
    when = "role == 'replica'"
    sql  = <<-SQL
      SELECT coalesce(r.status = 'streaming', false) AS receiving,
             now() - r.last_msg_receipt_time         AS last_received,
             r.received_tli                          AS timeline
      FROM (SELECT 1) AS one LEFT JOIN pg_stat_wal_receiver AS r ON true
    SQL
    metrics = {
      last_received = { title = "PostgreSQL time since the replica heard from its primary", unit = "s", description = "How long since the replica heard from its primary" }
      timeline      = { title = "PostgreSQL timeline", description = "Rises after a failover" }
      receiving     = { title = "PostgreSQL replica receiving" }
    }
  }

  # ---------------------------------------------------------------------------
  # Replication slots, on primaries and replicas

  query "slots" {
    sql = <<-SQL
      SELECT slot_name::text           AS slot,
             active                    AS slot_in_use,
             {{ headroom }}            AS slot_headroom,
             pg_wal_lsn_diff(CASE WHEN pg_is_in_recovery() THEN pg_last_wal_replay_lsn()
                                  ELSE pg_current_wal_lsn() END, restart_lsn) AS slot_retained,
             {{ lost }}                AS slot_lost
      FROM pg_replication_slots WHERE NOT temporary
    SQL
    fill "headroom" {
      versions = { "13" = "safe_wal_size" }
      older    = "NULL"
    }
    fill "lost" {
      versions = {
        "17" = "invalidation_reason IS NOT NULL OR wal_status = 'lost'"
        "13" = "wal_status = 'lost'"
      }
      older = "false" # before 13 a slot can't be lost: it keeps WAL until the disk fills
    }
    labels = ["slot"]
    metrics = {
      slot_retained = { title = "PostgreSQL WAL kept by a replication slot", unit = "bytes", description = "WAL kept for the slot; an unused slot keeps it until the disk fills" }
      slot_headroom = { title = "PostgreSQL WAL a slot can still keep", unit = "bytes", description = "WAL left before the slot is lost; none unless max_slot_wal_keep_size is set" }
      slot_in_use   = { title = "PostgreSQL replication slot in use" }
      slot_lost     = { title = "PostgreSQL replication slot lost" }
    }
  }

  # ---------------------------------------------------------------------------
  # Archiving, only when archive_mode is on

  query "archiving" {
    when = "archiving"
    sql  = <<-SQL
      SELECT archived_count AS archived, failed_count AS archive_failures,
             coalesce(last_failed_time > coalesce(last_archived_time, '-infinity'), false) AS archive_failing
      FROM pg_stat_archiver
    SQL
    metrics = {
      archived         = { title = "PostgreSQL WAL files archived", total = true }
      archive_failures = { title = "PostgreSQL archiving failures", total = true }
      archive_failing  = { title = "PostgreSQL archiving failing" }
    }
  }

  query "archive_waiting" {
    when    = "archiving"
    since   = "12"
    sql     = "SELECT count(*) AS archive_waiting FROM pg_ls_archive_statusdir() WHERE name LIKE '%.ready'"
    metrics = {
      archive_waiting = { title = "PostgreSQL WAL files waiting to be archived", description = "WAL files waiting to be archived" }
    }
  }

  # ---------------------------------------------------------------------------
  # Logical replication into the database signed in to

  query "subscriptions" {
    sql = <<-SQL
      SELECT s.subname::text AS subscription,
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
    metrics = {
      subscription_errors  = { title = "PostgreSQL subscription errors", total = true }
      subscription_running = { title = "PostgreSQL subscription running" }
    }
  }

  # ---------------------------------------------------------------------------
  # Sizes: slow on big servers, so they ship turned off. Turn them on from the
  # template's page.

  query "sizes" {
    enabled  = false
    interval = "5m"
    sql      = <<-SQL
      SELECT datname::text AS database, pg_database_size(oid) AS size
      FROM pg_database WHERE datallowconn AND has_database_privilege(oid, 'CONNECT')
    SQL
    labels  = ["database"]
    metrics = {
      size = { title = "PostgreSQL database size", unit = "bytes", description = "Each database's size on disk" }
    }
  }

  query "wal_size" {
    enabled  = false
    interval = "5m"
    sql      = "SELECT coalesce(sum(size), 0) AS wal_size FROM pg_ls_waldir()"
    metrics = {
      wal_size = { title = "PostgreSQL WAL on disk", unit = "bytes", description = "WAL kept on disk" }
    }
  }

  # ---------------------------------------------------------------------------
  # Alerts

  # `up` is every database template's: false when it can't be signed in to.
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
    name    = "PostgreSQL long-running transaction"
    warning = "oldest_transaction > duration('1h')"
    for     = "1m"
    summary = "{{ hostname }}: a transaction on {{ instance }} has been open for {{ oldest_transaction }}, holding back vacuum"
  }

  alert "wraparound" {
    name     = "PostgreSQL transaction IDs running out"
    warning  = "xid_age > 1000000000"
    critical = "xid_age > 1500000000"
    for      = "10m"
    summary  = "{{ hostname }}: {{ instance }} is {{ xid_age }} transactions from its last freeze; it stops near 2.1 billion"
  }

  alert "checksum_failures" {
    name     = "PostgreSQL data checksum failures"
    since    = "12"
    critical = "checksum_failures > 0"
    summary  = "{{ hostname }}: {{ instance }} found pages that fail their checksums, which usually means a bad disk"
  }

  alert "replica_lagging" {
    name     = "PostgreSQL replica lagging"
    when     = "role == 'replica'"
    warning  = "lag > duration('30s')"
    critical = "lag > duration('5m')"
    for      = "2m"
    summary  = "{{ hostname }}: replica {{ instance }} is {{ lag }} behind its primary"
  }

  # Lagging but still receiving is a slow replica; not receiving is a broken one.
  alert "replica_not_receiving" {
    name     = "PostgreSQL replica not receiving"
    when     = "role == 'replica'"
    critical = "!receiving"
    for      = "2m"
    summary  = "{{ hostname }}: replica {{ instance }} hasn't received anything from its primary for {{ last_received }}"
  }

  alert "standby_lagging" {
    name     = "PostgreSQL standby falling behind"
    when     = "role == 'primary'"
    warning  = "lag > duration('30s')"
    critical = "lag > duration('5m')"
    for      = "2m"
    summary  = "{{ hostname }}: standby {{ labels.application }} ({{ labels.address }}) is {{ lag }} behind {{ instance }}"
  }

  # Off until someone says how many standbys a primary should have.
  alert "too_few_standbys" {
    enabled  = false
    name     = "PostgreSQL too few standbys"
    when     = "role == 'primary'"
    critical = "standbys < 1"
    for      = "2m"
    summary  = "{{ hostname }}: only {{ standbys }} standbys are streaming from {{ instance }}"
  }

  alert "slot_unused" {
    name    = "PostgreSQL replication slot unused"
    warning = "!slot_in_use"
    for     = "30m"
    summary = "{{ hostname }}: nothing has used slot {{ labels.slot }} on {{ instance }} for 30 minutes; it keeps WAL until something does"
  }

  # Unused and holding a lot is what fills disks; either alone is often fine.
  alert "slot_retaining_wal" {
    name     = "PostgreSQL replication slot holding WAL"
    warning  = "slot_retained > gib(10)"
    critical = "slot_retained > gib(50) || (!slot_in_use && slot_retained > gib(10))"
    for      = "5m"
    summary  = "{{ hostname }}: slot {{ labels.slot }} on {{ instance }} is holding {{ slot_retained }} of WAL"
  }

  alert "slot_lost" {
    name     = "PostgreSQL replication slot lost"
    since    = "13"
    critical = "slot_lost"
    summary  = "{{ hostname }}: slot {{ labels.slot }} on {{ instance }} was lost; whatever used it has to be rebuilt"
  }

  alert "archiving_failing" {
    name     = "PostgreSQL WAL archiving failing"
    when     = "archiving"
    critical = "archive_failing"
    for      = "5m"
    summary  = "{{ hostname }}: {{ instance }} can't archive WAL, so it piles up on disk"
  }

  alert "subscription_stopped" {
    name     = "PostgreSQL subscription stopped"
    critical = "!subscription_running"
    for      = "5m"
    summary  = "{{ hostname }}: subscription {{ labels.subscription }} on {{ instance }} isn't running"
  }
}
