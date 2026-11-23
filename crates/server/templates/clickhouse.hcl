# ClickHouse's health, load and replication, from its system tables, which an
# account with SELECT ON system.* can read. It runs once for each ClickHouse
# database: each `database` block of that kind in an agent's config, and each
# ClickHouse check that reads stats on a host without an agent. ClickHouse is read
# over its HTTP interface, where every statement is a GET, which it only lets read.

template "clickhouse" {
  name        = "ClickHouse"
  description = "Health, load, merges, replication, Keeper and Distributed tables, for an account with SELECT ON system.*."
  database    = "clickhouse"

  # Whether it has a Keeper or ZooKeeper to read the session with, as the table
  # is only there when it has.
  discover "server" {
    interval = "1h"
    sql      = <<-SQL
      SELECT version() AS version,
             (SELECT toBool(count() > 0) FROM system.tables
              WHERE database = 'system' AND name = 'zookeeper_connection') AS has_keeper
    SQL
  }

  # ---------------------------------------------------------------------------
  # What's going on now, against the server's limits

  query "current" {
    sql = <<-SQL
      SELECT uptime,
             connections,
             connections * 100 / nullIf(max_connections, 0)       AS connections_used,
             interserver_connections,
             running_queries,
             running_queries * 100 / nullIf(max_queries, 0)       AS queries_used,
             pending_async_inserts,
             preempted_queries,
             merges_running,
             delayed_inserts,
             readonly_replicas,
             merge_memory,
             memory_tracked * 100 / nullIf(memory_limit, 0)       AS memory_used,
             distributed_files,
             distributed_broken_files,
             distributed_bytes,
             fetches_running,
             keeper_sessions,
             keeper_sessions_expired,
             keeper_requests,
             keeper_clients,
             keeper_outstanding
      FROM (
        SELECT uptime() AS uptime,
               sumIf(value, metric IN ('TCPConnection', 'HTTPConnection', 'MySQLConnection',
                                       'PostgreSQLConnection'))           AS connections,
               sumIf(value, metric = 'InterserverConnection')            AS interserver_connections,
               greatest(sumIf(value, metric = 'Query')
                        - sumIf(value, metric = 'PendingAsyncInsert'), 0) AS running_queries,
               sumIf(value, metric = 'PendingAsyncInsert')               AS pending_async_inserts,
               sumIf(value, metric = 'QueryPreempted')                   AS preempted_queries,
               sumIf(value, metric = 'Merge')                            AS merges_running,
               sumIf(value, metric = 'DelayedInserts')                   AS delayed_inserts,
               sumIf(value, metric = 'ReadonlyReplica')                  AS readonly_replicas,
               sumIf(value, metric = 'MemoryTracking')                   AS memory_tracked,
               sumIf(value, metric = 'MergesMutationsMemoryTracking')    AS merge_memory,
               sumIf(value, metric = 'DistributedFilesToInsert')         AS distributed_files,
               sumIf(value, metric = 'BrokenDistributedFilesToInsert')   AS distributed_broken_files,
               sumIf(value, metric = 'DistributedBytesToInsert')         AS distributed_bytes,
               sumIf(value, metric = 'ReplicatedFetch')                  AS fetches_running,
               sumIf(value, metric = 'ZooKeeperSession')                 AS keeper_sessions,
               sumIf(value, metric = 'ZooKeeperSessionExpired')          AS keeper_sessions_expired,
               sumIf(value, metric = 'ZooKeeperRequest')                 AS keeper_requests,
               sumIf(value, metric = 'KeeperAliveConnections')           AS keeper_clients,
               sumIf(value, metric = 'KeeperOutstandingRequests')        AS keeper_outstanding,
               (SELECT toFloat64OrZero(any(value)) FROM system.server_settings
                WHERE name = 'max_concurrent_queries')                   AS max_queries,
               (SELECT toFloat64OrZero(any(value)) FROM system.server_settings
                WHERE name = 'max_connections')                          AS max_connections,
               (SELECT if(estimate > 0 AND set > 0, least(estimate, set), greatest(estimate, set))
                FROM (SELECT if(available > 0, if(ratio > 0, available * ratio, available), 0) AS estimate,
                             set
                      FROM (SELECT (SELECT if(anyIf(value, metric = 'CGroupMemoryTotal') > 0,
                                              anyIf(value, metric = 'CGroupMemoryTotal'),
                                              anyIf(value, metric = 'OSMemoryTotal'))
                                    FROM system.asynchronous_metrics)          AS available,
                                   toFloat64OrZero(anyIf(value, name = 'max_server_memory_usage_to_ram_ratio')) AS ratio,
                                   toFloat64OrZero(anyIf(value, name = 'max_server_memory_usage')) AS set
                            FROM system.server_settings)))               AS memory_limit
        FROM system.metrics
      )
    SQL
    metrics = {
      uptime                   = { title = "ClickHouse uptime", unit = "s" }
      connections_used         = { title = "ClickHouse connections used", unit = "%", description = "Connections against max_connections" }
      running_queries          = { title = "ClickHouse queries running", description = "Queries running, leaving out inserts waiting to be batched, which count as queries from 26.3" }
      queries_used             = { title = "ClickHouse queries running of the most allowed", unit = "%", description = "Queries running against max_concurrent_queries" }
      merge_memory             = { title = "ClickHouse memory used by merges and mutations", unit = "bytes", description = "Memory used by merges and mutations" }
      memory_used              = { title = "ClickHouse memory used of its limit", unit = "%", description = "Memory in use against its limit, worked out from max_server_memory_usage, its share of memory and the memory it can have" }
      distributed_bytes        = { title = "ClickHouse Distributed bytes waiting", unit = "bytes" }
      connections              = { title = "ClickHouse connections" }
      preempted_queries        = { title = "ClickHouse queries held back by priority" }
      interserver_connections  = { title = "ClickHouse connections between servers" }
      delayed_inserts          = { title = "ClickHouse inserts being slowed" }
      pending_async_inserts    = { title = "ClickHouse inserts waiting to be batched" }
      merges_running           = { title = "ClickHouse merges running" }
      readonly_replicas        = { title = "ClickHouse read-only replicas" }
      fetches_running          = { title = "ClickHouse parts being fetched" }
      distributed_files        = { title = "ClickHouse Distributed files waiting" }
      distributed_broken_files = { title = "ClickHouse Distributed files broken" }
      keeper_sessions          = { title = "ClickHouse Keeper sessions" }
      keeper_sessions_expired  = { title = "ClickHouse Keeper sessions expired" }
      keeper_requests          = { title = "ClickHouse Keeper requests in flight" }
      keeper_clients           = { title = "ClickHouse embedded Keeper clients" }
      keeper_outstanding       = { title = "ClickHouse embedded Keeper requests waiting" }
    }
  }

  # Each background pool's tasks against its size, such as merges and mutations.
  query "pools" {
    sql = <<-SQL
      SELECT lower(trim(replaceRegexpAll(t.name, '([A-Z])', ' \\1'))) AS pool,
             t.value                                                    AS pool_tasks,
             t.value * 100 / nullIf(s.value, 0)                        AS pool_used
      FROM (SELECT extract(metric, '^Background(.+)PoolTask$') AS name, value
            FROM system.metrics WHERE metric LIKE 'Background%PoolTask') AS t
      JOIN (SELECT extract(metric, '^Background(.+)PoolSize$') AS name, value
            FROM system.metrics WHERE metric LIKE 'Background%PoolSize') AS s ON t.name = s.name
    SQL
    labels  = ["pool"]
    metrics = {
      pool_used  = { title = "ClickHouse background pool used", unit = "%", description = "A full merge pool means merges fall behind and parts pile up" }
      pool_tasks = { title = "ClickHouse background pool tasks" }
    }
  }

  # Running totals since it started, and averages over each sample worked out from
  # them. An event that's never happened counts as none.
  query "events" {
    sql = <<-SQL
      SELECT sumIf(value, event = 'Query')                                  AS queries,
             sumIf(value, event = 'SelectQuery')                            AS selects,
             sumIf(value, event = 'InsertQuery')                            AS inserts,
             sumIf(value, event = 'FailedQuery')                            AS failed_queries,
             sumIf(value, event = 'FailedSelectQuery')                      AS failed_selects,
             sumIf(value, event = 'FailedInsertQuery')                      AS failed_inserts,
             sumIf(value, event = 'QueryTimeMicroseconds')                  AS query_time,
             sumIf(value, event = 'SelectQueryTimeMicroseconds')            AS select_time,
             sumIf(value, event = 'InsertQueryTimeMicroseconds')            AS insert_time,
             sumIf(value, event = 'InsertedRows')                           AS inserted_rows,
             sumIf(value, event = 'InsertedBytes')                          AS inserted_bytes,
             sumIf(value, event = 'RejectedInserts')                        AS rejected_inserts,
             sumIf(value, event = 'DelayedInserts')                         AS inserts_delayed,
             sumIf(value, event = 'DelayedInsertsMilliseconds') / 1000      AS insert_delay,
             sumIf(value, event = 'QueryMemoryLimitExceeded')               AS memory_limit_exceeded,
             sumIf(value, event = 'MemoryOvercommitWaitTimeMicroseconds') / 1000000 AS overcommit_wait,
             sumIf(value, event = 'DelayedMutations')                       AS mutations_delayed,
             sumIf(value, event = 'RejectedMutations')                      AS mutations_rejected,
             sumIf(value, event = 'ReplicatedPartFailedFetches')            AS failed_fetches,
             sumIf(value, event = 'ReplicatedPartChecksFailed')             AS failed_part_checks,
             sumIf(value, event = 'ReplicatedDataLoss')                     AS data_loss,
             sumIf(value, event = 'DataAfterMergeDiffersFromReplica')       AS merge_differs,
             sumIf(value, event = 'DataAfterMutationDiffersFromReplica')    AS mutation_differs,
             sumIf(value, event = 'ReplicaPartialShutdown')                 AS partial_shutdowns,
             sumIf(value, event = 'DistributedConnectionFailTry')           AS distributed_retries,
             sumIf(value, event = 'DistributedConnectionFailAtAll')         AS distributed_failures,
             sumIf(value, event = 'DistributedRejectedInserts')             AS distributed_rejected,
             sumIf(value, event = 'DistributedAsyncInsertionFailures')      AS distributed_insert_failures,
             sumIf(value, event = 'ZooKeeperHardwareExceptions')            AS keeper_hardware_errors,
             sumIf(value, event = 'ZooKeeperUserExceptions')                AS keeper_user_errors,
             sumIf(value, event = 'ZooKeeperWaitMicroseconds')              AS keeper_wait,
             sumIf(value, event = 'ZooKeeperTransactions')                  AS keeper_transactions,
             sumIf(value, event = 'FailedAsyncInsertQuery')                 AS failed_async_inserts,
             sumIf(value, event = 'StorageBufferErrorOnFlush')              AS buffer_flush_errors,
             sumIf(value, event = 'SlowRead')                               AS slow_reads,
             sumIf(value, event = 'ReadBufferFromFileDescriptorReadFailed') AS read_failures,
             sumIf(value, event = 'WriteBufferFromFileDescriptorWriteFailed') AS write_failures
      FROM system.events
    SQL
    metrics = {
      queries                     = { title = "ClickHouse queries", total = true }
      selects                     = { title = "ClickHouse selects", total = true }
      inserts                     = { title = "ClickHouse inserts", total = true }
      failed_queries              = { title = "ClickHouse failed queries", total = true }
      failed_selects              = { title = "ClickHouse failed selects", total = true }
      failed_inserts              = { title = "ClickHouse failed inserts", total = true }
      query_time                  = { title = "ClickHouse time spent on queries", total = true, description = "Microseconds queries took" }
      select_time                 = { title = "ClickHouse time spent on selects", total = true, description = "Microseconds selects took" }
      insert_time                 = { title = "ClickHouse time spent on inserts", total = true, description = "Microseconds inserts took" }
      inserted_rows               = { title = "ClickHouse rows inserted", total = true }
      inserted_bytes              = { title = "ClickHouse bytes inserted", total = true, unit = "bytes" }
      rejected_inserts            = { title = "ClickHouse inserts refused for too many parts", total = true, description = "Inserts refused for too many parts" }
      inserts_delayed             = { title = "ClickHouse inserts slowed for too many parts", total = true, description = "Inserts slowed for too many parts" }
      insert_delay                = { title = "ClickHouse time inserts were slowed each second", total = true, unit = "s", description = "Time inserts were slowed each second" }
      memory_limit_exceeded       = { title = "ClickHouse queries over their memory limit", total = true }
      overcommit_wait             = { title = "ClickHouse time waiting for memory each second", total = true, unit = "s", description = "Time waiting for memory each second" }
      mutations_delayed           = { title = "ClickHouse mutations slowed", total = true }
      mutations_rejected          = { title = "ClickHouse mutations refused", total = true }
      failed_fetches              = { title = "ClickHouse failed fetches", total = true }
      failed_part_checks          = { title = "ClickHouse failed part checks", total = true }
      data_loss                   = { title = "ClickHouse data lost on a replica", total = true }
      merge_differs               = { title = "ClickHouse merges that differ from a replica", total = true }
      mutation_differs            = { title = "ClickHouse mutations that differ from a replica", total = true }
      partial_shutdowns           = { title = "ClickHouse replicated tables shut down", total = true }
      distributed_retries         = { title = "ClickHouse connections to shards retried", total = true }
      distributed_failures        = { title = "ClickHouse connections to shards failed", total = true }
      distributed_rejected        = { title = "ClickHouse Distributed inserts refused", total = true }
      distributed_insert_failures = { title = "ClickHouse Distributed inserts failed", total = true }
      keeper_hardware_errors      = { title = "ClickHouse Keeper connection errors", total = true }
      keeper_user_errors          = { title = "ClickHouse Keeper request errors", total = true }
      keeper_wait                 = { title = "ClickHouse time spent waiting for Keeper", total = true, description = "Microseconds spent waiting for Keeper" }
      keeper_transactions         = { title = "ClickHouse Keeper transactions", total = true }
      failed_async_inserts        = { title = "ClickHouse batched inserts failed", total = true }
      buffer_flush_errors         = { title = "ClickHouse buffer table flush failures", total = true }
      slow_reads                  = { title = "ClickHouse slow disk reads", total = true }
      read_failures               = { title = "ClickHouse failed disk reads", total = true }
      write_failures              = { title = "ClickHouse failed disk writes", total = true }
      latency = {
        title       = "ClickHouse average query time"
        value       = "rate(query_time) / rate(queries) / 1000000"
        unit        = "s"
        description = "The average query time over each sample"
      }
      select_latency              = { title = "ClickHouse average select time", value = "rate(select_time) / rate(selects) / 1000000", unit = "s" }
      insert_latency              = { title = "ClickHouse average insert time", value = "rate(insert_time) / rate(inserts) / 1000000", unit = "s" }
      rows_per_insert             = { title = "ClickHouse rows per insert", value = "rate(inserted_rows) / rate(inserts)", description = "Many inserts of few rows each make too many parts" }
      keeper_latency              = { title = "ClickHouse Keeper average wait", value = "rate(keeper_wait) / rate(keeper_transactions) / 1000000", unit = "s" }
    }
  }

  # What ClickHouse works out in the background, such as the most parts in one
  # partition, which slows inserts at parts_to_delay_insert. Embedded Keeper's
  # are only there when Keeper runs inside this server.
  query "background" {
    sql = <<-SQL
      SELECT max_parts,
             max_parts * 100 / nullIf(parts_to_delay_insert, 0) AS parts_used,
             parts_total,
             memory,
             lag,
             relative_lag,
             max_replication_queue,
             if(keeper_role, keeper_leader, NULL)                AS keeper_leader,
             if(keeper_role, keeper_synced_followers, NULL)      AS keeper_synced_followers,
             if(keeper_role, keeper_memory_limit_hit, NULL)      AS keeper_memory_limit_hit
      FROM (
        SELECT anyIf(value, metric = 'MaxPartCountForPartition')    AS max_parts,
               anyIf(value, metric = 'TotalPartsOfMergeTreeTables') AS parts_total,
               anyIf(value, metric = 'MemoryResident')              AS memory,
               anyIf(value, metric = 'ReplicasMaxAbsoluteDelay')    AS lag,
               anyIf(value, metric = 'ReplicasMaxRelativeDelay')    AS relative_lag,
               anyIf(value, metric = 'ReplicasMaxQueueSize')        AS max_replication_queue,
               sumIf(value, metric IN ('KeeperIsLeader', 'KeeperIsFollower',
                                       'KeeperIsStandalone')) > 0   AS keeper_role,
               anyIf(value, metric = 'KeeperIsLeader')              AS keeper_leader,
               anyIf(value, metric = 'KeeperSyncedFollowers')       AS keeper_synced_followers,
               anyIf(value, metric = 'KeeperIsExceedingMemorySoftLimitHit') AS keeper_memory_limit_hit,
               (SELECT toFloat64OrZero(any(value)) FROM system.merge_tree_settings
                WHERE name = 'parts_to_delay_insert')               AS parts_to_delay_insert
        FROM system.asynchronous_metrics
      )
    SQL
    metrics = {
      max_parts               = { title = "ClickHouse most parts in a partition", description = "The most parts in any one partition. Inserts are slowed at parts_to_delay_insert and refused at parts_to_throw_insert" }
      parts_used              = { title = "ClickHouse most parts in a partition, of where inserts slow", unit = "%", description = "The most parts in a partition against parts_to_delay_insert, where inserts slow" }
      memory                  = { title = "ClickHouse memory in use", unit = "bytes", description = "Memory in use" }
      lag                     = { title = "ClickHouse replication lag", unit = "s", description = "The furthest behind of its replicated tables that can take writes" }
      relative_lag            = { title = "ClickHouse replica lag behind the freshest", unit = "s", description = "How far behind the freshest replica it is" }
      parts_total             = { title = "ClickHouse parts in total" }
      max_replication_queue   = { title = "ClickHouse longest replication queue" }
      keeper_leader           = { title = "ClickHouse embedded Keeper is leader" }
      keeper_synced_followers = { title = "ClickHouse embedded Keeper synced followers" }
      keeper_memory_limit_hit = { title = "ClickHouse embedded Keeper over its memory limit" }
    }
  }

  # Replicated tables, without the columns that ask Keeper for every table, and
  # only when there are any.
  query "replicas" {
    sql = <<-SQL
      SELECT count()                                                AS replicated_tables,
             countIf(is_readonly)                                   AS readonly_tables,
             countIf(is_session_expired)                            AS expired_sessions,
             sum(queue_size)                                        AS replication_queue,
             sum(inserts_in_queue)                                  AS inserts_in_queue,
             max(merges_in_queue)                                   AS merges_in_queue,
             max(future_parts)                                      AS future_parts,
             max(parts_to_check)                                    AS parts_to_check,
             sum(lost_part_count)                                   AS lost_parts,
             countIf(last_queue_update_exception != '')             AS queue_update_errors,
             max(if(queue_size > 0, now() - queue_oldest_time, 0))  AS oldest_queue_entry,
             (SELECT countIf(num_tries > 100 OR num_postponed > 1000)
              FROM system.replication_queue)                        AS queue_stuck,
             (SELECT countIf(last_exception != '')
              FROM system.replication_queue)                        AS queue_failing,
             (SELECT max(elapsed) FROM system.replicated_fetches)   AS longest_fetch
      FROM system.replicas
      HAVING count() > 0
    SQL
    metrics = {
      readonly_tables     = { title = "ClickHouse replicated tables read only", description = "A table goes read only when it loses ClickHouse Keeper or ZooKeeper" }
      expired_sessions    = { title = "ClickHouse tables that lost Keeper", description = "Tables that lost Keeper" }
      lost_parts          = { title = "ClickHouse parts lost", total = true }
      oldest_queue_entry  = { title = "ClickHouse oldest replication queue entry", unit = "s" }
      queue_stuck         = { title = "ClickHouse replication queue entries stuck", description = "Replication queue entries tried over 100 times, or put off over 1000" }
      longest_fetch       = { title = "ClickHouse longest fetch", unit = "s" }
      replicated_tables   = { title = "ClickHouse replicated tables" }
      replication_queue   = { title = "ClickHouse replication queue" }
      inserts_in_queue    = { title = "ClickHouse inserts waiting to replicate" }
      merges_in_queue     = { title = "ClickHouse merges waiting to replicate" }
      future_parts        = { title = "ClickHouse parts still to appear" }
      parts_to_check      = { title = "ClickHouse parts waiting to be checked" }
      queue_failing       = { title = "ClickHouse replication queue entries failing" }
      queue_update_errors = { title = "ClickHouse replicas failing to update their queue" }
    }
  }

  # Its session with Keeper or ZooKeeper, when it has one.
  query "keeper" {
    since = "23.5"
    when  = "has_keeper"
    sql   = <<-SQL
      SELECT countIf(is_expired) = 0           AS keeper_connected,
             min(session_uptime_elapsed_seconds) AS keeper_session
      FROM system.zookeeper_connection
      HAVING count() > 0
    SQL
    metrics = {
      keeper_session   = { title = "ClickHouse Keeper session age", unit = "s", description = "How long its Keeper session has lasted" }
      keeper_connected = { title = "ClickHouse connected to Keeper" }
    }
  }

  # Mutations still to finish and failing, the longest query, dictionaries that
  # won't load, and how many replicas of other shards it recently failed to reach.
  query "work" {
    sql = <<-SQL
      SELECT (SELECT count() FROM system.mutations WHERE NOT is_done) AS mutations_pending,
             (SELECT countIf(latest_fail_reason != '') FROM system.mutations
              WHERE NOT is_done)                                     AS mutations_failing,
             (SELECT max(elapsed) FROM system.processes
              WHERE is_initial_query)                                AS oldest_query,
             (SELECT countIf(status IN ('FAILED', 'FAILED_AND_RELOADING')
                             OR last_exception != '')
              FROM system.dictionaries)                              AS dictionaries_failing,
             (SELECT sum(errors_count) FROM system.clusters)         AS cluster_errors
    SQL
    metrics = {
      mutations_pending    = { title = "ClickHouse mutations pending", description = "ALTER … UPDATE and DELETE still to finish" }
      oldest_query         = { title = "ClickHouse oldest query", unit = "s" }
      cluster_errors       = { title = "ClickHouse recent errors reaching other replicas", description = "Recent errors reaching replicas of other shards" }
      mutations_failing    = { title = "ClickHouse mutations failing" }
      dictionaries_failing = { title = "ClickHouse dictionaries failing" }
    }
  }

  # The error codes worth knowing about, each with what sort of trouble it is,
  # listed whether or not they've happened, so the first time one does counts.
  # ClickHouse's own docs warn that other codes rise while queries succeed.
  query "errors" {
    sql = <<-SQL
      SELECT tupleElement(code, 1) AS error,
             tupleElement(code, 2) AS kind,
             ifNull(found.count, 0) AS errors
      FROM (SELECT arrayJoin([
              ('MEMORY_LIMIT_EXCEEDED', 'capacity'), ('CANNOT_ALLOCATE_MEMORY', 'capacity'),
              ('TOO_MANY_SIMULTANEOUS_QUERIES', 'capacity'), ('SERVER_OVERLOADED', 'capacity'),
              ('NOT_ENOUGH_SPACE', 'capacity'), ('TOO_MANY_PARTS', 'capacity'),
              ('TOO_MANY_PARTITIONS', 'capacity'), ('TOO_MANY_MUTATIONS', 'capacity'),
              ('CHECKSUM_DOESNT_MATCH', 'integrity'), ('CORRUPTED_DATA', 'integrity'),
              ('POTENTIALLY_BROKEN_DATA_PART', 'integrity'), ('CANNOT_FSYNC', 'integrity'),
              ('KEEPER_EXCEPTION', 'replication'), ('NO_ZOOKEEPER', 'replication'),
              ('TABLE_IS_READ_ONLY', 'replication'), ('NO_REPLICA_HAS_PART', 'replication'),
              ('REPLICA_IS_NOT_IN_QUORUM', 'replication'), ('ALL_REPLICAS_ARE_STALE', 'replication'),
              ('ALL_CONNECTION_TRIES_FAILED', 'distributed'),
              ('DISTRIBUTED_TOO_MANY_PENDING_BYTES', 'distributed'),
              ('DISTRIBUTED_BROKEN_BATCH_INFO', 'distributed'),
              ('DISTRIBUTED_BROKEN_BATCH_FILES', 'distributed'),
              ('LOGICAL_ERROR', 'bug'), ('CANNOT_LOAD_CONFIG', 'bug'),
              ('DICTIONARIES_WAS_NOT_LOADED', 'bug'), ('S3_ERROR', 'bug'),
              ('AUTHENTICATION_FAILED', 'security')]) AS code) AS codes
      LEFT JOIN (SELECT name, sum(value) AS count FROM system.errors GROUP BY name) AS found
        ON tupleElement(codes.code, 1) = found.name
    SQL
    labels  = ["error", "kind"]
    metrics = {
      errors = { title = "ClickHouse errors by code", total = true, description = "Each error code worth knowing about, by what sort of trouble it is" }
    }
  }

  query "disks" {
    sql = <<-SQL
      SELECT name                                                   AS disk,
             free_space                                             AS disk_free,
             (total_space - free_space) * 100 / nullIf(total_space, 0) AS disk_used,
             {{ broken }}                                           AS disk_broken,
             {{ read_only }}                                        AS disk_read_only
      FROM system.disks
    SQL
    fill "broken" {
      versions = { "23.8" = "is_broken" }
      older    = "NULL"
    }
    fill "read_only" {
      versions = { "23.8" = "is_read_only" }
      older    = "NULL"
    }
    labels = ["disk"]
    metrics = {
      disk_free      = { title = "ClickHouse disk free", unit = "bytes" }
      disk_used      = { title = "ClickHouse disk used", unit = "%" }
      disk_broken    = { title = "ClickHouse disk broken" }
      disk_read_only = { title = "ClickHouse disk read only" }
    }
  }

  # ---------------------------------------------------------------------------
  # Every few minutes: what asks Keeper about every replicated table, and what
  # lists files on disk.

  query "replication_log" {
    interval = "5m"
    sql      = <<-SQL
      SELECT countIf(active_replicas < total_replicas) AS tables_missing_replicas,
             max(log_max_index - log_pointer)          AS log_lag
      FROM system.replicas
      HAVING count() > 0
    SQL
    metrics = {
      log_lag                 = { title = "ClickHouse replication log entries behind", description = "Replication log entries behind" }
      tables_missing_replicas = { title = "ClickHouse tables missing a replica" }
    }
  }

  # Parts on their way somewhere aren't counted.
  query "detached" {
    interval = "5m"
    sql      = <<-SQL
      SELECT countIf(reason NOT IN ('attaching', 'deleting', 'tmp-fetch')) AS detached_parts,
             countIf(startsWith(reason, 'broken')
                     OR endsWith(reason, '-not-byte-identical')
                     OR reason IN ('covered-by-broken', 'noquorum', 'unexpected')) AS detached_broken
      FROM system.detached_parts
    SQL
    metrics = {
      detached_broken = { title = "ClickHouse parts detached as broken", description = "Parts set aside because something was wrong with them" }
      detached_parts  = { title = "ClickHouse detached parts" }
    }
  }

  query "distribution" {
    interval = "5m"
    sql      = <<-SQL
      SELECT countIf(is_blocked) AS distribution_blocked, sum(error_count) AS distribution_errors
      FROM system.distribution_queue
    SQL
    metrics = {
      distribution_blocked = { title = "ClickHouse Distributed queues blocked" }
      distribution_errors  = { title = "ClickHouse Distributed queue errors" }
    }
  }

  query "async_inserts" {
    interval = "5m"
    sql      = "SELECT max(dateDiff('second', first_update, now())) AS async_queue_age FROM system.asynchronous_inserts"
    metrics = {
      async_queue_age = { title = "ClickHouse oldest insert waiting to be batched", unit = "s", description = "The oldest insert waiting to be batched" }
    }
  }

  query "backups" {
    interval = "5m"
    sql      = "SELECT countIf(status IN ('BACKUP_FAILED', 'RESTORE_FAILED')) AS backups_failed FROM system.backups"
    metrics = {
      backups_failed = { title = "ClickHouse backups and restores failed" }
    }
  }

  # ---------------------------------------------------------------------------
  # Turned off as they ship, as they cost more. Turn them on from the template's
  # page.

  query "sizes" {
    enabled = false
    sql     = <<-SQL
      SELECT database, sum(bytes_on_disk) AS size FROM system.parts
      WHERE active GROUP BY database
    SQL
    labels  = ["database"]
    metrics = {
      size = { title = "ClickHouse database size", unit = "bytes", description = "Each database's size on disk" }
    }
  }

  # How long queries took over the last five minutes, by kind, and how many
  # failed, from system.query_log, which keeps everything unless it's given a time
  # to live, so it can be slow on a busy server. Its newest rows can be 7.5
  # seconds from being written, so those are left for later, and this account's
  # own queries are left out.
  query "queries" {
    enabled = false
    sql     = <<-SQL
      SELECT if(query_kind = '', 'other', lower(query_kind)) AS kind,
             countIf(type IN ('ExceptionBeforeStart', 'ExceptionWhileProcessing')) AS queries_failed_5m,
             quantileIf(0.5)(query_duration_ms, type = 'QueryFinish') / 1000  AS query_p50,
             quantileIf(0.95)(query_duration_ms, type = 'QueryFinish') / 1000 AS query_p95,
             quantileIf(0.99)(query_duration_ms, type = 'QueryFinish') / 1000 AS query_p99
      FROM system.query_log
      WHERE event_date >= toDate(now() - INTERVAL 6 MINUTE)
        AND event_time > now() - INTERVAL 315 SECOND
        AND event_time <= now() - INTERVAL 15 SECOND
        AND type != 'QueryStart' AND is_initial_query AND user != currentUser()
      GROUP BY query_kind
    SQL
    labels = ["kind"]
    metrics = {
      query_p50         = { title = "ClickHouse median query time", unit = "s", description = "The median query time over the last five minutes" }
      query_p95         = { title = "ClickHouse 95th percentile query time", unit = "s" }
      query_p99         = { title = "ClickHouse 99th percentile query time", unit = "s" }
      queries_failed_5m = { title = "ClickHouse queries failed in five minutes" }
    }
  }

  # ---------------------------------------------------------------------------
  # Alerts

  # `up` is every database template's: false when it can't be signed in to.
  alert "down" {
    name             = "ClickHouse down"
    critical         = "!up"
    for              = "1m"
    summary          = "{{ hostname }}: ClickHouse {{ instance }} isn't answering"
    resolved_summary = "{{ hostname }}: ClickHouse {{ instance }} is answering again"
  }

  alert "too_many_parts" {
    name     = "ClickHouse parts piling up"
    warning  = "parts_used > 80"
    critical = "parts_used > 95"
    for      = "5m"
    summary  = "{{ hostname }}: {{ instance }} has a partition at {{ parts_used }} of where inserts slow"
  }

  alert "inserts_refused" {
    name     = "ClickHouse refusing inserts"
    critical = "rejected_inserts > 0"
    summary  = "{{ hostname }}: {{ instance }} is refusing inserts for too many parts"
  }

  alert "memory_running_out" {
    name    = "ClickHouse memory running out"
    warning = "memory_used > 90"
    for     = "5m"
    summary = "{{ hostname }}: {{ instance }} is using {{ memory_used }} of its memory limit"
  }

  alert "tables_read_only" {
    name     = "ClickHouse replicated tables read only"
    critical = "readonly_tables > 0 || expired_sessions > 0"
    for      = "1m"
    summary  = "{{ hostname }}: {{ instance }} has replicated tables that went read only, usually from losing Keeper"
  }

  alert "data_lost" {
    name     = "ClickHouse data lost on a replica"
    critical = "data_loss > 0"
    summary  = "{{ hostname }}: {{ instance }} lost data that no other replica had"
  }

  # Apart, as each is read by a query of its own, and a server with no replicated
  # tables has no replication queue to read.
  alert "replication_stuck" {
    name    = "ClickHouse replication stuck"
    warning = "queue_stuck > 0"
    for     = "15m"
    summary = "{{ hostname }}: {{ instance }} has replication queue entries that keep failing"
  }

  alert "mutations_failing" {
    name    = "ClickHouse mutations failing"
    warning = "mutations_failing > 0"
    for     = "15m"
    summary = "{{ hostname }}: {{ instance }} has mutations that keep failing"
  }
}
