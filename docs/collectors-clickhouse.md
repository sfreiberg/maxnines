# ClickHouse

MaxNines reads a ClickHouse server's health, load and replication: queries and inserts
against its limits, parts piling up, memory, merges and background pools, mutations,
error codes worth knowing about, its disks, replication, ClickHouse Keeper or
ZooKeeper, and Distributed tables. It's read by the built-in **ClickHouse**
[template](templates.md), over ClickHouse's HTTP interface, so it needs no driver, the
same way on an agent and on the server.

What only newer versions have is left out on older ones: Keeper's connection from 23.5,
and whether a disk is broken or read only from 23.8.

## Turning it on

**On a host with an agent**, add a `database` block to the agent's own `agent.hcl`,
with where the server is and how to sign in, so the password never leaves the host:

```hcl
database "events" {
  kind     = "clickhouse"
  target   = "127.0.0.1:8123"
  username = "maxnines"
  password = env("EVENTS_DB_PASSWORD")
}
```

`target` is the HTTP port, usually 8123, or 8443 for HTTPS with `tls = true`. Over
HTTP, a password goes with every request rather than being checked once, so the agent
only sends one over plain HTTP to ClickHouse on its own host, at `127.0.0.1` or
`localhost`, and anywhere else needs `tls = true`. The
[settings](database-stats.md#the-database-block) are the same for every kind of
database. Restart the agent after changing them.

That's all: the ClickHouse template reads every ClickHouse `database` block on every
host it's for, which as it ships is every host, with no config rule needed. Choose
which hosts on the template's page, under **Settings > Templates**, or turn it off
there.

**On a host without an agent**, such as a managed service, add a ClickHouse check about
the host on the **Checks** page, with how it signs in, and tick **Read its health and
replication**. See [hosts without an agent](database-stats.md#hosts-without-an-agent).

## The account to sign in as

Give MaxNines an account of its own, which can read the `system` tables and change
nothing:

```sql
CREATE SETTINGS PROFILE IF NOT EXISTS maxnines_monitor SETTINGS
    readonly = 1, max_execution_time = 10, timeout_overflow_mode = 'throw',
    max_memory_usage = 1000000000, max_result_rows = 100000,
    result_overflow_mode = 'throw', max_threads = 2,
    max_concurrent_queries_for_user = 4;
CREATE USER IF NOT EXISTS maxnines IDENTIFIED WITH sha256_password BY 'a long random password'
    HOST IP '192.0.2.10' SETTINGS PROFILE 'maxnines_monitor';
GRANT SELECT ON system.* TO maxnines;
```

Everything it reads is in the `system` tables, and the grant is needed even for those.
Every request is a GET, which ClickHouse only lets read, and MaxNines sends no settings
of its own, so the profile is what limits what a read can cost, its time limit
included. Users are kept on each server unless access control is replicated, so make
it on each.

## What's read, and how often

The template finds out about the server first, every hour, with **`server`**: its
version, and whether it has a Keeper connection to read. Then it reads its status,
events, background work, replication, Keeper, pools, error codes and disks every
sample. What asks Keeper about every table, or counts what's set aside, is read every 5
minutes: tables missing a replica and replication log lag, detached parts, Distributed
queues, the oldest insert waiting to be batched, and failed backups.

Two queries ship turned off, as they cost more. Turn either on with **Enable** under
**Queries** on the template's page:

- **`sizes`**: each database's size on disk.
- **`queries`**: how long queries took over the last five minutes, as the median, 95th
  and 99th percentiles for each kind of query, and how many failed, from
  `system.query_log`. That table keeps everything unless it's given a time to live, so
  this can be slow on a busy server.

What discovery found, and anything that went wrong, are on the template's page and the
host's **Templates** card.

## What's reported

Each metric has a series for each database block or check, labelled `instance`, such
as `events`, and those about several things are labelled by them too, such as the disk
`events, default` or the pool `events, merges and mutations`.

| Metric | Unit | Series | What it is |
| --- | --- | --- | --- |
| `clickhouse.up` | 1 or 0 | Each database | Whether the database answered |
| `clickhouse.uptime` | Seconds | Each database | How long the server has been running |
| `clickhouse.connections` | Number | Each database | Client connections, over every interface |
| `clickhouse.connections_used` | % | Each database | Connections as a percentage of `max_connections` |
| `clickhouse.interserver_connections` | Number | Each database | Connections from other servers, for replication |
| `clickhouse.running_queries` | Number | Each database | Queries running. Inserts waiting to be batched, which count as queries from 26.3, are left out |
| `clickhouse.queries_used` | % | Each database | Queries running as a percentage of `max_concurrent_queries` |
| `clickhouse.pending_async_inserts` | Number | Each database | Asynchronous inserts waiting to be batched |
| `clickhouse.preempted_queries` | Number | Each database | Queries held back for ones of higher priority |
| `clickhouse.merges_running` | Number | Each database | Background merges running |
| `clickhouse.delayed_inserts` | Number | Each database | Inserts being slowed for too many parts now |
| `clickhouse.readonly_replicas` | Number | Each database | Replicated tables that are read only now |
| `clickhouse.merge_memory` | Bytes | Each database | Memory used by merges and mutations |
| `clickhouse.memory_used` | % | Each database | Memory in use against its limit, worked out from `max_server_memory_usage`, its share of memory (0.9 by default) and the memory it can have |
| `clickhouse.distributed_files` | Number | Each database | Files waiting to be sent by Distributed tables |
| `clickhouse.distributed_broken_files` | Number | Each database | Files Distributed tables couldn't send and set aside |
| `clickhouse.distributed_bytes` | Bytes | Each database | Bytes waiting to be sent by Distributed tables |
| `clickhouse.fetches_running` | Number | Each database | Parts being fetched from other replicas |
| `clickhouse.keeper_sessions` | Number | Each database | Sessions with ClickHouse Keeper or ZooKeeper |
| `clickhouse.keeper_sessions_expired` | Number | Each database | Keeper sessions that expired |
| `clickhouse.keeper_requests` | Number | Each database | Requests to Keeper in flight |
| `clickhouse.keeper_clients` | Number | Each database | Clients of the Keeper running inside this server |
| `clickhouse.keeper_outstanding` | Number | Each database | Requests waiting in the Keeper running inside this server |
| `clickhouse.pool_tasks` | Number | Each database and background pool | Tasks running in each background pool, such as merges and mutations |
| `clickhouse.pool_used` | % | Each database and background pool | Each background pool's tasks against its size. A full merge pool means merges fall behind and parts pile up |
| `clickhouse.queries` | A second | Each database | Queries started |
| `clickhouse.selects` | A second | Each database | Selects started |
| `clickhouse.inserts` | A second | Each database | Inserts started |
| `clickhouse.failed_queries` | A second | Each database | Queries that failed |
| `clickhouse.failed_selects` | A second | Each database | Selects that failed |
| `clickhouse.failed_inserts` | A second | Each database | Inserts that failed |
| `clickhouse.query_time` | A second | Each database | Time queries took, in microseconds, which the average is worked out from |
| `clickhouse.select_time` | A second | Each database | Time selects took, in microseconds |
| `clickhouse.insert_time` | A second | Each database | Time inserts took, in microseconds |
| `clickhouse.inserted_rows` | A second | Each database | Rows inserted |
| `clickhouse.inserted_bytes` | Bytes a second | Each database | Bytes inserted |
| `clickhouse.rejected_inserts` | A second | Each database | Inserts refused for too many parts in a partition |
| `clickhouse.inserts_delayed` | A second | Each database | Inserts slowed for too many parts |
| `clickhouse.insert_delay` | Seconds | Each database | Time inserts were slowed each second |
| `clickhouse.memory_limit_exceeded` | A second | Each database | Queries stopped for going over their memory limit |
| `clickhouse.overcommit_wait` | Seconds | Each database | Time queries waited for memory each second |
| `clickhouse.mutations_delayed` | A second | Each database | Mutations slowed for too many waiting |
| `clickhouse.mutations_rejected` | A second | Each database | Mutations refused for too many waiting |
| `clickhouse.failed_fetches` | A second | Each database | Fetches of parts from other replicas that failed |
| `clickhouse.failed_part_checks` | A second | Each database | Checks of parts that found something wrong |
| `clickhouse.data_loss` | A second | Each database | Times a replica found data it should have that no replica has |
| `clickhouse.merge_differs` | A second | Each database | Merges whose result differed from another replica's |
| `clickhouse.mutation_differs` | A second | Each database | Mutations whose result differed from another replica's |
| `clickhouse.partial_shutdowns` | A second | Each database | Replicated tables shut down for losing Keeper |
| `clickhouse.distributed_retries` | A second | Each database | Connections to shards retried |
| `clickhouse.distributed_failures` | A second | Each database | Connections to shards that failed |
| `clickhouse.distributed_rejected` | A second | Each database | Inserts into Distributed tables refused for too many files waiting |
| `clickhouse.distributed_insert_failures` | A second | Each database | Inserts into Distributed tables that failed |
| `clickhouse.keeper_hardware_errors` | A second | Each database | Errors on the connection to Keeper |
| `clickhouse.keeper_user_errors` | A second | Each database | Requests Keeper refused |
| `clickhouse.keeper_wait` | A second | Each database | Time spent waiting for Keeper, in microseconds |
| `clickhouse.keeper_transactions` | A second | Each database | Requests to Keeper |
| `clickhouse.failed_async_inserts` | A second | Each database | Batched inserts that failed |
| `clickhouse.buffer_flush_errors` | A second | Each database | Times a Buffer table failed to write to its destination |
| `clickhouse.slow_reads` | A second | Each database | Disk reads slower than expected |
| `clickhouse.read_failures` | A second | Each database | Disk reads that failed |
| `clickhouse.write_failures` | A second | Each database | Disk writes that failed |
| `clickhouse.latency` | Seconds | Each database | The average query time over each sample |
| `clickhouse.select_latency` | Seconds | Each database | The average select time over each sample |
| `clickhouse.insert_latency` | Seconds | Each database | The average insert time over each sample |
| `clickhouse.rows_per_insert` | Number | Each database | Rows each insert brought. Many inserts of few rows each make too many parts |
| `clickhouse.keeper_latency` | Seconds | Each database | The average wait for Keeper over each sample |
| `clickhouse.max_parts` | Number | Each database | The most parts in any one partition. Inserts are slowed at `parts_to_delay_insert` and refused at `parts_to_throw_insert`, 1000 and 3000 since 23.6, 150 and 300 before |
| `clickhouse.parts_used` | % | Each database | The most parts in a partition against `parts_to_delay_insert`, where inserts slow |
| `clickhouse.parts_total` | Number | Each database | Active parts in every table |
| `clickhouse.memory` | Bytes | Each database | Memory in use |
| `clickhouse.lag` | Seconds | Each database | The furthest behind of its replicated tables that can take writes |
| `clickhouse.relative_lag` | Seconds | Each database | How far behind the freshest replica it is |
| `clickhouse.max_replication_queue` | Number | Each database | The longest replication queue of any table |
| `clickhouse.keeper_leader` | 1 or 0 | Each database | Whether the Keeper running inside this server is the leader |
| `clickhouse.keeper_synced_followers` | Number | Each database | Followers in sync with the Keeper running inside this server |
| `clickhouse.keeper_memory_limit_hit` | 1 or 0 | Each database | Whether the Keeper running inside this server is over its memory limit |
| `clickhouse.replicated_tables` | Number | Each database | Replicated tables |
| `clickhouse.readonly_tables` | Number | Each database | Replicated tables that are read only, which happens when one loses Keeper |
| `clickhouse.expired_sessions` | Number | Each database | Replicated tables whose Keeper session expired |
| `clickhouse.replication_queue` | Number | Each database | Entries in every table's replication queue |
| `clickhouse.inserts_in_queue` | Number | Each database | Inserts waiting to replicate |
| `clickhouse.merges_in_queue` | Number | Each database | Merges waiting to replicate |
| `clickhouse.future_parts` | Number | Each database | Parts still to appear from inserts and merges under way |
| `clickhouse.parts_to_check` | Number | Each database | Parts waiting to be checked |
| `clickhouse.lost_parts` | A second | Each database | Parts lost: replicas tried to fetch them and none had them |
| `clickhouse.queue_update_errors` | Number | Each database | Replicas that failed to update their queue from Keeper |
| `clickhouse.oldest_queue_entry` | Seconds | Each database | How long the oldest replication queue entry has waited |
| `clickhouse.queue_stuck` | Number | Each database | Replication queue entries tried over 100 times, or put off over 1000 |
| `clickhouse.queue_failing` | Number | Each database | Replication queue entries whose last try failed |
| `clickhouse.longest_fetch` | Seconds | Each database | How long the longest fetch under way has taken |
| `clickhouse.keeper_connected` | 1 or 0 | Each database | Whether it's connected to Keeper. Version 23.5 and later, where Keeper is set up |
| `clickhouse.keeper_session` | Seconds | Each database | How long its Keeper session has lasted |
| `clickhouse.mutations_pending` | Number | Each database | `ALTER … UPDATE` and `DELETE` still to finish |
| `clickhouse.mutations_failing` | Number | Each database | Mutations whose last try failed |
| `clickhouse.oldest_query` | Seconds | Each database | How long the longest-running query has been running |
| `clickhouse.dictionaries_failing` | Number | Each database | Dictionaries that failed to load |
| `clickhouse.cluster_errors` | Number | Each database | Recent errors reaching replicas of other shards |
| `clickhouse.errors` | A second | Each database and error code | Each error code worth knowing about, labelled by the code and the sort of trouble it is: `capacity`, `integrity`, `replication`, `distributed`, `bug` or `security`. Each is listed from the start, so the first time one happens counts |
| `clickhouse.disk_free` | Bytes | Each database and disk | Free space on each of its disks |
| `clickhouse.disk_used` | % | Each database and disk | Space used on each of its disks |
| `clickhouse.disk_broken` | 1 or 0 | Each database and disk | Whether each disk is broken. From 23.8 |
| `clickhouse.disk_read_only` | 1 or 0 | Each database and disk | Whether each disk is read only. From 23.8 |
| `clickhouse.tables_missing_replicas` | Number | Each database | Replicated tables with fewer replicas active than they have |
| `clickhouse.log_lag` | Number | Each database | Replication log entries this replica is behind, the furthest of any table |
| `clickhouse.detached_parts` | Number | Each database | Detached parts, not counting ones on their way somewhere |
| `clickhouse.detached_broken` | Number | Each database | Parts set aside because something was wrong with them |
| `clickhouse.distribution_blocked` | Number | Each database | Distributed tables' send queues that are blocked |
| `clickhouse.distribution_errors` | Number | Each database | Distributed tables' send queues with errors |
| `clickhouse.async_queue_age` | Seconds | Each database | How long the oldest insert waiting to be batched has waited |
| `clickhouse.backups_failed` | Number | Each database | Backups and restores that failed |
| `clickhouse.size` | Bytes | Each database and database in it | Each database's size on disk, with the `sizes` query turned on |
| `clickhouse.queries_failed_5m` | Number | Each database and kind of query | Queries that failed in the last five minutes, for each kind of query, with the `queries` query turned on |
| `clickhouse.query_p50` | Seconds | Each database and kind of query | The median query time over the last five minutes, for each kind of query |
| `clickhouse.query_p95` | Seconds | Each database and kind of query | The 95th percentile query time over the last five minutes |
| `clickhouse.query_p99` | Seconds | Each database and kind of query | The 99th percentile query time over the last five minutes |

ClickHouse's own docs warn that some error codes rise while queries succeed, which is
why only those worth knowing about are counted.

## Built-in alerts

The template brings these, for each ClickHouse database it reads. Change or turn off
any of them on the template's page.

| Alert | When | Level |
| --- | --- | --- |
| **ClickHouse down** | It hasn't answered for a minute | Critical |
| **ClickHouse parts piling up** | The most parts in a partition over 80% of where inserts slow for 5 minutes, or over 95% | Warning, then critical |
| **ClickHouse refusing inserts** | Any insert refused for too many parts | Critical |
| **ClickHouse memory running out** | Over 90% of its memory limit for 5 minutes | Warning |
| **ClickHouse replicated tables read only** | A replicated table read only, or one that lost Keeper, for a minute | Critical |
| **ClickHouse data lost on a replica** | A replica found data lost | Critical |
| **ClickHouse replication stuck** | A replication queue entry stuck for a quarter of an hour | Warning |
| **ClickHouse mutations failing** | A mutation failing for a quarter of an hour | Warning |

Beyond these, two are worth adding yourself: `clickhouse.pool_used` for merges and
mutations over 90% for a quarter of an hour, and `clickhouse.errors` above 0 for the
`integrity` codes, such as `CHECKSUM_DOESNT_MATCH`.
