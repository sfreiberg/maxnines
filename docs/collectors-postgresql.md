# PostgreSQL

MaxNines reads a PostgreSQL server's health, load and replication: its connections
against its limit, long transactions and queries, how close it is to running out of
transaction IDs, replication from both ends, replication slots, WAL archiving and
logical replication subscriptions. It's read by the built-in **PostgreSQL**
[template](templates.md), with SQL, the same way on an agent and on the server.

It's built for PostgreSQL 13 and later, and reads back to 10, leaving out what older
versions don't have. On Amazon Aurora, replicas don't report their lag this way.

## Turning it on

**On a host with an agent**, add a `database` block to the agent's own `agent.hcl`,
with where the server is and how to sign in, so the password never leaves the host:

```hcl
database "orders" {
  kind     = "postgres"
  target   = "127.0.0.1:5432"
  username = "maxnines"
  password = env("ORDERS_DB_PASSWORD")
}
```

`database` is the database to sign in to, by default `postgres`. TLS is used whenever
the server offers it, and `tls = true` refuses to connect without it. The
[settings](database-stats.md#the-database-block) are the same for every kind of
database. Restart the agent after changing them.

That's all: the PostgreSQL template reads every PostgreSQL `database` block on every
host it's for, which as it ships is every host, with no config rule needed. Choose
which hosts on the template's page, under **Settings > Templates**, or turn it off
there.

**On a host without an agent**, such as a managed database, add a PostgreSQL check about
the host on the **Checks** page, with how it signs in, and tick **Read its health and
replication**. See [hosts without an agent](database-stats.md#hosts-without-an-agent).

**MaxNines' own database**, when it's PostgreSQL, is read by the server itself, with
the template as it ships. See [MaxNines' own
database](templates.md#hosts-without-an-agent-and-maxnines-own-database).

## The account to sign in as

Give MaxNines an account of its own, which can read statistics and change nothing:

```sql
CREATE ROLE maxnines WITH LOGIN PASSWORD 'a long random password' CONNECTION LIMIT 3;
GRANT pg_monitor TO maxnines;
ALTER ROLE maxnines SET default_transaction_read_only = on;
```

Allow it in `pg_hba.conf`, preferably over TLS unless it's on the same host. Without
`pg_monitor`, other sessions' details and some views are hidden from it.

On PostgreSQL 14 and older, everyone can create tables in the `public` schema until
that's taken away, which counts as [writing](database-stats.md#what-the-account-may-do),
so the **Database account can do more than read** alert warns until you run:

```sql
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
```

A role the account is in only after `SET ROLE`, one made `NOINHERIT`, isn't looked at.

## What's read, and how often

The template finds out about the server first, and reads the rest every sample:

- **`server`**, every hour: the version, which picks the SQL for that version, and
  whether WAL archiving is on.
- **`role`**, every 10 seconds: whether it's a primary or a replica, so a failover is
  noticed quickly. What's about standbys is read only on a primary, and what's about
  replaying WAL only on a replica.

Two queries ship turned off, as they're slow on big servers. Turn either on with
**Enable** under **Queries** on the template's page:

- **`sizes`**, every 5 minutes: each database's size on disk.
- **`wal_size`**, every 5 minutes: the WAL kept on disk.

What discovery found, and anything that went wrong, such as a view the account isn't
allowed, are on the template's page and the host's **Templates** card.

## What's reported

Each metric has a series for each database block or check, labelled `instance`, such
as `orders`, and those about several things are labelled by them too, so a
replication slot is the series `orders, backups`, and a standby is labelled by its
`application_name` and address, such as `orders, walreceiver, 10.0.0.6`.

| Metric | Unit | Series | What it is |
| --- | --- | --- | --- |
| `postgres.up` | 1 or 0 | Each database | Whether the database answered |
| `postgres.uptime` | Seconds | Each database | How long the server has been running |
| `postgres.replica` | 1 or 0 | Each database | Whether it's a replica, replaying another server's WAL |
| `postgres.connections` | Number | Each database | Client connections |
| `postgres.connections_used` | % | Each database | Connections in use, out of those not reserved for superusers |
| `postgres.running_queries` | Number | Each database | Sessions running a query |
| `postgres.idle_in_transaction` | Number | Each database | Sessions idle in an open transaction |
| `postgres.lock_waits` | Number | Each database | Sessions waiting on a lock |
| `postgres.oldest_transaction` | Seconds | Each database | How long the longest open transaction has been open. A long one holds back vacuum |
| `postgres.oldest_query` | Seconds | Each database | How long the longest-running query has been running |
| `postgres.oldest_idle_in_transaction` | Seconds | Each database | How long the longest session idle in a transaction has been idle |
| `postgres.transactions` | A second | Each database | Transactions committed and rolled back, across every database |
| `postgres.rollbacks` | A second | Each database | Transactions rolled back |
| `postgres.blocks_read` | A second | Each database | Blocks read from disk rather than memory |
| `postgres.blocks_hit` | A second | Each database | Blocks found in memory |
| `postgres.temp_written` | Bytes a second | Each database | Temporary files written by queries too big for `work_mem` |
| `postgres.deadlocks` | A second | Each database | Deadlocks |
| `postgres.conflicts` | A second | Each database | Queries on a replica cancelled because of what it was replaying |
| `postgres.checksum_failures` | A second | Each database | Data checksum failures, where checksums are on |
| `postgres.cache_hit` | % | Each database | Reads served from memory rather than disk, worked out from `blocks_read` and `blocks_hit` |
| `postgres.checkpoints_timed` | A second | Each database | Checkpoints that came on schedule |
| `postgres.checkpoints_requested` | A second | Each database | Checkpoints forced by WAL filling up. Many mean `max_wal_size` is too small |
| `postgres.wal_written` | Bytes a second | Each database | WAL written. Version 14 and later |
| `postgres.xid_age` | Number | Each database | Transactions since the oldest database was last frozen. Writes stop near 2.1 billion |
| `postgres.mxid_age` | Number | Each database | Multixact IDs since the oldest database was last frozen, which wrap around as transaction IDs do |
| `postgres.prepared` | Number | Each database | Two-phase transactions prepared and never finished, which hold locks and cleanup back |
| `postgres.oldest_prepared` | Seconds | Each database | How long the oldest prepared transaction has waited |
| `postgres.streaming` | 1 or 0 | Each database and standby | On a primary, whether each standby is streaming |
| `postgres.lag_bytes` | Bytes | Each database and standby | On a primary, how far behind each standby is in WAL |
| `postgres.lag` | Seconds | Each database, and on a primary each standby | How far behind a replica is, or on a primary each standby, as the primary sees it |
| `postgres.standbys` | Number | Each database | On a primary, standbys streaming and replaying what they're sent, leaving out one catching up, `pg_basebackup`, `pg_receivewal` and logical replication |
| `postgres.synchronous_standbys` | Number | Each database | On a primary, synchronous standbys connected |
| `postgres.replay_backlog` | Bytes | Each database | On a replica, WAL received but not replayed yet |
| `postgres.replay_paused` | 1 or 0 | Each database | On a replica, whether replay is paused |
| `postgres.receiving` | 1 or 0 | Each database | On a replica, whether it's connected to its primary. Lag reads 0 when nothing's arriving, so watch this too |
| `postgres.last_received` | Seconds | Each database | On a replica, how long since it heard from its primary |
| `postgres.timeline` | Number | Each database | On a replica, its timeline, which rises after a failover |
| `postgres.slot_in_use` | 1 or 0 | Each database and slot | Whether each replication slot has something using it |
| `postgres.slot_headroom` | Bytes | Each database and slot | WAL a slot can still keep before it's lost. None unless `max_slot_wal_keep_size` is set |
| `postgres.slot_retained` | Bytes | Each database and slot | WAL kept for each slot. An unused slot keeps it until the disk fills |
| `postgres.slot_lost` | 1 or 0 | Each database and slot | Whether each slot has lost WAL it needed |
| `postgres.archived` | A second | Each database | WAL files archived, when `archive_mode` is on |
| `postgres.archive_failures` | A second | Each database | WAL archiving failures |
| `postgres.archive_failing` | 1 or 0 | Each database | Whether the last attempt to archive failed |
| `postgres.archive_waiting` | Number | Each database | WAL files waiting to be archived. Version 12 and later |
| `postgres.subscription_running` | 1 or 0 | Each database and subscription | Whether each logical replication subscription into the database signed in to is running |
| `postgres.subscription_errors` | A second | Each database and subscription | Errors in each subscription |
| `postgres.size` | Bytes | Each database and database in it | Each database's size on disk, with the `sizes` query turned on |
| `postgres.wal_size` | Bytes | Each database | WAL kept on disk, with the `wal_size` query turned on |

## Built-in alerts

The template brings these, for each PostgreSQL database it reads. Change or turn off
any of them on the template's page.

| Alert | When | Level |
| --- | --- | --- |
| **PostgreSQL down** | It hasn't answered for a minute | Critical |
| **PostgreSQL connections running out** | Over 80% of connections used for 5 minutes, or over 90% | Warning, then critical |
| **PostgreSQL long-running transaction** | A transaction has been open over an hour | Warning |
| **PostgreSQL transaction IDs running out** | `xid_age` over 1 billion for 10 minutes, or over 1.5 billion | Warning, then critical |
| **PostgreSQL data checksum failures** | Any checksum failure | Critical |
| **PostgreSQL replica lagging** | A replica over 30 seconds behind for 2 minutes, or over 5 minutes | Warning, then critical |
| **PostgreSQL replica not receiving** | A replica not connected to its primary for 2 minutes | Critical |
| **PostgreSQL standby falling behind** | On a primary, a standby over 30 seconds behind for 2 minutes, or over 5 minutes | Warning, then critical |
| **PostgreSQL too few standbys** | On a primary, no standby for 2 minutes. Off as it ships: set how many a primary should have, and turn it on | Critical |
| **PostgreSQL replication slot unused** | A slot nothing has used for half an hour | Warning |
| **PostgreSQL replication slot holding WAL** | A slot keeping over 10 GiB for 5 minutes, or over 50 GiB, or an unused one over 10 GiB | Warning, then critical |
| **PostgreSQL replication slot lost** | A slot has lost WAL it needed | Critical |
| **PostgreSQL WAL archiving failing** | Archiving has been failing for 5 minutes | Critical |
| **PostgreSQL subscription stopped** | A subscription hasn't been running for 5 minutes | Critical |
