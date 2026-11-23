# MySQL and MariaDB

MaxNines reads a MySQL or MariaDB server's health, load and replication: its
connections against its limit, InnoDB's buffer pool, long transactions and queries,
replication into it for each channel, semi-synchronous replication, Group Replication,
as in InnoDB Cluster, and Galera, as in MariaDB Galera Cluster and Percona XtraDB
Cluster. It's read by the built-in **MySQL** [template](templates.md), with SQL, the
same way on an agent and on the server.

It reads MySQL 8.0.22 and later, which renamed `SLAVE` to `REPLICA` and `Master` to
`Source`, and MariaDB. Older MySQL isn't read. Where MySQL and MariaDB differ, the
template has a query for each, and reads the one for what it finds.

## Turning it on

**On a host with an agent**, add a `database` block to the agent's own `agent.hcl`,
with where the server is and how to sign in, so the password never leaves the host:

```hcl
database "shop" {
  kind     = "mysql"
  target   = "127.0.0.1:3306"
  username = "maxnines"
  password = env("SHOP_DB_PASSWORD")
  tls      = true
}
```

`kind = "mysql"` is for MariaDB too. For MySQL 8, set `tls = true`, as its usual way of
signing in needs TLS the first time after a restart. The
[settings](database-stats.md#the-database-block) are the same for every kind of
database. Restart the agent after changing them.

That's all: the MySQL template reads every MySQL `database` block on every host it's
for, which as it ships is every host, with no config rule needed. Choose which hosts
on the template's page, under **Settings > Templates**, or turn it off there.

**On a host without an agent**, such as a managed database, add a MySQL check about the
host on the **Checks** page, with how it signs in, and tick **Read its health and
replication**. See [hosts without an agent](database-stats.md#hosts-without-an-agent).

**MaxNines' own database**, when it's MySQL or MariaDB, is read by the server itself,
with the template as it ships. See [MaxNines' own
database](templates.md#hosts-without-an-agent-and-maxnines-own-database).

## The account to sign in as

Give MaxNines an account of its own, which can read statistics and change nothing:

```sql
CREATE USER 'maxnines'@'127.0.0.1' IDENTIFIED BY 'a long random password'
  WITH MAX_USER_CONNECTIONS 3;
GRANT PROCESS, REPLICATION CLIENT ON *.* TO 'maxnines'@'127.0.0.1';
GRANT SELECT ON performance_schema.* TO 'maxnines'@'127.0.0.1';
```

On MariaDB 10.5.9 and later, also:

```sql
GRANT REPLICA MONITOR ON *.* TO 'maxnines'@'127.0.0.1';
```

Use `127.0.0.1` rather than `localhost`, which means the Unix socket to MySQL.
`PROCESS` shows the oldest transaction and query, `REPLICATION CLIENT`, or `REPLICA
MONITOR`, a replica's state, and `performance_schema` the server's status and Group
Replication.

Every role the account has been given counts towards [what it may
do](database-stats.md#what-the-account-may-do), whether or not it's in use, as the
account could start using it, and so do roles given to those roles. `EXECUTE` and `LOCK
TABLES` don't count as writing, as MySQL's `sys` schema needs `EXECUTE`.

## What's read, and how often

The template finds out about the server first, every hour, with **`server`**: its
version, whether it's MariaDB, and whether binary logging is on. Then it reads the rest
every sample:

- the server's status, InnoDB, transactions and the longest query;
- replication, with `SHOW REPLICA STATUS` on MySQL and `SHOW ALL SLAVES STATUS` on
  MariaDB, each channel a series of its own, labelled by its name, which is empty for
  the unnamed one;
- Group Replication, on MySQL, and Galera, on MariaDB where wsrep is on, as MariaDB
  reports Galera's status without it too.

Two queries ship turned off. Turn either on with **Enable** under **Queries** on the
template's page:

- **`sizes`**, every 5 minutes: each database's size on disk.
- **`binary_logs`**, every 5 minutes: the binary logs on disk, with `SHOW BINARY LOGS`,
  where binary logging is on.

What discovery found, and anything that went wrong, are on the template's page and the
host's **Templates** card.

## What's reported

Each metric has a series for each database block or check, labelled `instance`, such
as `shop`, and those about several things are labelled by them too, so replication
from the channel `east` is the series `shop, east`.

| Metric | Unit | Series | What it is |
| --- | --- | --- | --- |
| `mysql.up` | 1 or 0 | Each database | Whether the database answered |
| `mysql.uptime` | Seconds | Each database | How long the server has been running |
| `mysql.connections` | Number | Each database | Client connections |
| `mysql.connections_used` | % | Each database | Connections as a percentage of `max_connections` |
| `mysql.running_queries` | Number | Each database | Threads running a query |
| `mysql.queries` | A second | Each database | Statements run |
| `mysql.slow_queries` | A second | Each database | Queries slower than `long_query_time` |
| `mysql.refused` | A second | Each database | Connections refused for being over `max_connections` |
| `mysql.aborted_connects` | A second | Each database | Failed attempts to connect, such as a wrong password |
| `mysql.tmp_disk_tables` | A second | Each database | Temporary tables written to disk, from queries spilling out of memory |
| `mysql.pool_requests` | A second | Each database | Reads asked of the InnoDB buffer pool |
| `mysql.pool_reads` | A second | Each database | Of those, reads it had to go to disk for |
| `mysql.pool_dirty` | % | Each database | Buffer pool pages changed and not written yet |
| `mysql.pool_waits` | A second | Each database | Times InnoDB had to wait for a free page in the buffer pool |
| `mysql.lock_waits` | Number | Each database | Row lock waits going on now |
| `mysql.read_only` | 1 or 0 | Each database | Whether it's read only, in any of MariaDB's read-only modes. A replica should be, and a primary not |
| `mysql.super_read_only` | 1 or 0 | Each database | Whether it's read only even to accounts with `SUPER`. MySQL only |
| `mysql.semi_sync` | 1 or 0 | Each database | Whether semi-synchronous replication is on. Off while it's enabled means it fell back to waiting for no replica |
| `mysql.semi_sync_clients` | Number | Each database | Semi-synchronous replicas connected |
| `mysql.semi_sync_misses` | A second | Each database | Commits that went ahead without a replica acknowledging them |
| `mysql.cache_hit` | % | Each database | Reads served from the buffer pool rather than disk, worked out from `pool_requests` and `pool_reads` |
| `mysql.deadlocks` | A second | Each database | InnoDB deadlocks |
| `mysql.history_length` | Number | Each database | InnoDB undo history length. A long history means purge is held back, usually by a long transaction |
| `mysql.commits` | A second | Each database | Transactions committed |
| `mysql.rollbacks` | A second | Each database | Transactions rolled back |
| `mysql.replica` | 1 or 0 | Each database | Whether it's a replica. On MariaDB, whether its replication threads are running |
| `mysql.galera_primary` | 1 or 0 | Each database | Whether this Galera node is in the primary component. MariaDB with wsrep on |
| `mysql.galera_size` | Number | Each database | Nodes in the Galera cluster |
| `mysql.galera_ready` | 1 or 0 | Each database | Whether the node is ready to take queries |
| `mysql.galera_connected` | 1 or 0 | Each database | Whether the node is connected to the cluster |
| `mysql.galera_synced` | 1 or 0 | Each database | Whether the node is synced |
| `mysql.galera_receive_queue` | Number | Each database | Write sets waiting to be applied |
| `mysql.galera_send_queue` | Number | Each database | Write sets waiting to be sent |
| `mysql.galera_cert_failures` | A second | Each database | Transactions that failed certification |
| `mysql.galera_flow_paused` | % | Each database | The share of the time replication was paused for flow control |
| `mysql.open_transactions` | Number | Each database | InnoDB transactions open |
| `mysql.oldest_transaction` | Seconds | Each database | How long the longest open transaction has been open |
| `mysql.oldest_query` | Seconds | Each database | How long the longest-running query has been running |
| `mysql.receiving` | 1 or 0 | Each database and replication channel | Whether the replica is receiving from its source, for each channel |
| `mysql.applying` | 1 or 0 | Each database and replication channel | Whether the replica is applying what it received, for each channel |
| `mysql.behind` | Seconds | Each database and replication channel | How far behind the replica says it is (`Seconds_Behind_Source`), which lag is worked out from |
| `mysql.delay` | Seconds | Each database and replication channel | The delay the replica is set to keep (`SQL_Delay`) |
| `mysql.relay_log` | Bytes | Each database and replication channel | The relay log's size on disk |
| `mysql.io_errno` | Number | Each database and replication channel | The receiver thread's last error code, or 0 |
| `mysql.sql_errno` | Number | Each database and replication channel | The applier thread's last error code, or 0 |
| `mysql.lag` | Seconds | Each database and replication channel | How far behind a replica is, leaving out a delay it's set to keep |
| `mysql.replication_errno` | Number | Each database and replication channel | The replication error code, from the receiver or applier, or 0 |
| `mysql.group_members` | Number | Each database | Group Replication members, as in InnoDB Cluster. MySQL only |
| `mysql.group_online` | Number | Each database | Group members online |
| `mysql.applier_queue` | Number | Each database | Transactions waiting to be applied on this member |
| `mysql.certifier_queue` | Number | Each database | Transactions waiting to be certified on this member |
| `mysql.group_conflicts` | A second | Each database | Transactions that failed certification for conflicting with another member's |
| `mysql.member_online` | 1 or 0 | Each database and group member | Whether each group member is online |
| `mysql.size` | Bytes | Each database and database in it | Each database's size on disk, with the `sizes` query turned on |
| `mysql.binlog_size` | Bytes | Each database | Binary logs on disk, with the `binary_logs` query turned on, where binary logging is |

## Built-in alerts

The template brings these, for each MySQL or MariaDB database it reads. Change or turn
off any of them on the template's page.

| Alert | When | Level |
| --- | --- | --- |
| **MySQL down** | It hasn't answered for a minute | Critical |
| **MySQL connections running out** | Over 80% of connections used for 5 minutes, or over 90% | Warning, then critical |
| **MySQL long-running transaction** | A transaction has been open over an hour | Warning |
| **MySQL replication stopped** | A replica not receiving, not applying, or with a replication error, for 2 minutes | Critical |
| **MySQL replica lagging** | A replica over a minute behind for 2 minutes, or over 5 minutes | Warning, then critical |
| **Galera node not in the primary component** | A Galera node outside the primary component for a minute | Critical |
| **MySQL group member offline** | A Group Replication member offline for 2 minutes | Critical |

A Galera cluster smaller than it should be is worth an alert of your own, on
`mysql.galera_size`.
