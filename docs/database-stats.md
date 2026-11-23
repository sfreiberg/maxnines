# Database stats

An agent can read a database's health, load and replication: how many connections
it has and how close that is to its limit, how long the oldest transaction has been
open, how far behind a replica is, and more, from PostgreSQL, MySQL, MariaDB,
MongoDB and ClickHouse.

## Setting one up

A database is defined in the agent's own config file, `agent.hcl`, with where it is
and how to sign in, so its password never leaves the host:

```hcl
database "orders" {
  kind     = "postgres"
  target   = "127.0.0.1:5432"
  username = "maxnines"
  password = env("ORDERS_DB_PASSWORD")
}

database "shop" {
  kind     = "mysql"
  target   = "127.0.0.1:3306"
  username = "maxnines"
  password = env("SHOP_DB_PASSWORD")
}

database "documents" {
  kind     = "mongodb"
  target   = "127.0.0.1:27017"
  username = "maxnines"
  password = env("DOCUMENTS_DB_PASSWORD")
}

database "events" {
  kind     = "clickhouse"
  target   = "127.0.0.1:8123"
  username = "maxnines"
  password = env("EVENTS_DB_PASSWORD")
}
```

| Setting | Description |
|---|---|
| `kind` | `postgres`, `mysql` for MySQL and MariaDB, `mongodb`, or `clickhouse` |
| `target` | `host:port`. For ClickHouse, the HTTP port, usually 8123, or 8443 for HTTPS |
| `database` | PostgreSQL: the database to sign in to, by default `postgres`. MongoDB: the database the account was made in, by default `admin` |
| `tls` | `true` to only connect over TLS, which for ClickHouse is HTTPS. PostgreSQL uses TLS whenever the server offers it anyway |
| `insecure` | `true` to accept a certificate that can't be verified |
| `username`, `password` | Who to sign in as. `env()` reads the password from the agent's environment. MongoDB can be read without them where it allows that |

The name is what the database's series are called, so it can't have spaces. Restart
the agent after changing these.

The agent tells the server the names and kinds of the databases its config allows,
and nothing else.

**PostgreSQL** is read by the built-in PostgreSQL [template](templates.md), for every
PostgreSQL `database` block, with no rule needed. What it found, such as the version and
whether it's a primary or a replica, and anything that went wrong, are on the
template's page and the host's **Templates** card.

**MySQL and MariaDB**, and **ClickHouse**, are read by their built-in templates the
same way.

**MongoDB** is read by MaxNines itself, once a [config rule](api-config-rules.md)
picks it, under **Databases from the agent's config**, one name to a line. A name an
agent doesn't have reports that it's missing. Nothing of it is read until a rule asks
for it. The host's metrics page lists each under **Latest databases**: whether it
answered, whether it's a primary or a replica, its version, and anything that
couldn't be read, such as for want of a privilege.

The agent keeps one connection to each database open between samples, and opens a
new one if that stops working. Each of its reads has a 5 second limit, so a busy
server is never held up by it, and its session is read only.

### Extras

After a database's name in a rule, list anything else to read, which costs more:

| Extra | What it adds |
|---|---|
| `sizes` | MongoDB only: each database's size on disk. For PostgreSQL, MySQL and ClickHouse, turn on their templates' `sizes` queries on their pages instead, and PostgreSQL's `wal_size` or MySQL's `binary_logs` |

ClickHouse is read over its HTTP interface, where a password goes with every
request as basic authentication, not as a challenge as the others sign in. So
the agent only sends one over plain HTTP to ClickHouse on its own host, at
`127.0.0.1` or `localhost`, and anywhere else needs `tls = true`. Every request is a
GET, which ClickHouse only lets read. Its template's `queries` query, off as it ships,
reads how long queries took over the last five minutes, as the median, 95th and 99th
percentiles for each kind of query, and how many failed, from `system.query_log`, which
keeps everything unless it's given a time to live, so it can be slow on a busy server.

A MongoDB database is read from the one server given, so give each member of a
replica set a block of its own. It takes `host:port`, not a `mongodb+srv://`
address.

For example, `orders sizes`.

## Templates

A [template](templates.md) for a kind of database, such as `database = "postgres"`,
runs for each `database` block of that kind in the agent's config, whether or not a
config rule reads its stats, signing in the same way. The agent reads what the server
sends it for each: the template's discover blocks first, and then its queries, each
on its own schedule and over one connection, and sends their rows with its samples
under the template's key, with whether the database answered as `<key>.up`. Whenever the
connection is opened, the first time or again after the database restarts, discovery
runs at once, and a discover block that fails is tried again within a minute. A
database that doesn't answer is tried again after 5 seconds, then waits doubling to a
minute, with nothing else run meanwhile, and one with nothing due is checked each
sample, so `<key>.up` is as recent as a sample. A statement the database refuses, or a
database that can't be reached, is shown on the template's and the host's pages until
it's right again, as [what's going
wrong](templates.md#where-it-runs-and-whats-going-wrong). Templates can read
PostgreSQL, MySQL and MariaDB, and ClickHouse so far, not MongoDB. Their stats are
their built-in templates', and MongoDB's are still read by MaxNines itself.
What the account may do beyond reading is read too, as [below](#what-the-account-may-do).

## Hosts without an agent

For a database on a [host without an agent](agentless-hosts.md), such as a managed
one, the server reads it instead. Add a PostgreSQL, MySQL, MongoDB or ClickHouse check about the
host on the **Checks** page, with how it signs in, and tick **Read its health and
replication**, with any extras. Its stats are charted on the host's metrics page, as
an agent's are, named after the check, and for the kinds MaxNines reads itself, listed
under **Latest databases** there. The server keeps one connection open between runs,
as an agent does. A PostgreSQL, MySQL or ClickHouse check's stats are its built-in
template's, read as below.

A check that reads its stats is read for [templates](#templates) too, as a database in
an agent's config is: the server runs each template for the check's kind that's for
the host, discovery first and then its queries, on the same schedules, retries and
limits as an agent, with what the account may do read too. What's read is saved as the
host's each time the check runs, the series named after the check.

## The account to sign in as

Give the agent an account of its own, which can read statistics and change nothing.

### PostgreSQL

```sql
CREATE ROLE maxnines WITH LOGIN PASSWORD 'a long random password' CONNECTION LIMIT 3;
GRANT pg_monitor TO maxnines;
ALTER ROLE maxnines SET default_transaction_read_only = on;
```

Allow it in `pg_hba.conf`, preferably over TLS unless it's on the same host. Without
`pg_monitor`, other sessions' details and some views are hidden from it.

### MySQL and MariaDB

```sql
CREATE USER 'maxnines'@'127.0.0.1' IDENTIFIED BY 'a long random password'
  WITH MAX_USER_CONNECTIONS 3;
GRANT PROCESS, REPLICATION CLIENT ON *.* TO 'maxnines'@'127.0.0.1';
GRANT SELECT ON performance_schema.* TO 'maxnines'@'127.0.0.1';
```

On MariaDB 10.5.9 and later, also `GRANT REPLICA MONITOR ON *.*`, as replication
status needs it there. Use `127.0.0.1` rather than `localhost`, which means the Unix
socket to MySQL. `PROCESS` shows the oldest transaction and query, `REPLICATION
CLIENT` a replica's state, and `performance_schema` Group Replication. For MySQL 8, set
`tls = true`, as its usual way of signing in needs TLS the first time after a
restart.

### MongoDB

```javascript
use admin
db.createUser({
  user: "maxnines",
  pwd: passwordPrompt(),
  roles: [ { role: "clusterMonitor", db: "admin" }, { role: "read", db: "local" } ]
})
```

`clusterMonitor` reads the server's status and its replica set's, and `read` on
`local` the oplog's window. An account without `clusterMonitor` can only say the
server answers and its version.

### ClickHouse

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

Everything it reads is in the `system` tables, and the grant is needed even for
those. The profile limits what a read can cost, as an account that can only read
can't be sent settings of its own. Users are kept on each server unless access
control is replicated, so make it on each.

### What the account may do

For each database a template reads, the agent also reads what its account may do
beyond reading, when it connects and every 5 minutes, as metrics named after the
database. Each is 1 if it may and 0 if not:

| Metric | It may |
| --- | --- |
| `database_account.overprivileged` | Do any of the below |
| `database_account.superuser` | Do anything: a PostgreSQL superuser, MySQL's `SUPER` or every privilege on `*.*`, or ClickHouse's `ALL` on everything |
| `database_account.writes` | Change data or tables anywhere: insert, update, delete, truncate, create, alter, drop, or add triggers, routines or events, including through a role or only some columns |
| `database_account.manages` | Manage accounts or the server: create accounts, roles or databases, pass its privileges on (`WITH GRANT OPTION`, `WITH ADMIN OPTION`), replicate, or, on MySQL and MariaDB, `RELOAD`, `SHUTDOWN` or any admin privilege |
| `database_account.server_files` | Read or write the database server's own files, or run programs there: `pg_read_server_files`, `pg_write_server_files` or `pg_execute_server_program`, or `FILE`. On ClickHouse, `FILE`, `URL`, `REMOTE`, `S3` and the other table functions that reach outside it, and `BACKUP` |

MaxNines only ever reads, in transactions that can't write, but an account that can do
more is one a template's SQL, or anyone who learns its password, could misuse, so the
built-in **Database account can do more than read** alert fires for it. The account is
still used. The accounts above can do none of these, but a template that reads your own
tables needs `SELECT` on them and nothing more, such as `GRANT SELECT ON shop.orders TO
maxnines`. On MySQL and MariaDB, roles count whether or not they're in use, as the
account could start using one, and so do roles given to those roles. On PostgreSQL 14 and older, everyone can create tables
in the `public` schema unless that's taken away, which counts as writing:

```sql
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
```

## What's read

Each kind of database has metrics of its own, named for it, such as
`postgres.connections` and `mysql.connections`, so a chart or alert rule is always
about one kind. Each value is a series named after the database, such as `orders`.
Things a database has several of are named after both, such as `shop database sales`.
PostgreSQL's, read by its template, are labelled instead, by the database as
`instance` and by what they're of, so a replication slot is the series `orders,
backups`, and a standby is labelled by its `application_name` and address, such as
`orders, walreceiver, 10.0.0.6`.

### What most kinds have

Each of these is named for its kind, such as **PostgreSQL connections** or
**MongoDB replication lag**.

| Metric | What it is |
|---|---|
| **answering**, **uptime** | Whether it could be read, and for how long it's been running |
| **connections**, **connections used** | Client connections, and as a percentage of the most allowed |
| **oldest transaction**, **oldest query** | How long the longest has been going. A long transaction holds back cleanup. Not MongoDB's or ClickHouse's oldest transaction |
| **queries** | Per second, for MySQL and ClickHouse |
| **rollbacks**, **deadlocks** | Per second, for PostgreSQL and MySQL |
| **connections refused at the limit** | Per second, for MySQL and MongoDB 6.3 and later |
| **cache hit rate** | How much of what was read was already in memory, for PostgreSQL and MySQL |
| **is a replica**, **replica receiving** | Its role, and whether a replica is still connected to what it replicates. Lag reads 0 when nothing's arriving, so check this too. Not ClickHouse, whose replicas all take writes |
| **replication lag** | On a replica, how far behind it is. For PostgreSQL, also each standby, as its primary sees it, and for MongoDB each member, as **MongoDB member lag**. For ClickHouse, the furthest behind of its replicated tables |
| **database size** | With the `sizes` extra, or for PostgreSQL its template's `sizes` query turned on |

### PostgreSQL

| Metric | What it is |
|---|---|
| **PostgreSQL queries running**, **sessions idle in a transaction**, **sessions waiting on locks**, **longest idle in a transaction** | Sessions by what they're doing |
| **PostgreSQL transactions**, **temporary files written** | Per second, across every database |
| **PostgreSQL scheduled checkpoints**, **requested checkpoints** | Many requested ones mean `max_wal_size` is too small |
| **PostgreSQL WAL written**, **WAL on disk** | Bytes per second on version 14 and later, and with the template's `wal_size` query turned on |
| **PostgreSQL blocks read**, **blocks hit** | Per second, from disk and from memory, which the cache hit rate is worked out from |
| **PostgreSQL oldest transaction ID age** | How close it is to wraparound, which stops writes at about 2 billion |
| **PostgreSQL prepared transactions** | Two-phase transactions never finished hold locks and cleanup back |
| **PostgreSQL timeline** | Rises after a failover |
| **PostgreSQL standbys**, **standby lag in bytes**, **standby streaming** | On a primary, for each standby |
| **PostgreSQL time since the replica heard from its primary**, **WAL received but not replayed**, **replay paused** | On a replica |
| **PostgreSQL WAL kept by replication slots**, **slot in use**, **slot lost**, **WAL a slot can still keep** | An unused slot keeps WAL until the disk fills |
| **PostgreSQL archiving failing**, **WAL files waiting to be archived** | When `archive_mode` is on |
| **PostgreSQL subscription running**, **subscription errors** | Logical replication into the database signed in to |

These are the built-in PostgreSQL template's, each charted by its name, such as
**PostgreSQL xid age** for `postgres.xid_age`, and its page has each one's description,
and it alerts on them itself: down, connections running out, a long transaction,
transaction IDs running out, checksum failures, replicas and standbys lagging or not
receiving, replication slots unused, holding WAL or lost, archiving failing and
subscriptions stopped. Versions 13 and later are what it's built for, back to 10, and
older ones leave out what they don't have. On Amazon Aurora, replicas don't report
their lag this way.

### MySQL and MariaDB

| Metric | What it is |
|---|---|
| **MySQL queries running**, **slow queries**, **commits** | Load |
| **MySQL failed connection attempts** | Per second |
| **MySQL temporary tables on disk** | Queries spilling to disk |
| **MySQL buffer pool dirty**, **waits for a free buffer page** | InnoDB's memory under pressure |
| **MySQL row lock waits**, **undo history length**, **open transactions** | A long history means purge is held back, usually by a long transaction |
| **MySQL read only**, **super read only** | A replica should be read only, and a primary not |
| **MySQL replica applying**, **relay log size**, **replication error code** | For each channel a replica replicates from. The unnamed one is the database's own row |
| **MySQL semi-synchronous replication on**, **semi-synchronous replicas**, **commits not acknowledged by a replica** | When semi-synchronous replication is installed. Off while enabled means it fell back to waiting for no one |
| **MySQL group members**, **group members online**, **group member online**, **group applier queue**, **group certifier queue**, **group conflicts** | Group Replication, as in InnoDB Cluster |
| **Galera node in the primary component**, **cluster size**, **node ready**, **node connected**, **node synced**, **receive queue**, **send queue**, **certification failures**, **paused for flow control** | Galera, as in MariaDB Galera Cluster and Percona XtraDB Cluster |
| **MySQL binary logs on disk** | With the template's `binary_logs` query turned on, where binary logging is |
| **MySQL seconds behind, as the replica says**, **replica's set delay**, **replication receiver error code**, **applier error code** | What replication lag and the replication error code are worked out from |
| **MySQL buffer pool read requests**, **reads from disk** | Running totals the buffer pool hit rate is worked out from |

These are the built-in MySQL template's, and it alerts on them itself: down,
connections running out, a long transaction, replication stopped or failing, a replica
lagging, a Galera node outside the primary component, and a group member offline.
Replication is read with `SHOW REPLICA STATUS` on MySQL and `SHOW ALL SLAVES STATUS` on
MariaDB, each channel a series of its own, labelled by its name, which is empty for the
unnamed one. A delayed replica's lag leaves out its delay. It's for MySQL 8.0.22 and
later, which renamed `SLAVE` to `REPLICA` and `Master` to `Source`, and any MariaDB.
Galera is only read where wsrep is on, as MariaDB reports its status without it too.

### MongoDB

| Metric | What it is |
|---|---|
| **MongoDB operations** | Per second, for each kind, such as `documents operation insert` |
| **MongoDB read latency**, **write latency** | The average time an operation took |
| **MongoDB reads queued**, **writes queued**, **read tickets free**, **write tickets free** | Work waiting its turn. Few tickets free means the storage engine is the bottleneck |
| **MongoDB cache used**, **cache dirty** | As a percentage of WiredTiger's cache. Over 20% dirty starts slowing writes |
| **MongoDB memory in use**, **cursors open**, **cursors timed out**, **assertions** | The server's own state |
| **MongoDB held back by flow control** | On a primary, when it's slowing writes for lagging secondaries |
| **MongoDB replica set members**, **members healthy**, **has a primary**, **election term** | The set as this member sees it. The term rises with each election |
| **MongoDB member healthy**, **member lag** | Each member, as this one sees it |
| **MongoDB majority commit lag** | On the primary, how far majority writes are behind |
| **MongoDB oplog window** | How long the oplog covers, which is how long a secondary can be away and still catch up |

A server's role, such as primary, secondary or standalone, is under **Latest
databases**. Ones that aren't in a replica set leave out what's about replication.

### ClickHouse

These are the built-in ClickHouse template's, and it alerts on them itself: down,
parts piling up and inserts refused, memory running out, replicated tables going read
only, data lost on a replica, and replication or mutations stuck. Each is charted by
its name, such as **ClickHouse parts used** for `clickhouse.parts_used`.

| Metric | What it is |
|---|---|
| **ClickHouse queries running**, **queries running of the most allowed** | Against `max_concurrent_queries`. Inserts waiting to be batched aren't counted, as they would be from 26.3, when inserts are batched by default |
| **ClickHouse selects**, **inserts**, **failed queries**, **failed selects**, **failed inserts**, **rows inserted**, **bytes inserted**, **rows per insert** | Load. Many inserts of few rows each make too many parts |
| **ClickHouse average query time**, **average select time**, **average insert time** | Over each sample |
| **ClickHouse most parts in a partition**, **of where inserts slow**, **parts in total** | Inserts are slowed at `parts_to_delay_insert` and refused at `parts_to_throw_insert`, 1000 and 3000 since 23.6, 150 and 300 before. The percentage is against the server's own setting |
| **ClickHouse inserts being slowed**, **inserts slowed for too many parts**, **time inserts were slowed**, **inserts refused for too many parts** | What that's costing |
| **ClickHouse inserts waiting to be batched**, **batched inserts failed**, **oldest insert waiting to be batched** | Asynchronous inserts |
| **ClickHouse memory in use**, **memory used of its limit**, **memory used by merges and mutations**, **queries over their memory limit**, **time waiting for memory** | Its limit is worked out from `max_server_memory_usage`, its share of memory (0.9 by default) and the memory it can have, as no metric gives it |
| **ClickHouse merges running**, **background pool used**, **background pool tasks** | Each pool, such as `events pool merges and mutations`. A full merge pool means merges fall behind and parts pile up |
| **ClickHouse mutations pending**, **failing**, **slowed**, **refused** | `ALTER … UPDATE` and `DELETE` still to finish, and ones that keep failing |
| **ClickHouse dictionaries failing**, **detached parts**, **parts detached as broken**, **backups and restores failed** | Read every few minutes. Detached parts on their way somewhere aren't counted |
| **ClickHouse errors** | Per second, for each error code worth knowing about, labelled by the code and the sort of trouble it is, `capacity`, `integrity`, `replication`, `distributed`, `bug` or `security`. Each is listed from the start, so the first time one happens counts. ClickHouse's own docs warn that other codes rise while queries succeed |
| **ClickHouse buffer table flush failures**, **slow disk reads**, **failed disk reads**, **failed disk writes** | Trouble underneath |
| **ClickHouse replicated tables**, **replicated tables read only**, **tables that lost Keeper**, **read-only replicas** | A table goes read only when it loses ClickHouse Keeper or ZooKeeper |
| **ClickHouse replication queue**, **longest replication queue**, **inserts waiting to replicate**, **merges waiting to replicate**, **parts still to appear**, **parts waiting to be checked**, **oldest replication queue entry**, **replication queue entries stuck**, **entries failing**, **replicas failing to update their queue** | Replication's backlog. An entry tried over 100 times, or put off over 1000, is stuck, and the newest reason one failed is on the database's own row |
| **ClickHouse tables missing a replica**, **replication log entries behind** | Read every few minutes, as they ask Keeper about every table |
| **ClickHouse replica lag behind the freshest**, **parts lost**, **parts being fetched**, **longest fetch**, **failed fetches**, **failed part checks**, **data lost on a replica**, **merges and mutations that differ from a replica**, **replicated tables shut down** | The rest of replication |
| **ClickHouse Distributed files waiting**, **bytes waiting**, **files broken**, **connections to shards retried** and **failed**, **inserts refused** and **failed**, **queues blocked**, **queue errors**, **recent errors reaching other replicas** | Distributed tables |
| **ClickHouse connected to Keeper**, **Keeper session age**, **sessions**, **sessions expired**, **requests in flight**, **average wait**, **connection errors**, **request errors** | Its connection to ClickHouse Keeper or ZooKeeper. The connection table is from 23.5 |
| **ClickHouse embedded Keeper is leader**, **synced followers**, **over its memory limit**, **clients**, **requests waiting** | When ClickHouse Keeper runs inside this server |
| **ClickHouse disk free**, **disk used**, **disk broken**, **disk read only** | For each of its disks, such as `events disk default` |
| **ClickHouse median**, **95th** and **99th percentile query time**, **queries failed in five minutes** | With the template's `queries` query turned on, for each kind of query, such as `select` |
| **ClickHouse query time**, **select time**, **insert time**, **Keeper wait**, **Keeper transactions** | The running totals the averages are worked out from |

## Good things to alert on

PostgreSQL's, MySQL's and ClickHouse's templates have their alerts already, as their
sections say. Beyond them:

- **MongoDB answering** at 0, and **connections used** over 80%.
- **Galera cluster size** below what it should be.
- **MongoDB replica set has a primary** at 0, or **members healthy** below the
  set's size.
- **MongoDB oplog window** under a day.
- On ClickHouse, beyond its template's alerts: **background pool used** for merges
  and mutations over 90% for a quarter of an hour, and **ClickHouse errors** above 0
  for the `integrity` codes, such as `CHECKSUM_DOESNT_MATCH`.

Each server reports only what it knows about itself. Comparing servers, such as
noticing two primaries at once, is planned.
