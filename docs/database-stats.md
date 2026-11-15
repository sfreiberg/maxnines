# Database stats

An agent can read a database's health, load and replication: how many connections
it has and how close that is to its limit, how long the oldest transaction has been
open, how far behind a replica is, and more. PostgreSQL, MySQL and MariaDB are read
today, and MongoDB is on the way.

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
```

| Setting | Description |
|---|---|
| `kind` | `postgres`, or `mysql` for MySQL and MariaDB |
| `target` | `host:port` |
| `database` | PostgreSQL: the database to sign in to. Defaults to `postgres` |
| `tls` | `true` to only connect over TLS. PostgreSQL uses TLS whenever the server offers it anyway |
| `insecure` | `true` to accept a certificate that can't be verified |
| `username`, `password` | Who to sign in as. `env()` reads the password from the agent's environment |

The name is what the database's series are called, so it can't have spaces. Restart
the agent after changing these.

The agent tells the server the names of the databases its config allows, and nothing
else. A [config rule](api-config-rules.md) then picks which to read, under
**Databases from the agent's config**, one name to a line. A name an agent doesn't
have reports that it's missing. Nothing is read until a rule asks for it.

The host's metrics page lists each database under **Latest databases**: whether it
answered, whether it's a primary or a replica, its version, and anything that
couldn't be read, such as for want of a privilege.

The agent keeps one connection to each database open between samples, and opens a
new one if that stops working. Each of its reads has a 5 second limit, so a busy
server is never held up by it, and its session is read only.

### Extras

After a database's name in a rule, list anything else to read, which costs more:

| Extra | What it adds |
|---|---|
| `sizes` | Each database's size on disk. PostgreSQL adds the WAL kept, and MySQL the binary logs |

For example, `orders sizes`.

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

## What's read

Each value is a series named after the database, such as `orders`. Things a
database has several of are named after both, such as `orders standby replica1`,
`orders slot backups` or `shop database sales`.

### Every kind

| Metric | What it is |
|---|---|
| **Database answering**, **uptime** | Whether it could be read, and for how long it's been running |
| **Database connections**, **connections used** | Client connections, and as a percentage of the most allowed |
| **Database oldest transaction**, **oldest query** | How long the longest has been going. A long transaction holds back cleanup |
| **Database rollbacks**, **deadlocks** | Per second |
| **Database cache hit rate** | How much of what was read was already in memory |
| **Database is a replica**, **replica receiving** | Its role, and whether a replica is still connected to what it replicates. Lag reads 0 when nothing's arriving, so check this too |
| **Database replication lag** | On a replica, how far behind it is. For PostgreSQL, also each standby, as its primary sees it |
| **Database size** | With the `sizes` extra |

### PostgreSQL

| Metric | What it is |
|---|---|
| **PostgreSQL active queries**, **sessions idle in a transaction**, **sessions waiting on locks**, **longest idle in a transaction** | Sessions by what they're doing |
| **PostgreSQL transactions**, **temporary files written** | Per second, across every database |
| **PostgreSQL scheduled checkpoints**, **requested checkpoints** | Many requested ones mean `max_wal_size` is too small |
| **PostgreSQL WAL written**, **WAL on disk** | Bytes per second on version 14 and later, and with the `sizes` extra |
| **PostgreSQL oldest transaction ID age** | How close it is to wraparound, which stops writes at about 2 billion |
| **PostgreSQL prepared transactions** | Two-phase transactions never finished hold locks and cleanup back |
| **PostgreSQL timeline** | Rises after a failover |
| **PostgreSQL standbys**, **standby lag in bytes**, **standby streaming** | On a primary, for each standby |
| **PostgreSQL time since the replica heard from its primary**, **WAL received but not replayed**, **replay paused** | On a replica |
| **PostgreSQL WAL kept by replication slots**, **slot in use**, **slot lost**, **WAL a slot can still keep** | An unused slot keeps WAL until the disk fills |
| **PostgreSQL archiving failing**, **WAL files waiting to be archived** | When `archive_mode` is on |
| **PostgreSQL subscription running**, **subscription errors** | Logical replication into the database signed in to |

Versions 13 and later are what it's built for, and older ones leave out what they
don't have. On Amazon Aurora, replicas don't report their lag this way.

### MySQL and MariaDB

| Metric | What it is |
|---|---|
| **MySQL queries running**, **queries**, **slow queries**, **commits** | Load |
| **MySQL connections refused at the limit**, **failed connection attempts** | Per second |
| **MySQL temporary tables on disk** | Queries spilling to disk |
| **MySQL buffer pool dirty**, **waits for a free buffer page** | InnoDB's memory under pressure |
| **MySQL row lock waits**, **undo history length**, **open transactions** | A long history means purge is held back, usually by a long transaction |
| **MySQL read only**, **super read only** | A replica should be read only, and a primary not |
| **MySQL replica applying**, **relay log size**, **replication error code** | For each channel a replica replicates from. The unnamed one is the database's own row |
| **MySQL semi-synchronous replication on**, **semi-synchronous replicas**, **commits not acknowledged by a replica** | When semi-synchronous replication is installed. Off while enabled means it fell back to waiting for no one |
| **MySQL group members**, **group members online**, **group member online**, **group applier queue**, **group certifier queue**, **group conflicts** | Group Replication, as in InnoDB Cluster |
| **Galera cluster primary**, **cluster size**, **node ready**, **node connected**, **node synced**, **receive queue**, **send queue**, **certification failures**, **paused for flow control** | Galera, as in MariaDB Galera Cluster and Percona XtraDB Cluster |
| **MySQL binary logs on disk** | With the `sizes` extra |

Replication's statements and fields were renamed in MySQL 8.0.22, from `SLAVE` to
`REPLICA` and `Master` to `Source`, and MariaDB kept most of the old names. Either
works. A delayed replica's lag leaves out its delay.

## Good things to alert on

- **Database answering** at 0.
- **Database connections used** over 80%.
- **Database replication lag** over a minute, and **replica receiving** at 0 on a
  replica.
- **Database oldest transaction** over half an hour.
- **PostgreSQL oldest transaction ID age** over a billion.
- **PostgreSQL slot lost** at 1, or **WAL kept by replication slots** growing.
- **PostgreSQL archiving failing** at 1.
- **MySQL replication error code** above 0, or **replica applying** at 0.
- **Galera cluster primary** at 0, or **cluster size** below what it should be.

Each server reports only what it knows about itself. Comparing servers, such as
noticing two primaries at once, is planned.
