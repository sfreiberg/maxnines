# Database stats

An agent can read a database's health, load and replication: how many connections
it has and how close that is to its limit, how long the oldest transaction has been
open, how far behind a replica is, whether replication slots are holding back disk
space, and more. PostgreSQL is read today; MySQL, MariaDB and MongoDB are on the way.

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
```

| Setting | Description |
|---|---|
| `kind` | `postgres` |
| `target` | `host:port` |
| `database` | The database to sign in to. Defaults to `postgres` |
| `tls` | `true` to only connect over TLS. Without it, TLS is used whenever the server offers it |
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
couldn't be read.

### Extras

After a database's name in a rule, list anything else to read, which costs more:

| Extra | What it adds |
|---|---|
| `sizes` | Each database's size on disk, and how much WAL is kept |

For example, `orders sizes`.

## The account to sign in as

Give the agent an account of its own, in the `pg_monitor` role, which can read every
statistic and change nothing:

```sql
CREATE ROLE maxnines WITH LOGIN PASSWORD 'a long random password' CONNECTION LIMIT 3;
GRANT pg_monitor TO maxnines;
ALTER ROLE maxnines SET default_transaction_read_only = on;
```

Allow it in `pg_hba.conf`, preferably over TLS unless it's on the same host. Without
`pg_monitor`, other sessions' details and some views are hidden from it, and the
database's note says what couldn't be read. Each read also sets a 5 second statement
timeout and a 1 second lock timeout on its own connection, so a busy server is never
held up by it.

The agent keeps one connection open between samples, and opens a new one if that
stops working.

## What's read

Each value is a series named after the database, such as `orders`. Things a
database has several of are named after both, such as `orders standby replica1`,
`orders slot backups` or `orders database sales`.

| Metric | What it is |
|---|---|
| **PostgreSQL connections**, **connections used** | Client connections, and as a percentage of `max_connections` less the ones kept for superusers |
| **PostgreSQL active queries**, **sessions idle in a transaction**, **sessions waiting on locks** | Sessions by what they're doing |
| **PostgreSQL oldest transaction**, **oldest query**, **longest idle in a transaction** | How long the longest has been going. A long transaction holds back vacuum |
| **PostgreSQL transactions**, **rollbacks**, **deadlocks** | Per second, across every database |
| **PostgreSQL cache hit rate** | How much of what was read was already in memory |
| **PostgreSQL temporary files written** | Queries spilling to disk |
| **PostgreSQL scheduled checkpoints**, **requested checkpoints** | Many requested ones mean `max_wal_size` is too small |
| **PostgreSQL WAL written** | Bytes per second, on version 14 and later |
| **PostgreSQL oldest transaction ID age** | How close it is to wraparound, which stops writes at about 2 billion |
| **PostgreSQL prepared transactions** | Two-phase transactions never finished hold locks and vacuum back |
| **PostgreSQL is a replica**, **timeline** | Its role, and a timeline that rises after a failover |
| **PostgreSQL replication lag** | On a replica, how far behind its primary it is. On a primary, for each standby |
| **PostgreSQL standby lag in bytes**, **standby streaming** | For each standby of a primary |
| **PostgreSQL replica receiving**, **time since the replica heard from its primary** | Whether a replica is still connected. Lag reads 0 when nothing's arriving, so check this too |
| **PostgreSQL WAL received but not replayed**, **replay paused** | On a replica |
| **PostgreSQL WAL kept by replication slots**, **slot in use**, **slot lost**, **WAL a slot can still keep** | An unused slot keeps WAL until the disk fills |
| **PostgreSQL archiving failing**, **WAL files waiting to be archived** | When `archive_mode` is on |
| **PostgreSQL subscription running**, **subscription errors** | Logical replication into the database signed in to |
| **PostgreSQL database size**, **WAL on disk** | With the `sizes` extra |

Versions 13 and later are what it's built for, and older ones leave out what they
don't have. On Amazon Aurora, replicas don't report their lag this way.

### Good things to alert on

- **PostgreSQL answering** at 0.
- **PostgreSQL connections used** over 80%.
- **PostgreSQL replication lag** over a minute, and **replica receiving** at 0 on a
  replica.
- **PostgreSQL oldest transaction** over half an hour.
- **PostgreSQL oldest transaction ID age** over a billion.
- **PostgreSQL slot lost** at 1, or **WAL kept by replication slots** growing.
- **PostgreSQL archiving failing** at 1.

Each server reports only what it knows about itself. Comparing servers, such as
noticing two primaries at once, is planned.
