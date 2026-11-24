# Database stats

MaxNines can read a database's health, load and replication: how many connections it
has and how close that is to its limit, how long the oldest transaction has been open,
how far behind a replica is, and more. Each kind of database has a page of its own,
with how to turn it on, the account to sign in as, and every metric it reports:

- **[PostgreSQL](collectors-postgresql.md)**
- **[MySQL and MariaDB](collectors-mysql.md)**
- **[MongoDB](collectors-mongodb.md)**
- **[ClickHouse](collectors-clickhouse.md)**

Each is read by its built-in [template](templates.md), which reads every database of its
kind with no config rule needed.

## The database block

On a host with an agent, a database is defined in the agent's own config file,
`agent.hcl`, with where it is and how to sign in, so its password never leaves the
host:

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
| `kind` | `postgres`, `mysql` for MySQL and MariaDB, `mongodb`, or `clickhouse` |
| `target` | `host:port`. For ClickHouse, the HTTP port, usually 8123, or 8443 for HTTPS |
| `database` | PostgreSQL: the database to sign in to, by default `postgres`. MongoDB: the database the account was made in, by default `admin` |
| `tls` | `true` to only connect over TLS, which for ClickHouse is HTTPS. PostgreSQL uses TLS whenever the server offers it anyway |
| `insecure` | `true` to accept a certificate that can't be verified |
| `username`, `password` | Who to sign in as. `env()` reads the password from the agent's environment. MongoDB can be read without them where it allows that |

The name is what the database's series are called, so it can't have spaces. Restart
the agent after changing these. The agent tells the server the names and kinds of the
databases its config allows, and nothing else.

The agent keeps one connection to each database open between samples, and opens a new
one if that stops working. Each of its reads has a 5 second limit, so a busy server is
never held up by it, and its session is read only. A database that doesn't answer is
tried again after 5 seconds, then waits doubling to a minute. MongoDB has no read-only
sessions, so there what's read is up to its account.

## Hosts without an agent

For a database on a [host without an agent](agentless-hosts.md), such as a managed one,
the server reads it instead. Add a PostgreSQL, MySQL, MongoDB or ClickHouse check about
the host on the **Checks** page, with how it signs in, and tick **Read its health and
replication**. Its stats are charted on the host's metrics page, as an agent's are,
named after the check. The server keeps one connection open between runs, as an agent
does, and reads it as an agent would, with the same schedules, retries and limits.
What's read is saved as the host's each time the check runs, so it's read no more often
than the check runs. A check without **Read its health and replication** ticked only
checks the database answers.

## What the account may do

For each database a template reads, MaxNines also reads what its account may do beyond
reading, when it connects and every 5 minutes. Each of these has a series for each
database, and is 1 if it may and 0 if not:

| Metric | Unit | Series | What it is |
| --- | --- | --- | --- |
| `database_account.overprivileged` | 1 or 0 | Each database | Whether it may do any of the below |
| `database_account.superuser` | 1 or 0 | Each database | Whether it may do anything: a PostgreSQL superuser, MySQL's `SUPER` or every privilege on `*.*`, ClickHouse's `ALL` on everything, or MongoDB's `root` or `anyAction` |
| `database_account.writes` | 1 or 0 | Each database | Whether it may change data or tables anywhere: insert, update, delete, truncate, create, alter, drop, or add triggers, routines or events, including through a role or only some columns. On MongoDB, an action such as `insert`, `update`, `remove`, `createCollection` or `dropDatabase` anywhere |
| `database_account.manages` | 1 or 0 | Each database | Whether it may manage accounts or the server: create accounts, roles or databases, pass its privileges on (`WITH GRANT OPTION`, `WITH ADMIN OPTION`), replicate, or, on MySQL and MariaDB, `RELOAD`, `SHUTDOWN` or any admin privilege. On MongoDB, the actions that manage users, roles, the replica set, shards or the server, such as `createUser`, `grantRole`, `replSetConfigure`, `setParameter`, `shutdown` or `killop` |
| `database_account.server_files` | 1 or 0 | Each database | Whether it may read or write the database server's own files, or run programs there: `pg_read_server_files`, `pg_write_server_files` or `pg_execute_server_program`, or `FILE`. On ClickHouse, `FILE`, `URL`, `REMOTE`, `S3` and the other table functions that reach outside it, and `BACKUP`. MongoDB has no way to reach them but being a superuser |

MaxNines only ever reads, in sessions that can't write, but an account that can do more
is one a template's SQL, or anyone who learns its password, could misuse, so the
built-in **Database account can do more than read** alert, in the **Host** template,
warns about it. The account is still used, as what it may do is up to you. The accounts
each database's page gives can do none of these, and a template that reads your own
tables needs `SELECT` on them and nothing more, such as `GRANT SELECT ON shop.orders TO
maxnines`. It's built into MaxNines rather than a template, so it can't be changed by
changing a template; its alert can be changed or turned off. It isn't read for
MaxNines' own database, whose account has to be able to write.
