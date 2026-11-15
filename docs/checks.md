# Checks

A check tries reaching something and says whether it answered, how long it took, and
whatever else it learned on the way. The server runs the ones on the **Checks** page,
each about a [host without an agent](agentless-hosts.md) or the server itself. An
agent runs the ones in a [config rule](api-config-rules.md), from where it is, which
is how to check a database that only listens on its own host.

| Kind | Target | What it checks |
|---|---|---|
| **Website** (`http`) | An address | The page's status, timings, size and certificate, and optionally that it matches a pattern |
| **Port** (`tcp`) | `host:port` | That it accepts a connection |
| **Certificate** (`tls`) | `host:port` | The certificate, and how many days it has left |
| **DNS** (`dns`) | A host name | That it resolves, optionally from a given server |
| **Ping** (`ping`) | A host name | Round trip and packet loss |
| **PostgreSQL** (`postgres`) | `host:port` | That it answers as PostgreSQL, or that an account can sign in |
| **MySQL or MariaDB** (`mysql`) | `host:port` | Its version, from its greeting, or that an account can sign in |
| **Redis** (`redis`) | `host:port` | That it answers PING, or that an account can sign in, and its version |
| **SSH** (`ssh`) | `host:port` | Its host key and the ways it offers to sign in, or that an account can sign in |

Agents older than this version don't know the database, Redis and SSH checks. Upgrade
them before giving those kinds to them in a config rule.

## Signing in

A database, Redis or SSH check that isn't given a way to sign in checks only what it
can without one: that the server answers, and as what. Given a username and password,
or for SSH a private key, it signs in, and counts as down if it can't. Nothing else is
done once it has: no queries are run, and no commands.

### On the server

Under **Signing in** on the check's form, choose how, then give the username and the
password or key. A password or key is either typed in, and then kept in the server's
database and never shown again, on any page or through the API, or named as an
environment variable of the server's. The variable's name has to start with
`MAXNINES_SECRET_`, as for [metrics pages](agentless-hosts.md#passwords-and-tokens),
and it's read each time the check runs.

### On an agent

The server never has an agent's passwords. Instead, a `check_login` block in the
agent's own config file, `agent.hcl`, gives them, named for the check it's for:

```hcl
check_login "orders db" {
  username = "maxnines"
  password = env("ORDERS_DB_PASSWORD")
}

check_login "bastion" {
  username         = "monitor"
  private_key_file = "/etc/maxnines/bastion_key"
}

# Redis before version 6 has a password and no usernames.
check_login "cache" {
  password = env("REDIS_PASSWORD")
}
```

A login is only ever used by a check of a kind that signs in, so one named for a
website check is never sent anywhere. A key file is read when the agent starts, so it
has to be readable by the user the agent runs as. Restart the agent after changing
any of these.

### Certificates

A PostgreSQL check uses TLS whenever the server offers it, and MySQL, MariaDB and
Redis checks when **Use TLS** is ticked. The certificate is checked as a website's
is, during the handshake, so a password is never sent to a server whose certificate
can't be trusted. For a server with a certificate from a private authority, tick
**Don't count a bad certificate as down**.

MySQL 8's usual way of signing in, `caching_sha2_password`, needs TLS for an
account's first sign-in after the server restarts. Tick **Use TLS** for MySQL 8.

## SSH

Without signing in, an SSH check reports the server's host key, as its SHA-256
fingerprint, and the ways it offers to sign in, such as `publickey, password`. **SSH
offers password sign-in** is 1 while a password is accepted, to alert on for servers
that should only take keys.

Put the fingerprint the check's page shows under **Expected host key** to have any
other key count as down, as it would after a reinstall, or with someone in the
middle. A check with an expected key never signs in to a server with a different one.

OpenSSH 9.8 and later hold back an address that keeps disconnecting before signing
in, which a check does each time it doesn't sign in. Running every minute or less
often stays well clear of that. To check more often, sign in, or add the checking
host to the server's `PerSourcePenaltyExemptList`.

## Monitoring accounts

Give a check an account of its own, which can do no more than it needs. Signing in
needs almost nothing, and that's all a check does for now. Capping the account's
connections stops a check that's gone wrong from using up the server's.

### PostgreSQL

```sql
CREATE ROLE maxnines WITH LOGIN PASSWORD 'a long random password' CONNECTION LIMIT 3;
ALTER ROLE maxnines SET default_transaction_read_only = on;
ALTER ROLE maxnines SET statement_timeout = '5s';
```

Every role can connect to a database unless that's been taken away, in which case
add `GRANT CONNECT ON DATABASE postgres TO maxnines;`. Allow the checking host in
`pg_hba.conf`, preferably over TLS:

```text
hostssl  postgres  maxnines  192.0.2.10/32  scram-sha-256
```

Connect to the server itself, not through a pooler such as PgBouncer or a load
balancer, which would answer for it.

### MySQL and MariaDB

```sql
CREATE USER 'maxnines'@'192.0.2.10' IDENTIFIED BY 'a long random password'
  WITH MAX_USER_CONNECTIONS 3;
```

A user with no grants can sign in, which is all a check needs. Name the checking
host rather than `'%'`, and for a check on the same host use `127.0.0.1`, as
`localhost` means the Unix socket to MySQL. Keep the limit at 2 or more, as a quick
reconnect at a limit of 1 can be refused.

### Redis

Redis 6 and later have users of their own:

```text
ACL SETUSER maxnines on >a-long-random-password -@all +ping +info
ACL SAVE
```

`+info` lets the check report the server's version. `ACL SAVE` keeps the user over a
restart when users are kept in an ACL file; with users in `redis.conf`, use
`CONFIG REWRITE` instead. Before Redis 6 there's one password for everything, given
without a username, and the check can then do anything a client can.

On Amazon ElastiCache, users are made through its API with the same access string,
and it needs TLS.

### What other tools ask for

Monitoring tools that read a database's health, rather than just signing in, ask for
more: on PostgreSQL 10 and later, membership of `pg_monitor`; on MySQL, `PROCESS`,
`REPLICATION CLIENT` and `SELECT` on `performance_schema`; on Redis, `+info` and a
few others. MaxNines will ask for the same once its checks read more than whether
they can sign in.
