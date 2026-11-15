# Checks

A check tries reaching something and says whether it answered, how long it took, and
whatever else it learned on the way. The server runs the ones on the **Checks** page,
each about a [host without an agent](agentless-hosts.md) or the server itself. An
agent runs the ones a [config rule](api-config-rules.md) gives it, from where it is,
which is how to check something that only listens on its own host. Ones that sign in
are defined in the agent's own config, as [below](#on-an-agent).

| Kind | Target | What it checks |
|---|---|---|
| **Website** (`http`) | An address | The page's status, timings, size and certificate, when its domain registration runs out, and optionally that it matches a pattern |
| **Port** (`tcp`) | `host:port` | That it accepts a connection |
| **Certificate** (`tls`) | `host:port` | The certificate, and how many days it has left |
| **DNS** (`dns`) | A host name | That it resolves, optionally from a given server |
| **Ping** (`ping`) | A host name | Round trip and packet loss |
| **PostgreSQL** (`postgres`) | `host:port` | That it answers as PostgreSQL, or that an account can sign in |
| **MySQL or MariaDB** (`mysql`) | `host:port` | Its version, from its greeting, or that an account can sign in |
| **Redis** (`redis`) | `host:port` | That it answers PING, or that an account can sign in, and its version |
| **MongoDB** (`mongodb`) | `host:port` | That it answers as MongoDB, or that an account can sign in, and its version |
| **ClickHouse** (`clickhouse`) | `host:port`, its HTTP port | That it answers its ping, or that an account can sign in, and its version |
| **SSH** (`ssh`) | `host:port` | Its host key and the ways it offers to sign in, or that an account can sign in |
| **Mail sending** (`smtp`) | `host:port` | That it greets as a mail server, or that an account can sign in to send |
| **Mailbox** (`imap`, `pop3`) | `host:port` | That it greets as one, or that an account can sign in |

Agents older than this version don't know the database, Redis, SSH and mail checks. Upgrade
them before giving those kinds to them in a config rule.

## Domain expiry

A website check also finds out when the site's domain registration runs out, from the
domain's registry over RDAP, the successor to WHOIS, and reports it as **Domain days
left**. IANA's list says which registry answers for each top-level domain, and the
check asks about the site's host name and then each name above it until the registry
recognises one, so `www.example.co.uk` finds `example.co.uk`.

- Each domain is asked about at most twice a day, and IANA's list once a day, however
  often the check runs, as registries limit how often they're asked.
- It happens after the check's own timing and never makes the check fail. If the
  registry can't be reached, or doesn't say, the check's result says why.
- Addresses and names without a public registry, such as `printer.local`, are skipped,
  and so are domains whose registry doesn't offer RDAP, such as `.io`.
- Untick **Look up when the domain expires** on the check to turn it off.

To be warned in good time, add an alert rule on **Domain days left** below 30.

## Signing in

A database, Redis, SSH or mail check that isn't given a way to sign in checks only
what it can without one: that the server answers, and as what. Given a username and
password, or for SSH a private key, it signs in, and counts as down if it can't.
Nothing else is done once it has: no queries are run, no commands, and no mail is
sent or read.

### On the server

Under **Signing in** on the check's form, choose how, then give the username and the
password or key. A password or key is either typed in, and then kept in the server's
database and never shown again, on any page or through the API, or named as an
environment variable of the server's. The variable's name has to start with
`MAXNINES_SECRET_`, as for [metrics pages](agentless-hosts.md#passwords-and-tokens),
and it's read each time the check runs.

### On an agent

The server never has an agent's passwords, and never chooses where they go. A check
that signs in is a `check` block in the agent's own config file, `agent.hcl`, with
what it reaches and how it signs in:

```hcl
check "bastion" {
  kind             = "ssh"
  target           = "bastion.example.com:22"
  username         = "monitor"
  private_key_file = "/etc/maxnines/bastion_key"
  host_key         = "SHA256:Dfij..."
}

check "mail" {
  kind     = "imap"
  target   = "mail.example.com:993"
  tls      = true
  username = "monitor@example.com"
  password = env("MAIL_PASSWORD")
}

# Redis before version 6 has a password and no usernames.
check "cache" {
  kind     = "redis"
  target   = "127.0.0.1:6379"
  password = env("REDIS_PASSWORD")
}
```

Each can also have `insecure = true`. A database is a [`database` block](database-stats.md)
instead, which reads its stats as well as whether it answers. The agent tells the server the names of the
checks its config allows, never more, and a [config rule](api-config-rules.md) picks
which of them to run and how often, under **Checks from the agent's config**. A name
the agent doesn't have reports that it's missing. Checks with nothing to sign in
with, such as a website's, are given whole in the config rule instead, and a `check`
block of a kind that never signs in is refused.

A key file is read when the agent starts, so it has to be readable by the user the
agent runs as. Restart the agent after changing any of these.

### Certificates

A PostgreSQL check uses TLS whenever the server offers it, and MySQL, MariaDB,
Redis and MongoDB checks when **Use TLS** is ticked. The certificate is checked as a website's
is, during the handshake, so a password is never sent to a server whose certificate
can't be trusted. For a server with a certificate from a private authority, tick
**Don't count a bad certificate as down**.

A mail check uses TLS from the start when **Use TLS from the start** is ticked, as on
ports 465 (SMTP), 993 (IMAP) and 995 (POP3). Otherwise it connects in the clear and,
before signing in, upgrades with STARTTLS (STLS for POP3). A server that won't
upgrade isn't sent the password, and the check counts as down, saying why. Use a
mailbox set aside for the check.

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

### MongoDB

```javascript
use admin
db.createUser({ user: "maxnines", pwd: passwordPrompt(), roles: [] })
```

A user with no roles can sign in and be told the server's version, which is all a
check needs. Make it in `admin`, or give the database it was made in as the check's
**Database**.

A MongoDB check talks to the one server it's given, never the rest of its replica
set or cluster, so give each member its own check. It takes `host:port`, not a
`mongodb+srv://` address; on Atlas, use a member's host name, shown under the
cluster's connection details, and tick **Use TLS**, which Atlas needs.

### What other tools ask for

Monitoring tools that read a database's health, rather than just signing in, ask for
more: on PostgreSQL 10 and later, membership of `pg_monitor`; on MySQL, `PROCESS`,
`REPLICATION CLIENT` and `SELECT` on `performance_schema`; on Redis, `+info` and a
few others; on MongoDB, the `clusterMonitor` role. MaxNines will ask for the same once its checks read more than whether
they can sign in.
