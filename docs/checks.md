# Checks

A check tries reaching something and says whether it answered, how long it took, and
whatever else it learned on the way. The server runs the ones on the **Checks** page,
each about a [host without an agent](agentless-hosts.md). An
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
| **Memcached** (`memcached`) | `host:port` | Its version, connections, memory used against its limit, hit rate and evictions |
| **MongoDB** (`mongodb`) | `host:port` | That it answers as MongoDB, or that an account can sign in, and its version |
| **ClickHouse** (`clickhouse`) | `host:port`, its HTTP port | That it answers its ping, or that an account can sign in, and its version |
| **SSH** (`ssh`) | `host:port` | Its host key and the ways it offers to sign in, or that an account can sign in |
| **Mail sending** (`smtp`) | `host:port` | That it greets as a mail server, or that an account can sign in to send |
| **Mailbox** (`imap`, `pop3`) | `host:port` | That it greets as one, or that an account can sign in |
| **FTP or FTPS** (`ftp`) | `host:port` | That it greets as FTP, and its certificate where it offers TLS, or that an account can sign in |
| **Heartbeat** (`heartbeat`) | None | That scheduled work, such as a cron job or a backup, pinged its address in time, or [said it failed](#heartbeats) |

An agent older than a kind of check doesn't know it. It runs the rest of its checks,
and reports that one as down, saying the agent needs upgrading.

## A host for each check

Every check the server runs is about a host without an agent, never the server
itself. Choose one on the check's form, or leave it on **New host** and a new host
is made for the check, as **Add a host** on the Hosts page makes one, and recorded
in the audit log the same way. Type the new host's name, or leave it empty and it's
named after what the check reaches, in lower case:

| Kind | Named after | Example target | Host's name |
|---|---|---|---|
| `http` | The host in the address, without the scheme, port, path or any username | `https://www.example.com/health` | `www.example.com` |
| `tcp`, `tls`, `postgres`, `mysql`, `redis`, `memcached`, `mongodb`, `clickhouse`, `ssh`, `smtp`, `imap`, `pop3`, `ftp` | What's before the port | `db1.internal:5432` | `db1.internal` |
| `dns` | The name it looks up | `example.com` | `example.com` |
| `heartbeat` | The check's own name | | `nightly backup` |
| `ping` | The host it pings | `192.0.2.7` | `192.0.2.7` |

An address stays an address, and an IPv6 one loses its brackets, so
`https://[2001:db8::1]:8443/` gives `2001:db8::1`. The form shows the name the host
would get as you type the target.

Hosts are never matched by name, as two can share one, so two checks added this way
are on two hosts even when they reach the same place. To add a check to a host that's
already there, choose it on the form, or press **Add check** on the host's page.
Deleting a check leaves its host and what the check found, and deleting the host
deletes its checks.

## What's timed

Each check says how long each stage took, in seconds, so a slow answer can be told
apart from slow DNS. Each stage is timed the same way whatever the kind, and one a
check doesn't go through is left out.

| Field | Chart | What it is |
|---|---|---|
| `dns_secs` | **DNS lookup time** | Looking up the target's name, or asking the DNS server, for a DNS check |
| `connect_secs` | **Connection time** | Opening the TCP connection, once the address is known, and nothing after it: no TLS, greeting or signing in |
| `tls_secs` | **TLS handshake time** | The TLS handshake, for a website, a certificate, and mail, FTP and the rest over TLS |
| `first_byte_secs` | **Time to first byte** | A website: from sending the request to the answer starting |
| `download_secs` | **Download time** | A website: reading the rest of the page |
| `response_secs` | **Check response time** | The whole check, when it worked, signing in included |
| `rtt_min_secs`, `rtt_max_secs`, `rtt_stddev_secs` | | A ping's fastest and slowest replies, and how much they varied |

A database or Redis check opens a connection to time it, then its driver connects
again to do its work, so signing in shows in `response_secs` and never in
`connect_secs`.

## Ping

A ping check reports a host as up if the host itself replied to any of its pings,
not when a router answers that it can't be reached. Pings that went unanswered
show in its packet loss. On Windows MaxNines sends the pings itself.
On Linux, macOS and FreeBSD it runs the system's own `ping`, which every account can
use there, and pings the name's IPv4 address if it has one.

## Memcached

A Memcached check asks for Memcached's `stats` in its plain-text protocol, and reports:

| Field | Chart | What it is |
|---|---|---|
| `server_version` | | Memcached's version |
| `connections` | **Open connections** | Connections it has open, the check's own included |
| `memory_used_bytes`, `memory_limit_bytes` | **Cache memory used**, **Cache memory used of its limit** | What its keys take, and what they're allowed (`-m`) |
| `hit_rate_percent` | **Cache hit rate** | Of the reads since it started, the share it had the key for |
| `evictions` | **Cache evictions** | Keys dropped to make room since it started, which grows when it's too small |

A check keeps nothing between runs, so the hit rate and evictions are since Memcached
last started, not since the last run. A sudden drop in the hit rate shows best on a
Memcached that's been up a while.

It never signs in: Memcached only does that with SASL over its binary protocol, which
the check doesn't speak, so a Memcached that needs it doesn't answer `stats` and
counts as down. Tick **Use TLS from the start** for a Memcached started with TLS
(`-Z`), and its certificate is read as a website's is.

## FTP and FTPS

An FTP check reads the server's greeting, then asks to upgrade to TLS with `AUTH TLS`,
which is explicit FTPS. Where the server agrees, the check upgrades and reads its
certificate as a website check does, with its days left on **Certificate days left**,
and a certificate that fails counts as down unless **Don't count a bad certificate as
down** is ticked. `tls_offered` says whether it agreed. For implicit FTPS, usually on
port 990, tick **Use TLS from the start**.

Given a username and password, it signs in after upgrading and then leaves. Like a
mail check, it never sends a password without TLS, so signing in to a server that
doesn't offer it counts as down without the password being sent. To check a plain
FTP server, don't sign in. No data connection is ever opened, so nothing is listed,
fetched or sent.

## Heartbeats

A heartbeat check watches work that runs on a schedule, which no outward check can
see: a cron job, a backup, a batch run. Instead of the server reaching it, the work
calls the heartbeat's own address when it finishes, and the check is down if it
hasn't by the time it should have. Only the server watches heartbeats, so they're
added on the **Checks** page or through the [API](api-remote-checks.md), never in a
config rule.

- **Run every** is how often the work runs, from a minute to 31 days, and **Grace
  time** how much later than that a ping can come, for work that starts late or
  takes a while. A heartbeat pinged every day at 02:00 with an hour's grace is down
  from 03:00 the next day if it hasn't been pinged again. The period is a length of
  time, not a cron schedule, so work that only runs on weekdays needs a grace time
  that covers the weekend.
- A new heartbeat, or one changed or resumed, is given its first period and grace
  from then. So is one that has never been pinged when the server starts; one that
  has keeps counting from its last ping, so a restart never hides a run that's late.
- It's down from the moment its work says it failed, until a run works.

Its address is on the check's page, shown only to editors and admins, and is the
server's own address, on its one port, followed by `/ping/` and a random token:

```text
https://monitor.example.com/ping/0f3c9a6e5b1d4c7a8e2f6b9d1a3c5e7f
```

| Address | What it says |
|---|---|
| `…/ping/<token>` | A run finished and worked |
| `…/ping/<token>/start` | A run started, so the next ping times it, as **Last run took** and on **Check response time** |
| `…/ping/<token>/fail` | A run failed, so the check is down now rather than when the next one is due |

Each takes `GET`, `HEAD` or `POST`, needs no sign in, and answers `200` with `OK`.
What's sent with it is never read. An address that isn't a heartbeat's answers
`404`, and pings to one heartbeat closer together than a second, or many wrong
addresses from one place, are turned away with `429`. Pings to a paused heartbeat
are kept, but say nothing until it's resumed.

Anyone with the address can say the work ran, which could hide a failure, so keep
it as you would a password. **New address** on the check's page, or
[`POST /api/v1/remote-checks/{id}/ping-address`](api-remote-checks.md#give-a-heartbeat-a-new-address),
gives it a new one and stops the old one working at once. Who did that is in the
audit log; the address never is.

### From cron

Ping when the work worked, and say it failed when it didn't:

```sh
0 2 * * * /usr/local/bin/backup.sh && curl -fsS -m 10 --retry 3 https://monitor.example.com/ping/0f3c… > /dev/null || curl -fsS -m 10 --retry 3 https://monitor.example.com/ping/0f3c…/fail > /dev/null
```

To time each run too, ping `/start` first:

```sh
#!/bin/sh
url=https://monitor.example.com/ping/0f3c…
curl -fsS -m 10 --retry 3 "$url/start" > /dev/null
if /usr/local/bin/backup.sh; then
  curl -fsS -m 10 --retry 3 "$url" > /dev/null
else
  curl -fsS -m 10 --retry 3 "$url/fail" > /dev/null
fi
```

### From a Windows scheduled task

Windows 10, 11 and Server 2019 and later come with `curl.exe`. In the task's action,
run a PowerShell script such as:

```powershell
$url = "https://monitor.example.com/ping/0f3c…"
& C:\Scripts\backup.ps1
if ($?) { curl.exe -fsS -m 10 --retry 3 $url } else { curl.exe -fsS -m 10 --retry 3 "$url/fail" }
```

Or ping with PowerShell alone: `Invoke-WebRequest -UseBasicParsing -TimeoutSec 10 $url`.

## Domain expiry

A website check also finds out when the site's domain registration runs out, from the
domain's registry over RDAP, the successor to WHOIS, and reports it as **Domain days
left**. IANA's list says which registry answers for each top-level domain, and the
check asks about the site's host name and then each name above it until the registry
recognises one, so `www.example.co.uk` finds `example.co.uk`.

- Each domain is asked about at most twice a day, and IANA's list once a day, however
  often the check runs, as registries limit how often they're asked.
- It happens after the check's own timing, within the check's time limit, and never
  makes the check fail. If the registry can't be reached, doesn't say, or doesn't
  answer in time, the check's result says why, and a lookup that ran out of time
  carries on so that the next run has its answer.
- A domain's answer serves every name under it, so `www.example.com` and
  `api.example.com` share one lookup. A registry that couldn't be asked is asked
  again after an hour.
- Addresses and names without a public registry, such as `printer.local`, are skipped,
  and so are domains whose registry doesn't offer RDAP, such as `.io`.
- Untick **Look up when the domain expires** on the check to turn it off.

To be warned in good time, add an alert rule on **Domain days left** below 30.

## Signing in

A database, Redis, SSH, mail or FTP check that isn't given a way to sign in checks only
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

Each can also have `insecure = true`. A database is a [`database` block](database-stats.md#the-database-block)
instead, which reads its stats as well as whether it answers. The agent tells the server the names of the
checks its config allows, never more, and a [config rule](api-config-rules.md) picks
which of them to run and how often, under **Checks from the agent's config**. A name
the agent doesn't have reports that it's missing. Checks with nothing to sign in
with, such as a website's, are given whole in the config rule instead, and a `check`
block of a kind that never signs in is refused.

A key file is read when the agent starts, so it has to be readable by the user the
agent runs as. Restart the agent after changing any of these.

### Certificates

A PostgreSQL check uses TLS whenever the server offers it, and with **Use TLS**
ticked, only over TLS, so one that stops offering it, or someone in the middle
answering for it, is never sent the password. MySQL, MariaDB, Redis and MongoDB
checks use TLS when **Use TLS** is ticked. The certificate is checked as a website's
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
