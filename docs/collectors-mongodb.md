# MongoDB

MaxNines reads a MongoDB server's health, load and replication: its connections
against its limit, operations and how long they take, work waiting its turn,
WiredTiger's cache, and its replica set as this member sees it, down to how long the
oplog covers. It's read by the built-in **MongoDB** [template](templates.md), with
MongoDB's own [commands](templates.md#mongodb-commands), the same way on an agent and
on the server.

It reads MongoDB 7.0 and later, as older versions are past their end of life and keep
some of what's read elsewhere.

## Turning it on

**On a host with an agent**, add a `database` block to the agent's own `agent.hcl`,
with where the server is and how to sign in, so the password never leaves the host:

```hcl
database "documents" {
  kind     = "mongodb"
  target   = "127.0.0.1:27017"
  username = "maxnines"
  password = env("DOCUMENTS_DB_PASSWORD")
}
```

`database` is the database the account was made in, by default `admin`. MongoDB can be
read without a username and password where it allows that. A database is read from the
one server given, so give each member of a replica set a block of its own. It takes
`host:port`, not a `mongodb+srv://` address. The
[settings](database-stats.md#the-database-block) are the same for every kind of
database. Restart the agent after changing them.

That's all: the MongoDB template reads every MongoDB `database` block on every host it's
for, which as it ships is every host, with no config rule needed. Choose which hosts on
the template's page, under **Settings > Templates**, or turn it off there.

**On a host without an agent**, such as a managed service, add a MongoDB check about the
host on the **Checks** page, with how it signs in, and tick **Read its health and
replication**. See [hosts without an agent](database-stats.md#hosts-without-an-agent).
On Atlas, use a member's host name, shown under the cluster's **Metrics**.

## The account to sign in as

Give MaxNines an account of its own, which can read statistics and change nothing:

```javascript
use admin
db.createUser({
  user: "maxnines",
  pwd: passwordPrompt(),
  roles: [ { role: "clusterMonitor", db: "admin" } ]
})
```

`clusterMonitor` runs every command the template does. MongoDB has no read-only
sessions, so what a command may do is up to the account: one that can do more than
read is [reported](database-stats.md#what-the-account-may-do), and warned about. Users
are kept by the replica set, so making it on the primary makes it on every member.

## What's read, and how often

The template finds out about the server first, with **`server`**, its version, every
hour, and **`role`**, every 10 seconds, so a failover changes what's read quickly:
whether it's in a replica set, and whether it's the primary or a secondary. Then every
sample it reads:

- **`server`**, `serverStatus`: its connections, operations' times, work waiting,
  tickets, WiredTiger's cache, cursors, assertions, memory and flow control;
- **`operations`**, `serverStatus`: each kind of operation;
- **`oldest_query`**, the `$currentOp` stage: the longest-running operation a client
  asked for;
- in a replica set, `replSetGetStatus`: the set, **`replica_set`**, and each member,
  **`members`**, on a secondary how far behind it is, **`replication`**, and on the
  primary how far majority writes are behind, **`majority`**;
- in a replica set, every minute, how long the oplog covers, **`oplog`**.

One query ships turned off, as it costs more with many databases. Turn it on with
**Enable** under **Queries** on the template's page:

- **`sizes`**, `listDatabases`: each database's size on disk, every 5 minutes.

What discovery found, and anything that went wrong, are on the template's page and the
host's **Templates** card.

## What's reported

Each metric has a series for each database block or check, labelled `instance`, such
as `documents`, and those about several things are labelled by them too, such as the
member `documents, db2:27017`. A server that isn't in a replica set leaves out what's
about replication.

| Metric | Unit | Series | What it is |
| --- | --- | --- | --- |
| `mongodb.up` | 1 or 0 | Each database | Whether the server answered |
| `mongodb.uptime` | Seconds | Each database | How long the server has been running |
| `mongodb.connections` | Number | Each database | Client connections |
| `mongodb.connections_available` | Number | Each database | How many more connections it takes before refusing them |
| `mongodb.connections_used` | % | Each database | Connections as a percentage of the most allowed |
| `mongodb.refused` | A second | Each database | Connections refused at the limit |
| `mongodb.reads` | A second | Each database | Reads |
| `mongodb.read_time` | A second | Each database | Microseconds spent on reads |
| `mongodb.read_latency` | Seconds | Each database | The average time a read took |
| `mongodb.writes` | A second | Each database | Writes |
| `mongodb.write_time` | A second | Each database | Microseconds spent on writes |
| `mongodb.write_latency` | Seconds | Each database | The average time a write took |
| `mongodb.queued_reads` | Number | Each database | Reads waiting their turn |
| `mongodb.queued_writes` | Number | Each database | Writes waiting their turn |
| `mongodb.read_tickets` | Number | Each database | Read tickets free. Few free means the storage engine is the bottleneck |
| `mongodb.write_tickets` | Number | Each database | Write tickets free |
| `mongodb.cache_size` | Bytes | Each database | WiredTiger's cache in use |
| `mongodb.cache_dirty_size` | Bytes | Each database | WiredTiger's cache changed and not written yet |
| `mongodb.cache_limit` | Bytes | Each database | WiredTiger's cache's size |
| `mongodb.cache_used` | % | Each database | WiredTiger's cache in use, of its size |
| `mongodb.cache_dirty` | % | Each database | WiredTiger's cache changed and not written yet, of its size. Over 20% starts slowing writes |
| `mongodb.cursors_open` | Number | Each database | Cursors open |
| `mongodb.cursors_timed_out` | A second | Each database | Cursors that timed out |
| `mongodb.asserts` | A second | Each database | Assertions raised |
| `mongodb.memory` | Bytes | Each database | Memory in use |
| `mongodb.flow_control_lagged` | 1 or 0 | Each database | On a primary, whether it's slowing writes for lagging secondaries |
| `mongodb.replica` | 1 or 0 | Each database | In a replica set, whether it's a secondary |
| `mongodb.operations` | A second | Each database and operation | Operations, for each kind, such as `documents, insert` |
| `mongodb.oldest_query` | Seconds | Each database | How long the longest-running operation a client asked for has been running |
| `mongodb.size` | Bytes | Each database and database in it | Each database's size on disk, with the `sizes` query turned on, such as `documents, sales` |
| `mongodb.members` | Number | Each database | Members of its replica set, as this member sees it |
| `mongodb.members_healthy` | Number | Each database | Members healthy |
| `mongodb.has_primary` | 1 or 0 | Each database | Whether the set has a primary |
| `mongodb.term` | Number | Each database | The election term, which rises with each election |
| `mongodb.member_healthy` | 1 or 0 | Each database and member | Whether each member is healthy, as this one sees it, such as `documents, db2:27017` |
| `mongodb.member_lag` | Seconds | Each database and member | How far behind the primary each secondary is, as this one sees it |
| `mongodb.lag` | Seconds | Each database | On a secondary, how far behind the primary it is |
| `mongodb.receiving` | 1 or 0 | Each database | On a secondary, whether it's copying from another member |
| `mongodb.majority_lag` | Seconds | Each database | On the primary, how far majority writes are behind |
| `mongodb.oplog_window` | Seconds | Each database | How long the oplog covers, which is how long a secondary can be away and still catch up |

With no primary, a secondary's lag isn't known, so `mongodb.lag` and `mongodb.member_lag`
leave it out.

## Built-in alerts

The template brings these, for each MongoDB database it reads. Change or turn off any
of them on the template's page.

| Alert | When | Level |
| --- | --- | --- |
| **MongoDB down** | It hasn't answered for a minute | Critical |
| **MongoDB connections running out** | Over 80% of its connections for 5 minutes, or over 90% | Warning, then critical |
| **MongoDB replica set has no primary** | No primary for a minute, as a member sees it | Critical |
| **MongoDB replica set member unhealthy** | A member unhealthy for 2 minutes, as another sees it | Warning |
| **MongoDB replica lagging** | A secondary over a minute behind for 2 minutes, or over 5 minutes | Warning, then critical |
| **MongoDB replication stopped** | A secondary copying from no member for 2 minutes | Critical |
| **MongoDB oplog window short** | The oplog covering less than a day for 10 minutes. Ships turned off, as a new replica set's covers only the time since it started | Warning |
