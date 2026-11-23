# MongoDB

MaxNines reads a MongoDB server's health, load and replication: its connections
against its limit, operations and how long they take, work waiting its turn,
WiredTiger's cache, and its replica set as this member sees it, down to how long the
oplog covers. MongoDB isn't SQL, so [templates](templates.md) can't read it, and
MaxNines reads it itself, with MongoDB's own driver.

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

Then pick it in a [config rule](agents.md#config-rules), under **Databases from the
agent's config**, one name to a line. Nothing of it is read until a rule asks for it,
and a name an agent doesn't have reports that it's missing. After a name, list `sizes`
to read each database's size on disk too, which costs more, as in `documents sizes`.

**On a host without an agent**, add a MongoDB check about the host on the **Checks**
page, with how it signs in, and tick **Read its health and replication**, with
`sizes` if wanted. See [hosts without an agent](database-stats.md#hosts-without-an-agent).

The host's metrics page lists each MongoDB database under **Latest databases**: whether
it answered, whether it's a primary, a secondary or standalone, its version, and
anything that couldn't be read, such as for want of a privilege.

## The account to sign in as

Give MaxNines an account of its own, which can read statistics and change nothing:

```javascript
use admin
db.createUser({
  user: "maxnines",
  pwd: passwordPrompt(),
  roles: [ { role: "clusterMonitor", db: "admin" }, { role: "read", db: "local" } ]
})
```

`clusterMonitor` reads the server's status and its replica set's, and `read` on `local`
the oplog's window. An account without `clusterMonitor` can only say the server answers
and its version.

## What's reported

Each metric has a series for each database block or check, named after it, such as
`documents`, and those about several things are named after both. Servers that aren't
in a replica set leave out what's about replication.

| Metric | Unit | Series | What it is |
| --- | --- | --- | --- |
| `mongodb.up` | 1 or 0 | Each database | Whether the server answered |
| `mongodb.uptime` | Seconds | Each database | How long the server has been running |
| `mongodb.connections` | Number | Each database | Client connections |
| `mongodb.connections_used` | % | Each database | Connections as a percentage of the most allowed |
| `mongodb.refused` | A second | Each database | Connections refused at the limit. Version 6.3 and later |
| `mongodb.oldest_query` | Seconds | Each database | How long the longest-running operation a client asked for has been running |
| `mongodb.replica` | 1 or 0 | Each database | Whether it's a secondary |
| `mongodb.receiving` | 1 or 0 | Each database | On a secondary, whether it's replicating from another member |
| `mongodb.lag` | Seconds | Each database | On a secondary, how far behind the primary it is |
| `mongodb.size` | Bytes | Each database, and each database in it | Each database's size on disk, with the `sizes` extra, such as `documents database sales` |
| `mongodb.operations` | A second | Each database and operation | Operations, for each kind, such as `documents operation insert` |
| `mongodb.read_latency` | Seconds | Each database | The average time a read took |
| `mongodb.write_latency` | Seconds | Each database | The average time a write took |
| `mongodb.queued_reads` | Number | Each database | Reads waiting their turn |
| `mongodb.queued_writes` | Number | Each database | Writes waiting their turn |
| `mongodb.read_tickets` | Number | Each database | Read tickets free. Few free means the storage engine is the bottleneck |
| `mongodb.write_tickets` | Number | Each database | Write tickets free |
| `mongodb.cache_used` | % | Each database | WiredTiger's cache in use |
| `mongodb.cache_dirty` | % | Each database | WiredTiger's cache changed and not written yet. Over 20% starts slowing writes |
| `mongodb.cursors_open` | Number | Each database | Cursors open |
| `mongodb.cursors_timed_out` | A second | Each database | Cursors that timed out |
| `mongodb.asserts` | A second | Each database | Assertions raised |
| `mongodb.memory` | Bytes | Each database | Memory in use |
| `mongodb.flow_control_lagged` | 1 or 0 | Each database | On a primary, whether it's slowing writes for lagging secondaries |
| `mongodb.members` | Number | Each database | Members of its replica set, as this member sees it |
| `mongodb.members_healthy` | Number | Each database | Members healthy |
| `mongodb.has_primary` | 1 or 0 | Each database | Whether the set has a primary |
| `mongodb.term` | Number | Each database | The election term, which rises with each election |
| `mongodb.majority_lag` | Seconds | Each database | On the primary, how far majority writes are behind |
| `mongodb.member_healthy` | 1 or 0 | Each database and member | Whether each member is healthy, as this one sees it, such as `documents member db2:27017` |
| `mongodb.member_lag` | Seconds | Each database and member | How far behind each member is, as this one sees it |
| `mongodb.oplog_window` | Seconds | Each database | How long the oplog covers, which is how long a secondary can be away and still catch up |

## Good things to alert on

MongoDB has no built-in alerts yet. These are worth adding as [alert
rules](alerts.md):

- `mongodb.up == 0`, the server not answering.
- `mongodb.connections_used > 80`.
- `mongodb.has_primary == 0`, or `mongodb.members_healthy` below the set's size.
- `mongodb.oplog_window < duration('1d')`.
