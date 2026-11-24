# Templates

A template says what MaxNines watches for in something it monitors, such as a host,
PostgreSQL or IIS: what to read, the metrics that makes, and the alerts on them. Each
of its alerts is an [alert rule](alerts.md), which you can change, turn off and put
back as it was.

Templates are under **Settings > Templates**. The ones that come with MaxNines are
written as the server starts, and an upgrade can bring new versions of them. A built-in
template can't be edited or deleted. Changing one of its alerts, discover blocks,
queries or counters blocks makes a copy of your own, used in place of the built-in
one, which upgrades never touch. A built-in template, alert, query or counters block
can be disabled, which stays that way through upgrades. Admins see a notice on every
page when an upgrade has changed a template, saying which of its parts you have your
own copies of, until one of them dismisses it.

You can also **import** a template someone else wrote, from **Import** on the Templates
page: choose an `.hcl` file or paste it, and the page shows what it is before anything is
saved: its alerts and metrics, every SQL statement and performance counter it would
run, anything wrong with it, and for one imported before, what would change. An
imported template behaves as a built-in one does: it isn't edited, changing one of its
alerts makes your own copy, and it and its alerts can be disabled. Importing a newer
version of the same key replaces it, leaving your copies and what's turned off alone,
with the same notice to admins. Unlike a built-in one, it can be deleted. An import
with the key or name of a built-in template, or the key of one of your own, is refused.

Any template can be **exported** as HCL, from **Export** on its page.

You can add templates of your own, for things MaxNines doesn't know, with the form on
the Templates page, as HCL on its **HCL** tab, or through the
[API](api-templates.md). MaxNines keeps a template as its parts, not as text: HCL is how
one comes in and goes out, so comments and layout in HCL you save aren't kept, and what's
shown afterwards is written out from the parts.

## What comes with MaxNines

| Template | What it watches |
| --- | --- |
| **Host** | Every host, with an agent or only checks: whether it's online and sending metrics, its disks, clock, services and containers, and whether templates read its databases with accounts that can do more than read. It has the nine [built-in alert rules](alerts.md#the-built-in-rules), and the [agent settings](#agent-settings) every host gets |
| **macOS** | Macs: the agent settings they get beyond every host's, which read the GPU |
| **ClickHouse** | Each ClickHouse database: its load against its limits, inserts and parts, memory, merges and background pools, mutations, error codes worth knowing about, disks, replication, Keeper and Distributed tables, with 8 alerts. Its database sizes and query times ship turned off, as they cost more. What it reads is listed on the [ClickHouse](collectors-clickhouse.md) page |
| **MongoDB** | Each MongoDB database: its connections, operations and how long they take, work waiting, WiredTiger's cache, and its replica set as each member sees it, read with MongoDB's own commands, with 7 alerts, one of them off until its oplog has filled. Its database sizes ship turned off. What it reads is listed on the [MongoDB](collectors-mongodb.md) page |
| **MySQL** | Each MySQL or MariaDB database: its load, InnoDB, transactions and queries, replication into it, read through `SHOW`, semi-synchronous replication, Group Replication and Galera, with 7 alerts. MySQL's and MariaDB's differences are queries of their own, picked by what discovery finds. Its database and binary log sizes ship turned off. What it reads is listed on the [MySQL and MariaDB](collectors-mysql.md) page |
| **PostgreSQL** | Each PostgreSQL database: its health, load, replication from both ends, replication slots, archiving and subscriptions, with 14 alerts, one of them off until you say how many standbys a primary should have. Its sizes ship turned off, as they're slow on big servers. What it reads is listed on the [PostgreSQL](collectors-postgresql.md) page |

## What templates can read so far

- **Databases:** PostgreSQL, MySQL and MariaDB, and ClickHouse, with SQL, and MongoDB
  with [commands](#mongodb-commands). ClickHouse is read over its HTTP interface, where
  every statement is a GET, which it only lets read, and its account's own profile
  sets its time limit.
- **Windows:** performance counters and registry values, on hosts with an agent.
- **Every database** MaxNines reads, PostgreSQL, MySQL and MariaDB, MongoDB and
  ClickHouse, is read by its built-in template.

Where a template is read, and how, is the same on an agent and on the server for a
[host without an agent](#hosts-without-an-agent-and-maxnines-own-database).

## The format

A template is HCL, with [CEL](https://cel.dev) for anything worked out, such as a
condition. It's one `template` block, named by its key:

```hcl
template "myapp" {
  name        = "My app"
  description = "Connections and queues."
  database    = "postgres"

  query "sessions" {
    sql = <<-SQL
      SELECT count(*) AS connections FROM pg_stat_activity
    SQL
  }

  alert "busy" {
    name     = "My app busy"
    warning  = "connections > 100"
    critical = "connections > 200"
    for      = "5m"
    summary  = "{{ hostname }}: {{ connections }} connections"
  }
}
```

The **key**, `myapp`, starts the names of the template's metrics, so the column
`connections` is the metric `myapp.connections`. It's lowercase letters, digits and
underscores, starting with a letter, and no two templates share one. So are the keys of
the blocks inside it, such as `sessions` and `busy`. A template whose metric would
have the name of one MaxNines has built in, such as `cpu.usage`, is refused:
give it another key.

An agent is sent what it reads all at once, so a template can have up to 64 discover
blocks and queries together, each SQL statement up to 64 KB with what fills it, each
query up to 256 labels and metrics, and each `interval` up to a day. A host is sent
up to 64 templates to run, counting each database one runs for, and any more aren't
sent, which the server logs.

Lengths of time are written like `"30s"`, `"5m"`, `"1h"` or `"1h 30m"`, in whole
seconds. Versions are numbers with dots, compared as numbers, so 9.6 < 13 < 16.2, and
13 is the same as 13.0.

### What it runs for

One field says what a template is for, and it runs once for each match on a host:

| Field | Runs |
| --- | --- |
| `database = "postgres"` | Once for each database of this kind in the agent's config, or on a host without an agent, each database check of this kind that reads its stats |
| `service = "W3SVC"` | Once on each Windows host with this service |
| `os = ["linux", "freebsd"]` | Once on each host running one of these: `freebsd`, `linux`, `macos` and `windows`. Its alerts only apply to those hosts |
| none | Once on every host, agentless ones too |

Only a template for a database has SQL, its `query` blocks and the `sql` of its
discover blocks, as there's nothing else to run SQL on. A template for MongoDB has
a `command` in their place. The others read Windows
performance counters and the registry, so they run only on Windows hosts with an
agent, and a template for `os` has to list `windows` to read them. A database's
template can't read them, as they're the host's: read them in a template for the
service, such as `service = "MSSQLSERVER"`.

`min_version` is the oldest version it's for. `services` lists services that the
host's own **Service stopped** alert should watch.

Databases are found from the `agent.databases` fact, which names each database in the
agent's config with its kind, such as `{"orders": "postgres"}`, and services from the
`services` fact, the services Windows has installed. On a [host without an
agent](agentless-hosts.md), a database check that reads its stats is a database,
named after the check, and of the check's kind.

### Which hosts it's for

`applies_to` is CEL over a host's facts, as a [config rule's](agents.md) is, saying
which hosts a template is for: `applies_to = "facts.custom.role == 'db'"`. Without
it, a template is for every host. On a template's page, under **Hosts**, you can change
that, and give it hosts by hand: it's then for those as well as the ones `applies_to`
picks, or with no condition, for only those. For a built-in or imported template
that's your choice, which newer versions leave alone. A template's alerts are only
checked on the hosts it's for, and what it runs for is only looked for on them.

### Discovery

`discover` blocks run first, each then every `interval`, an hour unless it says, and
again when what's monitored restarts. What they find is what `when` and `since` look
at, together, so no two can find the same name. A template can have several, so what
changes quickly can be looked at often and what hardly changes rarely:

- `sql`: each column of the first row, by its name. A column called `version` is
  read as a version, from the first number in it, so `16.4 (Debian 16.4-1)` is 16.4;
- `command` and `columns`, for MongoDB: each field `columns` names in the reply, by
  its name, as a [query's](#mongodb-commands) are read;
- `registry "<key>" { name = "Value" }`: Windows registry values, each by its name.
  Only keys under `HKLM` (`HKEY_LOCAL_MACHINE`) are read, as the agent runs as a
  service with no user's settings. Text is read as text and numbers as numbers, and
  a list of pieces of text as one, joined with commas. A value that isn't there isn't
  found;
- `counter_sets = { name = "Counter set" }`: whether the host has each performance
  counter set, true or false.

```hcl
discover "server" {
  sql = "SELECT current_setting('server_version') AS version"
}

discover "role" {
  interval = "10s" # so a failover switches queries quickly
  sql      = "SELECT pg_is_in_recovery() AS replica"
}
```

The server works out what each agent reads: for each database a template runs for,
its discover blocks, and the queries whose `since` and `when` hold of what discovery
last found there, their SQL filled in for that version. A query with a `when`,
`since` or `fill`, or in a template with a `min_version`, waits until discovery has
found something, and below `min_version` only discovery runs. When what discovery
finds changes, the agent is sent what to read again. The agent itself only runs the
SQL it's sent. A template that isn't for a database is sent once to each Windows host it's for
that runs what it's for, if it reads anything there: what its discover blocks look
for, and its counters blocks picked by `when` and `since` as queries are, each with
only its metrics for the version found. What it finds is kept for the host, and its
alerts with `when` or `since` are checked on the hosts where what was found fits.

### Queries

`query` blocks are SQL whose columns become metrics:

- each column becomes a metric named `<key>.<column>`. True and false columns become
  yes or no, and intervals become lengths of time;
- every column needs a name: give anything that isn't a column of its own one with
  `AS`;
- `labels = ["slot"]` names the text columns that tell rows apart, one series per row.
  No label can be called `instance`, in any template, as that's the database a series
  is from;
- a NULL gives no sample, rather than zero;
- a column whose name starts with `_`, which only a SHOW statement's or MongoDB's
  `columns` can name, is only there to work other metrics out with `value`, and isn't
  kept. `metrics` can say one is a running total, `_reads = { total = true }`, so
  `rate(_reads)` works.

`metrics = { … }` only says what can't be worked out from the column: `total = true`
for a running total, which is kept as a rate; a `unit`, which is `%`, `s`, `bytes`,
`bytes/s`, `/s` or `°C`; a `title`, up to 100 characters, which charts and lists call it,
such as `PostgreSQL replication lag`, rather than the template's name and the metric's
key in words; a `description`; or `value`, CEL working a metric out from the others as
each sample arrives. Whether a database template's database answers, `<key>.up`, is
titled with the template's name, such as `PostgreSQL up`.

```hcl
query "throughput" {
  sql = "SELECT sum(xact_commit) AS commits, sum(blks_hit) AS hits, sum(blks_read) AS reads FROM pg_stat_database"
  metrics = {
    commits   = { total = true }
    cache_hit = { value = "rate(hits) / (rate(hits) + rate(reads)) * 100", unit = "%" }
  }
}
```

A `value` is worked out by the server as each sample arrives, for each row of its
query, from that row's numbers by their columns' names, with the host's facts under
`facts` on a host with an agent. `rate(x)` is a running total's
change each second since the query last sent that row's series, so a series' first
row has no rate, and nor does a sample the agent kept while away and sent after newer
ones. Nothing is worked out from a column the row doesn't have. A metric with
`since = "15"` is only read, or worked out, where the version discovery found is 15
or later, and its query waits for discovery.

**By version.** `since = "14"` runs a query only from version 14 on. `fill` picks a
piece of SQL by version, so a query is written once: `{{ name }}` in the SQL is filled
from the version given that's the highest at or below the one found, or from `older`
below them all.

```hcl
query "checkpoints" {
  sql = "SELECT {{ checkpoints }}"
  fill "checkpoints" {
    versions = { "17" = "num_timed AS timed FROM pg_stat_checkpointer" }
    older    = "checkpoints_timed AS timed FROM pg_stat_bgwriter"
  }
}
```

**By what discovery found.** `when` is CEL over what discovery found, such as
`role == 'primary'`, and the query only runs while it's true.

`interval` runs a query less often than the agent samples, and `enabled = false`
ships it turned off.

**How SQL runs.** Each discover block has to be one `SELECT`, and each query one
`SELECT` or [`SHOW`](#show-statements), which saving checks. It
runs on its own, as a prepared statement, in a read-only transaction, and the database
stops it after 5 seconds. On PostgreSQL a statement that worked commits its
transaction, as nothing in it could write, so PostgreSQL's own count of rollbacks
isn't one for each statement a template runs; MySQL's is rolled back. On MySQL and
MariaDB the whole session is read-only too, as MySQL ends a transaction before
anything that changes a table. ClickHouse is asked over HTTP, where every statement is
a GET, which it only lets read, and it's sent a 5 second limit too, unless its account
is set to `readonly = 1`, which can't be sent settings, so its [profile's
limit](collectors-clickhouse.md#the-account-to-sign-in-as) stands instead. A template
can still run any `SELECT` its account is allowed to, so give MaxNines a [read-only
account](#read-only-database-accounts).

#### SHOW statements

A query is one statement: a `SELECT`, or a `SHOW`, any the database takes, as some of
what a database knows is only said by `SHOW`, such as how far behind a MySQL replica
is. There's no list of which: what a template can read is up to the account it signs in
as, which is why MaxNines warns when that account [can do more than
read](database-stats.md#what-the-account-may-do). Saving or importing a template checks
it's one statement, and the agent or server checks again that it's a `SELECT` or `SHOW`
before it runs one. Each runs as any query does, in a read-only transaction on a
read-only session, with a time limit, or on ClickHouse as a GET. MySQL and MariaDB
don't take every `SHOW` as a prepared statement, so theirs are sent as plain text,
which would run a second statement after a `;`, so one with a `;` anywhere but at its
end isn't run.

What a `SHOW` statement gives isn't known until it runs, so `columns` names each column
it reads, as a metric or a label, and no other column is read:

```hcl
query "replication" {
  sql = "SHOW REPLICA STATUS"
  columns = {
    channel   = "Channel_Name"
    receiving = "Replica_IO_Running"
    behind    = "Seconds_Behind_Source"
  }
  labels = ["channel"]
}
```

A column's `Yes` or `No`, `ON` or `OFF`, is read as yes or no, with `Connecting` as no,
and a number written as text as a number. Rows with the same labels add up, so
`SHOW BINARY LOGS` with no labels gives the size of every binary log together.

#### MongoDB commands

MongoDB isn't SQL, so a template for it, `database = "mongodb"`, asks it with one
[database command](https://www.mongodb.com/docs/manual/reference/command/) for each
discover block and query, written as JSON, as MongoDB's own documents write one, in
`command` rather than `sql`. It runs on the `admin` database unless its `$db` says
another, and MongoDB stops it after 5 seconds unless it gives a `maxTimeMS` of its
own. Saving and the agent check it's one command, named by its first field. MongoDB
has no read-only sessions, so what a command may do is up to the account it signs in
as: give MaxNines a [read-only account](#read-only-database-accounts), such as one with
only the `clusterMonitor` role.

A reply isn't columns, so `columns` names each field read, as a metric or a label, and
where it is: a field's name, or names down through documents, as `connections.current`.
In a path:

- a list is read as how many it holds, so `members` is how many members there are;
- `[field=value]` after a list's name keeps only the documents in it whose `field` is
  `value`, so `members[health=1]` is how many are healthy;
- going on past a list reads the first document it kept, so
  `members[state=1].optimeDate` is the primary's;
- dates and MongoDB's timestamps are read as seconds since 1970, to work lengths of time
  out from with `value`.

A reply is one row, or with a cursor, as `aggregate` and `find` give, a row for each
document of its first batch. `rows` says where else its rows are: a list, each of whose
items is a row, or a document, each of whose fields is a row of its name, `k`, and its
value, `v`, as MongoDB's `$objectToArray` has them. In a query with rows, a path is in
each row, and one starting `$.` is in the whole reply:

```hcl
query "members" {
  command = <<-JSON
    { "replSetGetStatus": 1 }
  JSON
  rows   = "members"
  labels = ["member"]
  columns = {
    member  = "name"
    _health = "health"
    _state  = "state"
    _optime = "optimeDate"
    _leader = "$.members[state=1].optimeDate"
  }
  metrics = {
    member_healthy = { value = "_health == 1" }
    member_lag     = { value = "_state == 2 ? _leader - _optime : null", unit = "s" }
  }
}
```

A field that isn't there gives no sample. A `value` that comes to `null` gives none
either.

### Performance counters

`counters` blocks read a Windows performance counter set. Each entry under `metrics`
is a metric, named `<key>.<entry>`, reading the counter by its name:

```hcl
counters "sites" {
  object = "Web Service"
  label  = "site"
  metrics = {
    requests    = "Total Method Requests/sec"
    site_uptime = { counter = "Service Uptime", unit = "s" }
  }
}
```

- Units come from Windows' own names: `/sec` counters are per second already, names
  starting `Bytes` are bytes and names starting `%` are percentages. Give a `unit`
  only when the name doesn't say;
- `total = true` marks a running total, kept as a rate;
- `value` works the metric out from the counter's `value`, such as `value == 3` for a
  yes or no, or `value / 1000`;
- `states = { "3" = "Running" }` gives a word for each number;
- `label = "site"` gives each instance its own series, labelled `site`. `_Total` is
  always left out, and no label can be called `instance`;
- `pattern` does the same with a regular expression whose named groups become labels,
  leaving out instances it doesn't match. `instance` reads one instance only, and
  `exclude` lists instances to leave out;
- `join` matches these instances to another counter set's by a group named in both
  patterns, which the other groups then label. `groups = { pid = "ID Process" }` reads a
  group's value from a counter rather than the instance's name;
- series that end up with the same labels add up; percentages take the highest.

With none of `label`, `pattern` or `instance`, the counter set is read as one with no
instances, such as `Memory`. A `join` matches each instance to the other counter set's
instances its pattern matches, and an instance with no match, or no value for a
`groups` counter, is left out; with `groups` and no `pattern`, every instance is read.
Up to 256 series are read from a counters block.

A `value` is worked out by the server as each sample arrives, from the counter's own
reading, `value`, and the host's facts, so `value / facts.cpu.logical_cores` is a
share of the whole host. What it works out takes the reading's place.

`when`, `since` and `interval` work as a query's do, and a metric's `since` leaves it
out below that version. Counters are read through Windows' English names, so a
template works whatever language Windows is in. Counter sets a `join` reads and that
`counter_sets` looks for are given by their English names too, such as `Process`, and
found by the name Windows has for them in its own language; an application's own
counter sets that Windows has no English name for, such as IIS's `W3SVC_W3WP`, have one
name in every language. To see which counters a host has, run
`typeperf -qx "<Counter set>"` there.

### Alerts

Each `alert` block becomes an alert rule:

| Field | What it is |
| --- | --- |
| `name` | The rule's name, which no other rule can have |
| `warning`, `critical` | [Conditions](alerts.md#conditions) in CEL, either of which can be left out |
| `for` | How long it has to last before it fires |
| `window` | For `forecast()`, how much of the past its line is drawn through |
| `summary`, `resolved_summary` | What it says as it fires and as it clears |
| `when`, `since` | Only on what discovery found, or from a version on |
| `enabled` | `false` ships it turned off |

Inside a template, a metric's short name is the template's own metric: `lag` is
`postgres.lag`. Its full name works too, other metrics are used by their full names,
such as `cpu.load`, and facts are under `facts.`. A metric with labels used as it is
gives one alert per series, and the template's metrics with the same labels pair up.
`slot_retained['main']` picks one series.

Summaries can show `{{ hostname }}`, `{{ series }}`, `{{ instance }}`, what the
template runs for, such as a database's name, `{{ labels.slot }}` and any of the
template's metrics by either name, written in their units.

Every condition and summary is checked as the template is saved, as an alert rule's
is: names against the metrics there are and the template's own, and a try on sample
values. A column whose type only the database knows is tried as a number, a length of
time and a yes or no, and the condition has to work for one of them.

A template's metrics are like any others once agents send them: they're charted on a
host's metrics page, listed by the [API](api-metrics.md), and can be used in
dashboards and any alert rule by their full names. Each series is named by its
labels' values, such as `main, slot_a`, what a database template runs for coming
first. An alert on them with nothing sent yet doesn't fire, as missing data never
does.

An alert with `when` or `since` is only for the databases where what discovery last
found fits them, such as only replicas for `role == 'replica'`: it isn't checked on a
host until discovery has found something there, and only the series of those databases
are. Agents send what discovery finds with their samples, and the server keeps the
newest for each database a template runs for on each host. It's forgotten once the
agent isn't sent that template for that database any more, as when the database
leaves the agent's config or the template is turned off or no longer for the host,
and found again when it is.

### Agent settings

A template that comes with MaxNines can have a `config` block: the agent settings the
hosts it's for get, the same settings a [config rule](agents.md) sets.

```hcl
template "macos" {
  name = "macOS"
  os   = ["macos"]
  config {
    collectors = {
      gpu = { enabled = true }
    }
  }
}
```

Each becomes a built-in config rule of its own, named after the template, for the hosts
the template is for, at priority 0, where it's listed as coming with MaxNines. Your own
rules apply over it as over any rule: one at a higher priority wins, so a rule of your
own changes what a template's settings say without touching the template, and upgrades
leave it alone. The rule is for the same hosts as its template, as you choose them on
the template's page: the hosts you pick and those its condition matches, or every host
the template says when you've chosen none, so a host taken off the template loses its
settings too. The rule is only in force while its template is enabled, and can be
turned off on its own too, which lasts through upgrades. As the settings are that rule,
the template's HCL, as its page shows it and as it's exported, leaves the `config`
block out, so it can be copied into a template of your own, and its page links to the
rule instead.

Templates you import or write can't have a `config` block, and one that does is refused:
give agents' settings in a config rule, which says plainly what it changes on which
hosts.

### Notices

`notice` blocks are shown while their `when` holds:

```hcl
notice "cannot_see_sessions" {
  when = "!sees_all_sessions"
  text = "The account can't see other sessions. Grant it pg_monitor."
}
```

## Hosts without an agent, and MaxNines' own database

On a [host without an agent](agentless-hosts.md), the server reads its databases
itself, through its database checks that have **Read its health and replication**
ticked: each is a database, named after the check and of its kind, and the templates
for that kind that are for the host run for it. What's read is worked out as an
agent's would be, read the same way, with the same schedules, retries and limits,
and saved as a sample from the host each time the check runs, so it's read no more
often than the check runs, every 10 seconds at most. A check without that ticked
runs no template SQL. What's read is worked out again when templates, checks or what
discovery found change, and at least once a minute. Changing a check starts its
reading again, running totals too. Templates for Windows aren't read on these hosts,
and a `value` there has no facts to work from.

The server also reads its own database, when it's PostgreSQL or MySQL, but only with
the templates for that kind that come with MaxNines, exactly as this version of the
server was built with them: never an imported template, one of your own, or your copy
of a part of one, so nothing but SQL that shipped runs over the server's own
connection, and whether it runs is whether the template ships on, whatever's chosen
on its page. Each statement is read-only, as every template's is, and its series are
on the **MaxNines server** host, named `maxnines`. Your changes to those templates'
alerts still apply there. As the server's account has to be able to write, what it
may do beyond reading isn't reported. To read MaxNines' own database with other
templates, add a database check for it with a [read-only
account](#read-only-database-accounts). So the built-in PostgreSQL or MySQL template
reads it, whichever it is.

## Read-only database accounts

MaxNines only ever reads, but a template's SQL runs as whatever account the agent or
the database check signs in as, so what that account may do is what a template could
do. Give it an account of its own that can read what monitoring needs and change
nothing: each database's page gives one, for [PostgreSQL](collectors-postgresql.md#the-account-to-sign-in-as),
[MySQL and MariaDB](collectors-mysql.md#the-account-to-sign-in-as),
[MongoDB](collectors-mongodb.md#the-account-to-sign-in-as) and
[ClickHouse](collectors-clickhouse.md#the-account-to-sign-in-as). Whenever it connects,
and every 5 minutes, MaxNines reads [what the account may
do](database-stats.md#what-the-account-may-do) beyond reading, and the built-in
**Database account can do more than read** alert warns about any that may do more. The
account is still used, as what it may do is up to you.

**Your own tables.** A template that reads your application's tables needs `SELECT`
on them and nothing more, such as `GRANT SELECT ON shop.orders TO maxnines`.

## Examples

The templates that come with MaxNines are examples to read and copy from: open one
under **Settings > Templates** and choose **Export** for its HCL. The built-in
**PostgreSQL** template is all SQL:

- `database = "postgres"`, so it's for each PostgreSQL database in an agent's config;
- `discover` finds the version, whether the server is a primary or a replica, and
  whether it archives WAL, which the queries' `when` and `since` then pick by;
- a query each for sessions, throughput, checkpoints, WAL, replication from both
  ends, replication slots, archiving and subscriptions. `fill` covers the views that
  moved between versions, such as checkpoints in 17, so each query is written once;
- `labels` give a series to each standby, slot and subscription;
- `value` works the cache hit rate out from two running totals with `rate()`;
- the database and WAL sizes ship with `enabled = false`;
- its alerts use the short names, such as `lag > duration('30s')` and `!receiving`,
  and `when` keeps the replica's alerts to replicas.

To import it as a template of your own, give it another key and name, as a built-in
template's are its own.

One more example, which doesn't come with MaxNines, is here to read and import:

**[iis.hcl](examples/iis.hcl)**, for IIS, is Windows performance counters and one
registry read, with nothing about IIS anywhere else:

- `service = "W3SVC"`, so it's for each Windows host with IIS's web service;
- `discover` reads the version from the registry and notes which counter sets the
  host has, so ASP.NET's counters are only read where ASP.NET is;
- `label` gives each site and each application pool its own series, and `pattern`
  takes the pool's name out of a worker process's, leaving out the process ID that
  changes on every recycle;
- `join` matches a pool's memory and CPU, which Windows only counts per process, to
  the pool by process ID;
- `value = "value == 3"` makes a yes or no of a pool's state for alerting, and
  `states` gives each state its word.

## Changing a template's alerts

Open the alert from the template's page, or from **Settings > Alert rules**, where it
says which template it's from, and change it with the usual form.

For a **built-in** or imported template, saving a change makes a copy of your own. From
then on your copy is the rule that's checked, and the template's own isn't. A problem
that's already alerting carries on as the same alert, now your copy's, with nobody told
again, and its silences and maintenance windows come with it. If your copy's
conditions no longer hold, it resolves as any alert does. The template's page and the copy's form show what
the built-in one says beside yours, and when an upgrade last changed it, so you can
compare. **Reset to template** deletes your copy and the template's own rule is checked again,
taking over open alerts, silences and maintenance windows the same way.

Turning one of these alerts on or off, and nothing else, makes no copy: it's kept as
your choice. Until you choose, an alert is on or off as the template comes, so a newer
version can turn it on or off; once you've chosen, a newer version leaves it. **Reset
to template** forgets the choice too. The template itself works the same way, with
**Follow the template** to forget your choice. The page says which it is.

For a template of **your own**, there are no copies: changing an alert with its form
changes the template itself, as editing the template does.

A template's alerts can be turned off but not deleted.

## Changing a template's discover blocks, queries and counters

The template's page lists its discover blocks, queries and performance counters as
they run. **Change** opens one on its own, with the same fields as the template's form;
its key stays as it is. It's checked in the template, so a column one of its alerts
uses can't go, and the form says which alert.

For a **built-in** or imported template, saving makes a copy of your own, used in place
of the template's own from then on, as a changed alert is. Upgrades and newer imports
leave your copy alone; when one changes the part you copied, the page and the notice
say so, and you can compare it with what the template now says under **As the
template comes**. If a newer version drops the part, your copy goes with it, and the
notice says that too. Saving what the template says deletes your copy, as **Reset to
template** does.

**Disable** turns a query or counters block off without a copy, as your choice, which
newer versions leave alone; **Reset to template** forgets it. A discover block can be
changed but not turned off, as what it finds is what the rest waits on.

For a template of **your own**, changing a part changes the template itself, and
**Disable** clears its **Enabled** box.

## Where it runs, and what's going wrong

A template's page lists **Where it runs**: each host it's on and for, each database it
reads there, or the host itself for one that runs once on it, what its discovery last
found there, and the discover blocks, queries and counters blocks it reads now, which
is what that host's agent, or the server for a host with no agent, is sent. A host's
page lists the same for every template on it, under **Templates**. Anything going
wrong comes first, with what the database or Windows said and since when:

- `connecting`: the database can't be reached or signed in to, or the agent's config
  has no database by that name;
- `account`: what the account may do couldn't be read;
- a discover block, query or counters block, by its key: the database refused the
  SQL, as for a table that isn't there or a view the account can't read, or Windows
  has no such counter.

The agent says it whenever it changes, and once it's right again it goes. Each page
lists at most 100; the API lists them all.

## Names, keys and upgrades

A built-in template is known by its key, so an upgrade can rename it or change
anything else about it and still keep your copies of its alerts and what's turned off.
The same goes for its parts, each known by its key: one that's renamed is a new part.
If a newer version drops an alert you have your own copy of, or the whole template
goes, your copy stays, as an ordinary alert rule of yours, and the notice says so. One whose key changes says so
with `renamed_from = ["old_key"]`. If an upgrade brings a built-in template with the
key or name of one of yours, yours keeps everything it has under a key and name of its
own, such as `myapp_yours` and `My app (yours)`, and a rule of yours with the name of
one of its alerts is renamed the same way.
