# Templates

A template says what MaxNines watches for in something it monitors, such as a host,
PostgreSQL or IIS: what to read, the metrics that makes, and the alerts on them. Each
of its alerts is an [alert rule](alerts.md), which you can change, turn off and put
back as it was.

Templates are under **Settings > Templates**. The ones that come with MaxNines are
written as the server starts, and an upgrade can bring new versions of them. A built-in
template can't be edited or deleted. Changing one of its alerts makes a copy of your
own, used in place of the built-in one, which upgrades never touch. A built-in template
or alert can be disabled, which stays that way through upgrades. Admins see a notice on
every page when an upgrade has changed a template, saying which alerts you have your
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
| **Host** | Every host, with an agent or only checks: whether it's online and sending metrics, and its disks, clock, services and containers. It has the eight [built-in alert rules](alerts.md#the-built-in-rules) |

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
have the name of one MaxNines has built in, such as `postgres.lag`, is refused: give
it another key.

Lengths of time are written like `"30s"`, `"5m"`, `"1h"` or `"1h 30m"`, in whole
seconds. Versions are numbers with dots, compared as numbers, so 9.6 < 13 < 16.2, and
13 is the same as 13.0.

### What it runs for

One field says what a template is for, and it runs once for each match on a host:

| Field | Runs |
| --- | --- |
| `database = "postgres"` | Once for each database of this kind in the agent's config |
| `service = "W3SVC"` | Once on each Windows host with this service |
| `os = ["linux", "freebsd"]` | Once on each host running one of these: `freebsd`, `linux`, `macos` and `windows`. Its alerts only apply to those hosts |
| none | Once on every host, agentless ones too |

`min_version` is the oldest version it's for. `services` lists services that the
host's own **Service stopped** alert should watch.

### Discovery

`discover` runs first, then every `interval`, and again when what's monitored
restarts. What it finds is what `when` and `since` look at:

- `sql`: each column, by its name. A column called `version` is read as a version;
- `registry "<key>" { name = "Value" }`: Windows registry values, each by its name;
- `counter_sets = { name = "Counter set" }`: whether the host has each performance
  counter set, true or false.

```hcl
discover {
  interval = "1m"
  sql      = "SELECT current_setting('server_version') AS version, pg_is_in_recovery() AS replica"
}
```

### Queries

`query` blocks are SQL whose columns become metrics:

- each column becomes a metric named `<key>.<column>`. True and false columns become
  yes or no, and intervals become lengths of time;
- every column needs a name: give anything that isn't a column of its own one with
  `AS`;
- `labels = ["slot"]` names the text columns that tell rows apart, one series per row;
- a NULL gives no sample, rather than zero.

`metrics = { … }` only says what can't be worked out from the column: `total = true`
for a running total, which is kept as a rate; a `unit`, which is `%`, `s`, `bytes`,
`bytes/s`, `/s` or `°C`; a `description`; or `value`, CEL working a metric out from the
others as each sample arrives.

```hcl
query "throughput" {
  sql = "SELECT sum(xact_commit) AS commits, sum(blks_hit) AS hits, sum(blks_read) AS reads FROM pg_stat_database"
  metrics = {
    commits   = { total = true }
    cache_hit = { value = "rate(hits) / (rate(hits) + rate(reads)) * 100", unit = "%" }
  }
}
```

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
  always left out;
- `pattern` does the same with a regular expression whose named groups become labels,
  leaving out instances it doesn't match. `instance` reads one instance only, and
  `exclude` lists instances to leave out;
- `join` matches these instances to another counter set's by a group named in both
  patterns, which the other groups then label. `groups = { pid = "ID Process" }` reads a
  group's value from a counter rather than the instance's name;
- series that end up with the same labels add up; percentages take the highest.

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

An alert with `when` or `since` says **Not checked yet** on the template's page, and
isn't worked out yet: which databases or hosts it's for depends on what discovery
finds on each, which isn't kept yet.

### Notices

`notice` blocks are shown while their `when` holds:

```hcl
notice "cannot_see_sessions" {
  when = "!sees_all_sessions"
  text = "The account can't see other sessions. Grant it pg_monitor."
}
```

## Examples

Two full templates, to read, copy from and import. They're examples of the format,
not templates that come with MaxNines. The PostgreSQL one can't be imported with its
key as it is, `postgres`, because MaxNines already reads PostgreSQL itself under the
same metric names. Change the key, such as to `pg`, to import it.

**[postgres.hcl](examples/postgres.hcl)**, for PostgreSQL, is all SQL:

- `database = "postgres"`, so it's for each PostgreSQL database in an agent's config;
- `discover` finds the version, whether the server is a primary or a replica, and
  whether it archives WAL, which the queries' `when` and `since` then pick by;
- a query each for sessions, throughput, checkpoints, WAL, replication from both
  ends, replication slots, archiving and subscriptions. `fill` covers the views that
  moved between versions, such as checkpoints in 17, so each query is written once;
- `labels` give a series to each standby, slot and subscription;
- the slow queries, database and WAL sizes, ship with `enabled = false`;
- its alerts use the short names, such as `lag > duration('30s')` and `!receiving`,
  and `when` keeps the replica's alerts to replicas.

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
