# Databases

## Main database

Users, agents, alert rules, dashboards and settings are kept in the main database, which
is separate from metrics. `server.hcl` chooses it with a URL:

```hcl
# SQLite, the default. There's nothing else to run.
database {
  url = "sqlite://data/maxnines.sqlite?mode=rwc"
}

# PostgreSQL
database {
  url = "postgres://maxnines:${env("DB_PASSWORD")}@db.example.com:5432/maxnines"
}

# MySQL or MariaDB
database {
  url = "mysql://maxnines:${env("DB_PASSWORD")}@db.example.com:3306/maxnines"
}
```

To keep the password out of `server.hcl`, use `env()` as above, or put the whole URL in a
file and use `url_file = "/path/to/file"` instead of `url`.

For PostgreSQL, MySQL and MariaDB, create an empty database and a user who can create
tables in it. The server sets up its tables when it starts, and updates them after an
upgrade. PostgreSQL 16, MySQL 8.4 and MariaDB 12 are tested.

Nothing moves between databases, so changing later starts this data afresh.

## Metrics databases

`server.hcl` chooses where metrics are kept, and everything else works the same on
either.

- **DuckDB** is the default. It's built into the server, so there's nothing else to run.
  Use it for smaller installations.
- **ClickHouse** runs as a server of its own. Use it for bigger fleets. Point the
  `metrics "clickhouse"` block at it, and the database and tables are created for you.

Nothing moves between them, so changing later starts metrics afresh.

## How long metrics are kept

Every sample is kept for 30 days. After that, what's kept is each minute for a year and
each hour for good, as its lowest, highest and average value. Set how long in
`server.hcl`:

```hcl
retention {
  full_resolution_days = 30
  minute_days          = 365
  hour_days            = 1825   # leave this out to keep hours for good
}
```

- **Spikes aren't averaged away.** A minute or an hour keeps its highest and lowest
  value as well as its average, so a 15-second spike to 100% CPU still reaches 100% on
  a chart of last year. Charts draw a shaded band from the lowest to the highest value
  at each point, around the average line. Rates, like network traffic, are worked out
  before rolling up, so a burst keeps its real peak.
- **Long charts read the rolled-up minutes and hours,** which is quicker, and samples
  only for the newest hour, which isn't rolled up yet. A chart reaching back past 30
  days reads minutes, and past a year reads hours.
- **Alerts always read samples**, so `full_resolution_days` has to be at least 2.
  `minute_days` can't be shorter than it, and `hour_days` can't be shorter than
  `minute_days`.
- **An hour is rolled up once it's over.** Samples that arrive after that, like those an
  agent kept while it couldn't reach the server, have their hour rolled up again.
- **Nothing is deleted before it's rolled up.** If rolling up falls behind, samples are
  kept until it catches up, rather than lost.

Old data is deleted about once an hour. Setting a longer time keeps what's still there,
and a shorter one deletes what's now too old at the next hourly pass.
