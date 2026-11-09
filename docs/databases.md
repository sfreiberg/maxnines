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
