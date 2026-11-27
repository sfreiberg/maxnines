# Server API

## Get server status

`GET /api/v1/server`

How the server is doing, including its CPU, memory, databases and activity. Each part
is read on its own, so one that's unavailable is empty and the rest still answer.
`cpu_percent` is a share of the whole host, and empty on the first request after a
start. Each of `metrics.collectors` counts its samples over the last hour, with the
oldest and newest of those, as counting every sample ever kept would read them all;
`rows` is `null` for that reason, and `total_rows` is what the store says it holds. `memory_bytes` can read high on macOS, which counts memory that's been freed
until something else needs it. `built_at` is empty for a build that didn't record when
it was made.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" "$MAXNINES_URL/api/v1/server"
```

```json
{
  "version": "0.1.0",
  "commit": "770de39",
  "built_at": "2026-11-06T04:42:04.427542Z",
  "rust_version": "1.100.0",
  "started_at": "2026-11-06T04:44:24.095Z",
  "uptime_secs": 22,
  "os": "Ubuntu 24.04",
  "process": {
    "memory_bytes": 53641216,
    "cpu_percent": 5.2,
    "open_files": 17,
    "host_memory_total_bytes": 51539607552,
    "host_memory_used_bytes": 39138967552,
    "cores": 12
  },
  "disk": {
    "mount_point": "/",
    "total_bytes": 994662584320,
    "available_bytes": 266447943341
  },
  "metrics": {
    "engine": "DuckDB",
    "size": "417.5 MiB",
    "write_ahead_log": "9.9 KiB",
    "memory_used": "718.0 KiB",
    "memory_limit": "128.0 MiB",
    "collectors": [
      {
        "name": "cpu",
        "rows": null,
        "rows_last_hour": 295967,
        "oldest_sample_at": "2026-11-06T03:37:29.223Z",
        "newest_sample_at": "2026-11-06T03:52:18.143Z"
      }
    ],
    "total_rows": 18540210
  },
  "database": {
    "engine": "SQLite",
    "size_bytes": 28397568,
    "response_secs": 0.00003,
    "latest_migration": "m20261119_000001_create_tables",
    "tables": [{ "name": "Hosts", "rows": 5001 }],
    "notifications_waiting": 0,
    "notifications_failed": 0
  },
  "activity": {
    "hosts_online": 5000,
    "hosts_approved": 5000,
    "hosts_waiting": 0,
    "samples_written": 119757,
    "samples_failed": 0,
    "samples_queued": 0,
    "queue_capacity": 1024,
    "alerts_open": 0,
    "last_alert_pass_at": "2026-11-06T03:52:24.561Z"
  }
}
```

## Get the server's own history

The server records its own numbers every 15 seconds as the built-in host `server`,
along with `cpu`, `memory`, `disk` and `network` for the host it's on. Nothing has
to be installed for this. They work like any host's metrics, including in alert
rules. Read them with the same route, using metrics such as `server.metrics` (metrics
stored per second), `server.samples`, `server.write_queue`, `server.write_time`,
`server.hosts`, `server.alerts`, `server.database_size`, `server.series`,
`server.memory`, `server.cpu`, `server.open_files` and `cpu.usage`:

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/hosts/server/metrics/server.memory"
```
