# PHP-FPM

The `php_fpm` collector reads each PHP-FPM pool's own status page, which gives its
requests, its processes and whether requests are waiting.

## Turning it on

1. **In each pool**, set `pm.status_path = /status`, and have the web server pass that
   address through to the pool, limited to the host itself.
2. **In MaxNines**, turn on `php_fpm` in a config rule, under **Collectors**. It reads
   `http://localhost/status` unless the rule lists other pages under **PHP-FPM status
   pages**, one to a line, such as one for each pool, which also turns it on.

Addresses with a username or password in them aren't accepted, so they never show up
on the rules pages. The agent reads each page every sample, and gives up on one after
10 seconds. The page can be plain text or `?json`.

## What's reported

Each metric has a series for each page, named by its address without the query, such
as `http://localhost/status`.

| Metric | Unit | Series | What it is |
| --- | --- | --- | --- |
| `php_fpm.up` | 1 or 0 | Each page | Whether the status page answered |
| `php_fpm.requests` | A second | Each page | Requests the pool accepted |
| `php_fpm.active_processes` | Number | Each page | Processes handling a request |
| `php_fpm.idle_processes` | Number | Each page | Processes waiting for one |
| `php_fpm.total_processes` | Number | Each page | Every process in the pool |
| `php_fpm.listen_queue` | Number | Each page | Requests waiting for a free process. Anything above 0 for long means the pool is too small |
| `php_fpm.max_children_reached` | A second | Each page | How often the pool hit `pm.max_children` and couldn't start another process |
| `php_fpm.slow_requests` | A second | Each page | Requests slower than `request_slowlog_timeout`, when that's set |
| `php_fpm.uptime` | Seconds | Each page | How long since the pool started |

Running totals are turned into rates between one read and the next, so a page that
stops answering starts afresh when it's back, rather than counting the gap as one
burst.
