# Collectors

A collector is the part of an agent that reads one kind of thing about its host, such
as its CPU, its disks or a web server's status page. The pages under this one say what
each collector reads, how to turn it on, and every metric it reports:

- **[Operating system](collectors-operating-system.md):** CPU, memory, disks, network,
  processes, services, updates, logins, files and folders, GPUs, temperatures, the
  clock and uptime.
- **[Containers](collectors-containers.md):** Docker and Podman containers on Linux.
- **[Windows performance counters](collectors-windows-counters.md):** any counter
  Windows or the software on it publishes.
- **Web servers:** [Apache](collectors-apache.md), [nginx](collectors-nginx.md) and
  [PHP-FPM](collectors-php-fpm.md).

Databases, [checks](checks.md), [check commands](check-commands.md), custom metrics and
[OpenMetrics pages](openmetrics.md) are collectors too, with pages of their own, and
[templates](templates.md) add metrics on top.

## Turning collectors on

[Config rules](agents.md#config-rules) say which collectors each host runs, under
**Collectors** on the rule's form, where each is **On**, **Off** or decided by other
rules. Filling in anything under **What to watch**, such as services or status pages,
turns that collector on too, unless the rule sets it to **Off**.

| Collector | On by default | Systems |
| --- | --- | --- |
| `cpu`, `memory`, `disk`, `network`, `host`, `system` | Yes | All |
| `gpu` | On Macs | macOS |
| `processes`, `services`, `files` | Once a rule lists what to watch | All |
| `top_processes`, `sensors` | No | All |
| `containers` | No | Linux |
| `counters` | Once a rule lists counters | Windows |
| `apache`, `nginx`, `php_fpm` | No | All |

## Reading the tables

Each page lists its metrics by the names alert rules, dashboards and the API use,
such as `cpu.usage`.

- **Unit** is how the value is written: a percentage, bytes, bytes a second, a count
  a second, seconds, a plain number, or 1 and 0 for yes and no.
- **Series** says what a metric is broken down by. A metric with a series for each
  disk, interface or such is checked for each of them by an alert rule, and
  `['name']` picks one out, as in `cpu.load['5 minutes']`. See
  [Conditions](alerts.md#conditions).
- A value a system doesn't have is left out, never reported as 0, so an alert on it
  stays as it was.
