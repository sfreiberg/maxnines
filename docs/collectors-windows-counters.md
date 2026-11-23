# Windows performance counters

A Windows agent's `counters` collector reports any of Windows' performance counters,
which is how most Windows software, such as SQL Server and IIS, says how it's doing.
It needs no extra rights.

## Turning it on

List the counters in a config rule under **Windows performance counters**, one per
line, by their English path, which turns it on:

```text
\Processor(_Total)\% Processor Time
\Memory\Available MBytes
\PhysicalDisk(*)\Avg. Disk sec/Read
\SQLServer:Buffer Manager\Page life expectancy
```

- **Names are in English** whatever language Windows is in, so one rule works on every
  host. Windows' `typeperf -q` lists what a host has, in its own language.
- **`(*)` reports every instance,** such as each disk or each processor, as a series of its
  own, up to 64 for one path: `_Total` first, then the rest in order of their names, so
  each sample keeps the same ones. Programs sharing a name are numbered as Windows
  numbers them, like `svchost#1`.
- **Rates are worked out by Windows** between one sample and the next, so a counter like
  `Disk Reads/sec` has a value from the first sample.
- **A path a host doesn't have** is shown as failing on its page, and looked for again
  each minute, as software adds its own counters once it's installed.

Counters are only ever read, never changed, and only on the host itself. Other
systems ignore the list.

To give counters names and units of their own, and alerts to go with them, use a
[template](templates.md) instead.

## What's reported

Each metric has a series for each path, or each instance of a path with `(*)`.

| Metric | Unit | Series | What it is |
| --- | --- | --- | --- |
| `counter.value` | Number | Each counter | Its value |
| `counter.ok` | 1 or 0 | Each path | Whether it could be read |
| `counter.dropped` | Number | Each path with `(*)` | Instances past the 64 reported |

Each host's page charts the busiest counters together and lists the latest value of
each. An alert rule on `counter.value` can watch one of them by its path.
