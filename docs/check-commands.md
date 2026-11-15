# Check commands

Thousands of monitoring plugins already exist in the Nagios style, for databases,
RAID controllers, appliances, licences and much else, and most teams have a few of
their own. An agent can run them as **check commands**, so anything one of them
checks shows up in MaxNines with nothing else to install.

The [Monitoring Plugins](https://www.monitoring-plugins.org/) project has the common
ones, packaged as `monitoring-plugins` on Debian and Ubuntu, `nagios-plugins-all` on
Fedora and RHEL (from EPEL), and `monitoring-plugins` in Homebrew.

## Defining one

A check command is defined in the agent's own config file, `agent.hcl`, by name:

```hcl
check_command "raid" {
  command = ["/usr/lib/nagios/plugins/check_raid"]
}

check_command "ntp" {
  command      = ["/usr/lib/nagios/plugins/check_ntp_time", "-H", "pool.ntp.org", "-w", "0.5", "-c", "1"]
  timeout_secs = 20
}
```

- `command` is the program, then each of its arguments. It runs directly, not through
  a shell, so there's no quoting to get wrong and nothing a shell would expand.
- `timeout_secs` is how long it gets, from 1 to 300 seconds. It defaults to 30. One
  that takes longer is stopped, along with anything it started, and counts as
  unknown.
- A name has letters, digits, `.`, `-` and `_`.

Restart the agent after changing the file. Then list the names under **Check
commands** in a [config rule](api-config-rules.md), one to a line, to run them on the
hosts the rule applies to. They run with every sample, or less often if the rule's
interval says so.

The server only chooses which names to run. It can never add a command or change one,
so whoever controls the server can't make a host run anything new. A name the server
asks for that a host doesn't define reports as unknown, saying so.

## What's reported

A plugin says how things are by how it exits:

| Exit code | Status |
|---|---|
| 0 | OK |
| 1 | Warning |
| 2 | Critical |
| 3, or anything else | Unknown |

| Metric | What it is |
|---|---|
| **Check command status** | The status above, as 0 to 3 |
| **Check command passing** | 1 while it's OK, 0 otherwise, which isn't charted |
| **Check command values** | Its performance data, as below |

The first line a plugin prints says why, such as `RAID CRITICAL - md0 degraded`. Up
to 256 characters of it are sent to the server and shown on the host's metrics page
beside each command's status. Don't use a plugin that prints a secret on its first
line.

### Performance data

Anything after a `|` on the first line, or on a later line, is performance data:
values separated by spaces, each as `label=value[unit];warn;crit;min;max`.

```text
DISK OK - free space: / 3326 MB (56%); | /=2643MB;5948;5958;0;5968 'root inodes'=12%
```

Each value becomes a series named by the command and its label, such as `disk /` and
`disk root inodes`. Times are kept in seconds and sizes in bytes, so `250ms` becomes
0.25 and `2KB` becomes 2048. Percentages and counters (`c`) are kept as they are. The
warning and critical levels after the value are left out, as an alert rule sets its
own. A value of `U`, meaning it couldn't be measured, is skipped, and so is anything
that isn't a number. Up to 32 values are kept from each run.

## Alerting

To be told when a plugin says something is wrong, add an alert rule on **Check command
status** for the command, such as **above 1** for critical and **above 0** for a
warning first. Its performance data can be alerted on like any other metric.
