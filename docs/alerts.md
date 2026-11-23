# Alerts

## The built-in rules

Every server starts with nine alert rules, from the built-in **Host**
[template](templates.md):

| Rule | Fires when | Severity |
| --- | --- | --- |
| **Host offline** | An approved host's agent has been gone for a minute | Critical |
| **Host sending no metrics** | A host's agent has been [connected but sending no metrics](#connected-but-sending-no-metrics) for 5 minutes | Critical |
| **Disk filling up** | A disk has been over 80% full for 5 minutes, or over 90% | Warning, then critical |
| **Disk running out of inodes** | A disk has used over 80% of its [inodes](collectors-operating-system.md#disks) for 5 minutes, or over 90% | Warning, then critical |
| **Container down** | A container has been failing for a minute, on hosts that report [containers](collectors-containers.md) | Critical |
| **Service stopped** | A [watched service](collectors-operating-system.md#services) hasn't been running for a minute | Critical |
| **Clock is wrong** | A host's [clock](collectors-operating-system.md#clock) has been over 5 seconds from the server's for a minute, or over 30 seconds | Warning, then critical |
| **Disk will be full soon** | A disk has been on course to be full within a day for half an hour, judging by the last 6 hours, or within 4 hours | Warning, then critical |
| **Database account can do more than read** | A [template](templates.md) reads a database with an account that [can do more than read](database-stats.md#what-the-account-may-do) | Warning |

The built-in **PostgreSQL** template brings 14 more, for each PostgreSQL database it
reads, one of them off until you say how many standbys a primary should have: they're
listed on the [PostgreSQL](collectors-postgresql.md#built-in-alerts) page. The built-in
**ClickHouse** template brings 7, for each ClickHouse database it reads, listed on the
[ClickHouse](collectors-clickhouse.md#built-in-alerts) page, and the built-in **MySQL**
template 7 more, for each MySQL or MariaDB database, listed on the [MySQL and
MariaDB](collectors-mysql.md#built-in-alerts) page.

Each disk alerts on its own. Every alert resolves as soon as its problem is gone,
without waiting, so a recovery is known at once, and something that keeps failing and
recovering shows as doing that. A Host offline alert resolves within moments of the
agent reconnecting, even just after the server restarts. They tell every notification channel, including ones added later, so they start working as soon
as there's a channel to tell. Until then they show on the Alerts page and the overview.

They're ordinary rules, under **Settings > Alert rules**, that come from a template,
and an upgrade can bring a new version of them. Changing one makes a copy of your own,
which is used in its place and which upgrades leave alone; an alert that's open carries
on as the same alert. **Reset to template** deletes your copy and puts the one that
comes with MaxNines back. Turning one on or off needs no copy: it's your choice from
then on, and until you choose, an upgrade can turn one on or off. They can't be
deleted, but the whole template can be disabled under **Settings > Templates**.

Any rule can tell every channel this way, with **Every channel, including ones added
later**, or tell only the channels chosen.

## Conditions

A rule alerts when its **Warning when** or **Critical when** condition is true, or both.
Each is [CEL](https://cel.dev), the same language as a config rule's `applies_to`, over
metrics by their names in the [catalog](api-metrics.md#list-metrics). As you type one,
the form suggests what can come next: metrics a step at a time through their dots, the
series in brackets of a metric that has fixed ones, such as `cpu.load['5 minutes']`,
facts hosts report, and the names and functions conditions know. Use the arrow keys and
Enter or Tab to pick one, and Escape to close them.

| Condition | Alerts when |
| --- | --- |
| `disk.usage > 90` | A disk is over 90% full. Each disk is checked on its own |
| `series != '/boot' && disk.usage > 90` | The same, leaving out `/boot` |
| `disk.usage > 90 && disk.inodes > 80` | A disk is full and short of inodes. Metrics with a series for each disk pair up by disk |
| `cpu.load['5 minutes'] > facts.cpu.logical_cores` | The 5-minute load is more than the host has cores |
| `check.up['www'] == 0` | One check is failing, picked out by name |
| `clock.difference > duration('30s')` | The clock is over 30 seconds out |
| `process.memory > gib(2)` | A process uses over 2 GiB |
| `!online` | The host's agent is gone |
| `!reporting` | The host is [connected but sending no metrics](#connected-but-sending-no-metrics) |
| `forecast(disk.usage, duration('4h')) >= 100` | A disk is on course to be full within 4 hours, as in [forecasts](#forecasts) |

- **Metrics** are used by their names. One that's a length of time, such as
  `clock.difference`, is compared with `duration('30s')`, `duration('5m')` or
  `duration('2h')`. Sizes are in bytes, with `kib()`, `mib()`, `gib()` and `tib()` to
  write them. Metrics that say whether something works, such as `check.up` or
  `service.running`, are 1 or 0.
- **A metric with a series for each disk, interface, service or such** is checked for
  each one, and each has its own alert. Two such metrics in one condition pair up when
  their series are of the same things, such as disks; metrics with series of different
  things, such as disks and checks, can't be used together that way. `['name']` picks out
  one series instead, and then the alert is about the host.
- **A metric with a few fixed series**, such as `cpu.load` with `'1 minute'`,
  `'5 minutes'` and `'15 minutes'`, or `memory.usage` with `'Memory'` and `'Swap'`, always
  has one picked out with brackets.
- **`series`** is the series being checked, such as `/data`, and empty for the host as a
  whole. **`hostname`** is the hostname, and **`facts.`** are what the host's agent reports,
  as in [config rules](agents.md#config-rules).
- **`online`** is whether the host's agent is connected, and **`reporting`** whether a
  connected host's samples are arriving.
- **A missing reading** isn't a problem: a host or series that hasn't reported a metric a
  condition uses isn't checked, and an alert that's open stays open until it reports
  again.

Each condition is checked when the rule is saved: a name that isn't a metric suggests the
nearest one, and something that can't work, such as a length of time compared with a
number, is refused with what's wrong.

A rule with a calculation across hosts, as in the [API](api-alert-rules.md), has
conditions about the calculated `value` instead, like `value > 80`.

**Try it on the last day**, on the rule's form, works the rule out on the last 24 hours
of what's stored, without saving it, and says how many times it would have warned and
gone critical, and on which hosts, waiting its **For at least** time as it would. It's
tried on each stored step's average, 10 minutes for a day, so something shorter may not
show, and `forecast()` is drawn through those steps. Hosts are taken to have been
`online` and `reporting`, as that isn't kept. The API does the same, as
[trying a rule](api-alert-rules.md#try-an-alert-rule-on-the-last-day) describes.

### What alerts say

Without a **Summary**, an alert says the rule's name, the host, and the first metric's
reading, like *Disk filling up on web-1: / is 92%*, and as it clears, *Disk filling up on
web-1: / is now 70%*. A summary can say anything else, filled in like a
[custom webhook's body](notifications.md#custom-webhooks), with `{{ hostname }}`,
`{{ series }}`, `{{ value }}` and the metrics the conditions use, each written in its
unit: `{{ hostname }}: {{ series }} is {{ disk.usage }} full` says *web-1: / is 92% full*.

## Connected but sending no metrics

An agent can stay connected while nothing it sends is stored, such as when the server
can't read samples from an agent on the other side of a change to them. It never goes
offline, so the Host offline rule can't see it. A connected host isn't `reporting` once
the newest sample stored from it is three of its intervals old, from the
[config rules](agents.md#config-rules) that apply to it, and at least a minute, so one
set to send a sample every 10 minutes isn't reporting after 30 minutes. A rule with
`!reporting` alerts once that's lasted its **For at least** time, like *web-1 is
connected but sending no metrics*, and resolves as soon as a sample is stored again,
saying *web-1 is sending metrics again*.

- A host that hasn't sent anything since it connected counts from when it connected.
- A host that's gone keeps what it was as it went: one that had stopped sending
  stays not `reporting`, and any other is `reporting`, as its going is the Host
  offline rule's to alert on. So an alert that's already open stays open while its
  agent is away, after it reconnects and after the server restarts, until a sample is
  stored, and `!online || !reporting` alerts on either. A host without an agent, or the
  server itself, is always `reporting`.
- The server's own readings of a host's [clock](collectors-operating-system.md#clock) don't count, as
  they're saved whether or not anything the agent sends is.
- Nothing starts in the first two minutes after the server starts, while agents
  reconnect and send what they kept meanwhile.

## Forecasts

A forecast alerts before a problem rather than once it's there, such as a disk that will
be full in a few hours while it's still at 70%. `forecast(disk.usage, duration('4h'))` is
where the metric will be in 4 hours, judging by the straight line that best fits each
series over the last few hours, carried on. So a rule that warns when a disk is on
course to be full within a day, and is critical within 4 hours, has:

- **Warning when** `forecast(disk.usage, duration('24h')) >= 100`
- **Critical when** `forecast(disk.usage, duration('4h')) >= 100`

**Looking back** is how much of the past the line is drawn through, from 1 to 24 hours,
and 6 hours unless it's set. A longer time is steadier, and a shorter one notices a
change sooner.

Forecasts are worked out every 5 minutes. A series needs at least 10 readings, from at
least half the time looked back over, and one in the last 10 minutes, before it has a
forecast at all, so a new host waits a while.

## Warning, then critical

A rule can have a warning condition, a critical condition, or both. With both, there's
one alert for each thing it watches, at the worse of the two: a disk at 85% is a
warning, and the same alert becomes critical when the disk passes 90%. Each condition has
to be true for the rule's **For at least** time to count, and stops counting the moment
it isn't.

- **Getting worse** sends a **Now critical** notification to every channel that heard
  the alert start, and clears any acknowledgement, so someone has to pick it up again.
- **Getting better** without clearing sends **Down to a warning** to the same channels.
- **Clearing** resolves the alert, whichever it was at.

A channel whose first notification hasn't gone out yet gets the alert as it is when it
does. On-call services get the change on the same incident, so they show the new
severity without opening another. Webhooks see the events `escalated` and `eased`.

## Which channels hear what

Each channel takes warnings, critical alerts or both, under **Alerts to send** on its
form. A channel hears of an alert once it reaches a severity the channel takes, and from
then on of every change until it resolves:

- **Critical alerts only**, for a pager: a warning isn't sent, and if it becomes
  critical, the pager hears of it starting then. If it eases, the pager hears that too,
  on the same incident. One that eases before the pager was sent it isn't sent at all.
- **Warnings only**, for email or chat: a warning is sent, and so is it becoming
  critical. An alert that's critical from the start isn't sent.
- **Both**, the default: everything.

A resolved notification says where things stand as the problem cleared rather than
repeating what was wrong, like `High CPU on web-1: CPU usage is now 42%` or
`web-1 is back online`, as the rule's [summary](#what-alerts-say) says. Email,
Telegram and Teams add what it said when it fired. In Slack, the message the alert
fired with is marked resolved and keeps its words, and the reply in its thread says
where things stand now.

## Actions

A rule about hosts, rather than a calculation across them, can run actions on the
alert's host, and what they print is
kept with the alert: which processes are busiest when CPU is high, where the space
has gone when a disk is filling up, or the result of restarting a service.

In the rule's **Actions** box, list one per line by name. Each runs once per alert:

| Line | Runs |
| --- | --- |
| `top_cpu` | When the alert starts, whatever it starts at |
| `top_cpu on=warning` | The first time the alert is a warning |
| `disk_space on=critical timeout=120` | The first time the alert is critical, whether it starts there or gets there, with 120 seconds to finish |

An action gets 30 seconds unless `timeout=` says otherwise, up to 600. One that runs
out of time is stopped, and what it printed until then is kept.

Agents have these built in, which only look:

| Action | Prints |
| --- | --- |
| `top_cpu` | The 20 processes using the most CPU |
| `top_memory` | The 20 processes using the most memory |
| `disk_io` | The processes reading and writing the most, over a second |
| `disk_space` | Where the space on the alert's disk is going: up to ten folders that each hold 2% or more of what's used, however deep they are, what couldn't be accounted for, and what changed since it last looked |
| `connections` | The 20 processes holding the most network connections, how many are in each state, and the ten addresses with the most. FreeBSD doesn't say what state a connection is in, so its agent leaves that out |

Anything else is a command in the agent's own config file, as described under
[agents](agents.md#actions). That's the only place an action can be added, so the
server can only ever ask a host for something its administrator put there.

An action can use values from the alert: `{disk}`, `{interface}`, `{process}`,
`{container}` or `{check}` for what the alert is about, or `{series}` for any of them,
and `{hostname}`, `{rule}`, `{severity}`, `{metric}` and `{value}`, the first metric the
rule's conditions use and its reading. A
rule can't be saved with an action that needs something its alerts don't have, such as
`disk_space` on a CPU rule, or with one no host has. A host that lacks an action
other hosts have records that it couldn't run it, and so does an alert about a whole
host whose rule's action needs `{series}` or one of its kinds, as it has none to give.

What an action printed is sent to the channels that heard the alert start, as
[notification channels](notifications.md#what-actions-print) describes: a reply
under the alert's message in Slack and Telegram, and a message of its own elsewhere.
On-call services aren't sent it.

The **Actions** button on an alert shows what its actions printed. A host's page has
**Actions** too, with every run on that host and a **Run** button for each action it
has, which takes the responder role. Don't have an action print secrets: anyone who
can sign in can read what it printed.

## Silences

A silence stops notifications for a while, as during planned work. Press **Silence** on
a firing alert, or start one from **Alerts > Silences**. It needs a reason and a length,
and it can cover one rule or all of them, and some hosts or all of them, using the same
filter as the Hosts list. To cover every alert on every host, choose **Every alert, on
every host**: leaving the rule, hosts and series empty isn't enough, so a silence can't
quiet everything by accident. Maintenance windows work the same way.

**Silence** on a firing alert covers that alert alone: its rule, on its host, and only
the series it's about, such as one disk or one container.

Alerts still fire and show while they're silenced. If one is still firing when the
silence ends, the notifications go out then, and if it ends first, nobody hears about it.
Anyone who had already been told about an alert still hears when it ends, which keeps
on-call services from leaving an incident open.

To silence one host, such as while it's rebooted or upgraded, use **Start maintenance**
on its page under **Hosts**. Choose how long, from 30 minutes to a day, and a reason if
you like. It's a silence for every rule on that host alone, so it shows under
**Alerts > Silences** too, and **End now** on the host's page stops it early. While
anything holds back all of a host's notifications, its page says what and until when,
including a wider silence or a maintenance window, which are ended from their own pages.
It takes the responder role, like any silence.

A maintenance window is a silence that comes round on a schedule, like Sundays from 02:00
for two hours. Add one under **Alerts > Silences**, with a time zone so it keeps its place
in the day when the clocks change.

## An alert's chart

Press **Chart** on an open alert to see just what it's about: the first metric its
rule's conditions use, and its own series, such as the one disk that's filling, with
lines where the alert started and, once it has, resolved. A condition that only compares
the metric with a number, such as `disk.usage > 90`, is drawn across it too. The chart
reaches back past the start to show what led up to it, and the ranges above it look
further. A rule that uses no metric, such as `!online`, has no chart.

## Reminders and acknowledging

Set **Remind every** on an alert rule to hear again while it's still firing, at most
every 5 minutes. Reminders go to the channels that were told it started, except on-call
services, which repeat for themselves.

Press **Acknowledge** on a firing alert to say you're dealing with it. That shows your
name on the Alerts page and stops the reminders. It only applies inside MaxNines, so
acknowledging an alert here doesn't acknowledge it in PagerDuty, or the other way round.
