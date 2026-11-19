# Alerts

## The built-in rules

Every server starts with eight alert rules:

| Rule | Fires when | Severity |
| --- | --- | --- |
| **Host offline** | An approved host's agent has been gone for a minute | Critical |
| **Host sending no metrics** | A host's agent has been [connected but sending no metrics](#connected-but-sending-no-metrics) for 5 minutes | Critical |
| **Disk filling up** | A disk has been over 80% full for 5 minutes, or over 90% | Warning, then critical |
| **Disk running out of inodes** | A disk has used over 80% of its [inodes](agents.md#disks) for 5 minutes, or over 90% | Warning, then critical |
| **Container down** | A container has been failing for a minute, on hosts that report [containers](agents.md#containers) | Critical |
| **Service stopped** | A [watched service](agents.md#watching-services-and-processes) hasn't been running for a minute | Critical |
| **Clock is wrong** | A host's [clock](agents.md#clock) has been over 5 seconds from the server's for a minute, or over 30 seconds | Warning, then critical |
| **Disk will be full soon** | A disk has been on course to be full within a day for half an hour, judging by the last 6 hours, or within 4 hours | Warning, then critical |

Each disk alerts on its own. Every alert resolves as soon as its problem is gone,
without waiting, so a recovery is known at once, and something that keeps failing and
recovering shows as doing that. A Host offline alert resolves within moments of the
agent reconnecting, even just after the server restarts. They tell every notification channel, including ones added later, so they start working as soon
as there's a channel to tell. Until then they show on the Alerts page and the overview.

They're ordinary rules from then on: change them, turn them off or delete them under
**Settings > Alert rules**, and upgrades leave them alone. A server that already had a
rule called Host sending no metrics when it upgraded keeps that one instead.

Any rule can tell every channel this way, with **Every channel, including ones added
later**, or tell only the channels chosen.

## Connected but sending no metrics

An agent can stay connected while nothing it sends is stored, such as when the server
can't read samples from an agent on the other side of a change to them. It never goes
offline, so the Host offline rule can't see it. A rule of the kind **A host stays
connected but sends no metrics** alerts when the newest sample stored from a connected
host is older than its **For at least** time, like *web-1 is connected but sending no
metrics*, and resolves as soon as one is stored again, saying *web-1 is sending metrics
again*.

- A host that hasn't sent anything since it connected counts from when it connected.
- A host that sends seldom gets at least three of its intervals, from the
  [config rules](agents.md#config-rules) that apply to it, so one set to send a sample
  every 10 minutes alerts after 30 minutes, not after 5.
- Only connected agents are watched. One that's gone is the Host offline rule's to
  alert on, and a host without an agent, or the server itself, never alerts. An alert
  that's already open stays open while its agent is away and after it reconnects,
  until a sample is stored.
- The server's own readings of a host's [clock](agents.md#clock) don't count, as
  they're saved whether or not anything the agent sends is.
- Nothing starts in the first two minutes after the server starts, while agents
  reconnect and send what they kept meanwhile.

## Forecasts

A forecast rule alerts before a problem rather than once it's there, such as a disk that
will be full in a few hours while it's still at 70%. It draws the straight line that best
fits each series over the last few hours, carries it on, and alerts when that line
reaches a level within the time you choose.

On the rule's page, choose **A metric is on course to reach a level soon**, then:

- **Level** is what the metric is heading for, like 100 for a disk being full. Above
  means rising to it, and below means falling to it.
- **Warning if it gets there within** and **Critical if it gets there within** are in
  hours. Fill in either or both. With both, one alert starts as a warning and becomes
  critical once the level is closer, as with thresholds.
- **Judging by the last** is how many hours the line is drawn through, from 1 to 24.
  A longer time is steadier, and a shorter one notices a change sooner.

Forecasts are worked out every 5 minutes. A series needs at least 10 readings, from at
least half the time looked back over, and one in the last 10 minutes, before it has a
forecast at all, so a new host waits a while. A series that's already reached the
level counts as getting there now. When the line stops heading for the level, the
alert clears once that's lasted the rule's **For at least** time.

The alert says where the metric is and how fast it's moving, like *Disk usage (/) on
web-1 is 92% and rising by 3% an hour, so it reaches 100% in about 3 hours*.

## Warning, then critical

A metric or calculation rule can have a warning threshold, a critical threshold, or
both. With both, there's one alert for each thing it watches, at the worse of the two:
a disk at 85% is a warning, and the same alert becomes critical when the disk passes
90%. Each threshold has to be crossed for the rule's **For at least** time to count, and
stops counting the moment it's clear.

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
repeating what was wrong, like `CPU usage on web-1 is now 42%, no longer above 90%`,
`Disk usage (/) on web-1 is now 83.7% and steady`,
`Disk usage (/) on web-1 is now 84% and rising by 0.6% an hour, so it reaches 100% in about 27 hours, no longer within 1 day`
or `web-1 is back online`. Email,
Telegram and Teams add what it said when it fired. In Slack, the message the alert
fired with is marked resolved and keeps its words, and the reply in its thread says
where things stand now.

## Actions

A metric or forecast rule can run actions on the alert's host, and what they print is
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
and `{hostname}`, `{rule}`, `{severity}`, `{metric}`, `{value}` and `{threshold}`. A
rule can't be saved with an action that needs something its alerts don't have, such as
`disk_space` on a CPU rule, or with one no host has. A host that lacks an action
other hosts have records that it couldn't run it.

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

Press **Chart** on an open alert to see just what it's about: its own series, such as
the one disk that's filling, with the rule's thresholds across it and lines where the
alert started and, once it has, resolved. The chart reaches back past the start to
show what led up to it, and the ranges above it look further. A forecast's chart has
its level, such as 100%, across it instead. Offline and no-metrics alerts have no
chart, as they don't watch a metric.

## Reminders and acknowledging

Set **Remind every** on an alert rule to hear again while it's still firing, at most
every 5 minutes. Reminders go to the channels that were told it started, except on-call
services, which repeat for themselves.

Press **Acknowledge** on a firing alert to say you're dealing with it. That shows your
name on the Alerts page and stops the reminders. It only applies inside MaxNines, so
acknowledging an alert here doesn't acknowledge it in PagerDuty, or the other way round.
