# Alerts

## The built-in rules

Every server starts with seven alert rules:

| Rule | Fires when | Severity |
| --- | --- | --- |
| **Host offline** | An approved host's agent has been gone for 5 minutes | Critical |
| **Disk filling up** | A disk has been over 80% full for 5 minutes, or over 90% | Warning, then critical |
| **Disk running out of inodes** | A disk has used over 80% of its [inodes](agents.md#disks) for 5 minutes, or over 90% | Warning, then critical |
| **Container down** | A container has been failing for 5 minutes, on hosts that report [containers](agents.md#containers) | Critical |
| **Service stopped** | A [watched service](agents.md#watching-services-and-processes) hasn't been running for 5 minutes | Critical |
| **Clock is wrong** | A host's [clock](agents.md#clock) has been over 5 seconds from the server's for 5 minutes, or over 30 seconds | Warning, then critical |
| **Disk will be full soon** | A disk has been on course to be full within a day for half an hour, judging by the last 6 hours, or within 4 hours | Warning, then critical |

Each disk alerts on its own. A Host offline alert resolves within moments of the agent
reconnecting, even just after the server restarts. They tell every notification channel, including ones added later, so they start working as soon
as there's a channel to tell. Until then they show on the Alerts page and the overview.

They're ordinary rules from then on: change them, turn them off or delete them under
**Settings > Alert rules**, and upgrades leave them alone. A server that already had an
offline rule of its own when it upgraded doesn't get a second one, and one with a
disk usage, inodes or containers rule of its own doesn't get that one.

Any rule can tell every channel this way, with **Every channel, including ones added
later**, or tell only the channels chosen.

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
be clear that long to stop counting.

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
filter as the Hosts list.

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

## Reminders and acknowledging

Set **Remind every** on an alert rule to hear again while it's still firing, at most
every 5 minutes. Reminders go to the channels that were told it started, except on-call
services, which repeat for themselves.

Press **Acknowledge** on a firing alert to say you're dealing with it. That shows your
name on the Alerts page and stops the reminders. It only applies inside MaxNines, so
acknowledging an alert here doesn't acknowledge it in PagerDuty, or the other way round.
