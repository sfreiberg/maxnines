# Alerts

## The built-in rules

Every server starts with three alert rules:

| Rule | Fires when | Severity |
| --- | --- | --- |
| **Agent offline** | An approved agent has been gone for 5 minutes | Critical |
| **Disk filling up** | A disk has been over 80% full for 5 minutes | Warning |
| **Disk nearly full** | A disk has been over 90% full for 5 minutes | Critical |

Each disk alerts on its own, and a disk over 90% has both alerts open. They tell
every notification channel, including ones added later, so they start working as soon
as there's a channel to tell. Until then they show on the Alerts page and the overview.

They're ordinary rules from then on: change them, turn them off or delete them under
**Settings > Alert rules**, and upgrades leave them alone. A server that already had an
offline rule of its own when it upgraded doesn't get a second one, and one with a
disk usage rule of its own doesn't get the disk rules.

Any rule can tell every channel this way, with **Every channel, including ones added
later**, or tell only the channels chosen.

## Silences

A silence stops notifications for a while, as during planned work. Press **Silence** on
a firing alert, or start one from **Alerts > Silences**. It needs a reason and a length,
and it can cover one rule or all of them, and some hosts or all of them, using the same
filter as the host list.

Alerts still fire and show while they're silenced. If one is still firing when the
silence ends, the notifications go out then, and if it ends first, nobody hears about it.
Anyone who had already been told about an alert still hears when it ends, which keeps
on-call services from leaving an incident open.

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
