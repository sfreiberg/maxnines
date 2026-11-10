# Alerts

## The built-in rules

Every server starts with three alert rules:

| Rule | Fires when | Severity |
| --- | --- | --- |
| **Agent offline** | An approved agent has been gone for 5 minutes | Critical |
| **Disk filling up** | A disk has been over 80% full for 5 minutes, or over 90% | Warning, then critical |
| **Container down** | A container has been failing for 5 minutes, on machines that report [containers](agents.md#containers) | Critical |

Each disk alerts on its own. They tell every notification channel, including ones added later, so they start working as soon
as there's a channel to tell. Until then they show on the Alerts page and the overview.

They're ordinary rules from then on: change them, turn them off or delete them under
**Settings > Alert rules**, and upgrades leave them alone. A server that already had an
offline rule of its own when it upgraded doesn't get a second one, and one with a
disk usage rule or a containers rule of its own doesn't get that one.

Any rule can tell every channel this way, with **Every channel, including ones added
later**, or tell only the channels chosen.

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
