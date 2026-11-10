# Audit log

The audit log records every change to the server's setup and every sign in: who did
it, when, where from, and each field's value before and after. Find it under
Settings, or read it through the [API](api.md#audit-log). Entries are kept for good,
and there's no way to change or delete them from MaxNines.

## What's recorded

- Signing in, signing out, and failed sign ins, with the email address that was tried
- Users: adding, disabling, enabling and deleting them, role changes, password
  changes, new password links, two-factor being turned on, off or reset, and each
  person's theme and time zone
- Two-factor being made required for everyone, or optional again
- API keys being created and revoked, and deleted with their owner
- Agents being approved, revoked, renamed by their machine, and deleted, and new agents
  asking to join
- Config rules, alert rules, notification channels, silences, maintenance windows,
  remote checks, location rules and dashboards being created, changed and deleted
- Alerts being acknowledged and unacknowledged, on the pages or in Slack

Saving something without changing it doesn't add an entry. Alerts starting and
ending, and the notifications they send, aren't recorded here, as the alerts page
already keeps their history.

## Who and where from

Each entry says who acted:

- a user, by their email address, on the pages, with one of their API keys, which
  the entry names, or by pressing an alert's buttons in Slack, matched to them by
  email address
- the command line, with the system account that ran `maxnines-server`
- MaxNines itself, like a registration rule approving an agent
- someone not signed in, for a failed sign in

It also keeps the address each request came from. Behind a reverse proxy, that's
the address the proxy passes on, but only if the proxy is listed in
`trusted_proxies`, as anyone could otherwise claim any address. See
[HTTPS](https.md).

## Secrets

Passwords, bot and app tokens, and a channel's target where it works as a password,
like a webhook's address, are never written to the log. Their entries only say
they were set, changed or removed. The same goes for any config rule setting with a
name like `password`, `secret`, `token` or `credential`.
