# Hosts without an agent

Some things can't have an agent installed: a managed database, a network device, a
service someone else runs. They can still be hosts. The server reads their metrics
itself, from [OpenMetrics](openmetrics.md) pages you give it, and checks that they
can be reached, and everything that works for a host works for them: charts, alert
rules, silences, maintenance windows, dashboards and the map.

## Adding one

On the Hosts page, press **Add a host** and give it a name, such as `orders-db`. The
name is whatever you want it called in lists and alerts, and can be changed later
without losing its history. Then add the pages to read, on the host's own page under
**Metrics pages**:

| Setting | What it's for |
| --- | --- |
| **Address** | A page in the Prometheus or OpenMetrics text format, such as an exporter's `/metrics`. The server reads it from where the server runs |
| **Read every** | How often, from 10 seconds to a day |
| **Metrics to keep** | Metric names, one to a line, with `*` and `?` for anything. Leave it empty for everything, up to 2,000 series from each page |
| **Signing in** | A username and password, for a page that asks for them |

What's read is charted and named exactly as it is for a page an agent reads, which
[OpenMetrics](openmetrics.md#whats-reported) describes. A host can have up to 16
pages, and two of them can't have the same name.

## Checks

A check tries reaching something: a website, a port, a certificate, a name in DNS or
a ping. Press **Add check** under **Checks** on the host's page, or choose the host
on any check's form. The check's results are the host's, so its charts are on the
host's metrics page and an alert about it names the host.

A check doesn't have to be about a host. One left on **MaxNines server** is the
server's own, as every check was before hosts could have them, and those are all
listed on the Checks page with the rest.

## Online and offline

A host with no agent is online while any of its pages answers or any of its checks
passes, so the built-in **Host offline** rule alerts once nothing has for a minute.
A single page or check that fails while others carry on is an alert of its own
instead, on **OpenMetrics page answering** or **Checks passing**. A host with no pages or
checks, or with all of them turned off, is neither online nor offline, and nothing
alerts about it.

## Passwords

A page's password can be given two ways:

- **Typed in.** It's kept in the server's database and never shown again, on any
  page or through the API. Leaving the box empty when editing keeps the one saved.
- **From an environment variable** of the server, by name. The server reads it each
  time it reads the page, so the password is never in the database, and changing it
  needs no more than restarting the server with the new value. If the variable
  isn't set, the page counts as not answering, and says so.

The variable's name has to start with `MAXNINES_SECRET_`, such as
`MAXNINES_SECRET_ORDERS_DB`. Whoever adds a page chooses where its password is sent,
so without that rule anyone who can add one could have the server send them anything
in its environment. This way only what you've set aside can go anywhere.

A password sent to an `http://` page crosses the network in the clear, so use
`https://` for anything not on the server's own host or a network you trust.

## What they don't have

There's no agent, so there are no facts, no config rules, no actions, and no checks
on the host's clock or services. Filters that pick hosts by their facts don't match
them, though one can still be picked by its name or ID.

Deleting a host without an agent takes one step, as there's no agent to revoke
first, and removes its pages, checks, metrics and alerts for good.
