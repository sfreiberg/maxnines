# OpenMetrics

Most software that can be monitored serves its numbers as a page in the Prometheus
text format, now standardised as OpenMetrics, usually at `/metrics`: web frameworks,
databases, proxies, and the many exporters written for everything else. An agent can
read those pages, so anything that already has one can be charted and alerted on with
nothing added to it.

Fill in **OpenMetrics pages** in a config rule, one address to a line, such as
`http://localhost:9100/metrics`. That turns the `openmetrics` collector on for the
hosts the rule applies to, and each agent reads its pages with every sample. A page
is usually on the agent's own host, but can be anywhere the agent can reach.

## What's reported

Each line of a page is a series, named by its page and the line as the page wrote
it:

```text
localhost:9100 node_load1
localhost:8080 http_requests_total{method="GET",code="200"}
```

A page's name is its address without `http://`, anything after a `?`, or a path
that's only `/metrics`, so `http://localhost:8080/app/metrics` is
`localhost:8080/app`. Two pages in one rule can't have the same name.

| Chart | What's in it |
| --- | --- |
| **OpenMetrics values** | Gauges and anything untyped, as the page gave them |
| **OpenMetrics rates** | Counters, as how fast they're rising each second |

- **Counters** only ever go up, so their rate is what's kept. One that goes
  backwards has started again, and counts as no change that once.
- **Histograms and summaries** report their `_sum` and `_count` as rates, which
  divide into an average. A histogram's buckets are left out, as each is a series
  of its own and they add up quickly. A summary's quantiles are kept as values.
- A value that isn't a number, or is infinite, is left out.

The charts on a host's page show the busiest few series. To follow particular ones,
put them on a [dashboard](dashboards.md) or in an alert rule, which pick series by
name with `*` and `?` for anything: `localhost:8080 http_requests_total*`.

## Keeping it small

An exporter can list thousands of series, and most are rarely looked at. An agent
keeps at most 2,000 from a rule's pages, shared equally between them, so four pages
get 500 each. Series past that are counted, not kept, and a name longer than 255
characters is counted with them.

To choose what's kept, list metric names under **OpenMetrics metrics**, with `*` and
`?` for anything:

```text
http_*
process_resident_memory_bytes
pg_stat_database_*
```

Names are matched against the metric alone, without its labels. With none listed,
everything is kept up to the limit.

## Alerting

Two more metrics are there to alert on, and aren't charted:

| Metric | What it says |
| --- | --- |
| **OpenMetrics page answering** | 1 while a page can be read, 0 when it can't, with why, such as a timeout |
| **OpenMetrics series over the limit** | How many series a page had that weren't kept |

## Pages that need signing in

Pages behind a password or a token can't be read yet. Addresses with a username or
password in them aren't accepted, so they never show up on the rules pages. Until
then, keep such a page reachable from the host itself without one, as exporters are
by default.
