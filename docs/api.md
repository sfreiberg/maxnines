# MaxNines API

Everything the web pages can see and do is available as JSON. The API shares the
server's one port, under `/api/v1`.

## Getting started

Make a key, then send it as a bearer token with every request:

```sh
export MAXNINES_URL=http://localhost:9000
export MAXNINES_API_KEY=$(maxnines-server api-keys create "My script" --user you@example.com --expires-in 30d)

curl -H "Authorization: Bearer $MAXNINES_API_KEY" "$MAXNINES_URL/api/v1/hosts"
```

The examples below use those two variables. Where one needs a host, it uses
`$HOST_ID`, which you can set like this:

```sh
export HOST_ID=$(curl -s -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/hosts" | jq -r '.[0].id')
```

## How the API works

**Authentication.** Every request needs an `Authorization: Bearer` header holding an
API key. Each key belongs to a user and acts as them: what it does is recorded in the
[audit log](audit-log.md) as that person, via the key, and it stops working while
they're disabled. Give each tool its own key. Without a valid key, the answer is
`401`.

**Roles.** A key has a [role](users.md#roles), its owner's or lower, and can do
what that role can: reading needs a viewer, acknowledging and silencing a responder,
changing the setup an editor, and users, the audit log and deleting hosts an admin. Anything else gives `403`.
Give each key the lowest role that does its job, as described under
[API keys and roles](users.md#api-keys-and-roles): an editor key, not an admin one, for
a tool that manages rules. Keys are made on the Settings page, through this API, or with
`maxnines-server api-keys create --user <email>`, which writes to the main database
directly, so it works while the server is stopped. For a script that isn't anyone's,
add a user for it, such as `ci@example.com`, which never needs a password.

**Encryption.** Use the server's own TLS, either your certificates or automatic ones
through ACME, or put it behind a proxy that terminates TLS. Anywhere beyond one
host, keys shouldn't cross the network in the clear.

**Requests and responses.** Requests with a body are JSON, with
`Content-Type: application/json`. Responses are JSON unless noted.

**Times** are milliseconds since the Unix epoch, in fields ending in `_ms`.

**Versions.** A change that would break a client goes in a new version, such as
`/api/v2`. Adding a field isn't a breaking change, so ignore fields you don't know.

**Lists** return everything at once, except where noted. The API isn't rate limited.

### Status codes

| Status | Meaning |
| --- | --- |
| `200` | It worked, and the answer is in the body |
| `201` | It was created, and the body holds its `id` |
| `204` | It worked, and there's nothing to return |
| `400` | The request couldn't be understood, such as a filter that can't be read |
| `401` | The key is missing, wrong, revoked or expired, or its owner is disabled |
| `403` | The key's role doesn't allow it. The `error` says which role it needs |
| `404` | There's nothing at that address, or no such item |
| `409` | It clashes with what's there, such as a user with that email already, or disabling the last admin |
| `422` | The request was understood but refused, such as an invalid rule |
| `500` | Something went wrong on the server |
| `502` | A test notification couldn't be delivered |

Where there's an explanation, it's in an `error` field:

```json
{ "error": "A key needs a name." }
```

## What's in the API

Each part has a page of its own:

| Part | What it covers |
| --- | --- |
| [Hosts](api-hosts.md) | The hosts the server knows, their facts and config, and approving, revoking and deleting them |
| [Metrics pages](api-metrics-pages.md) | The OpenMetrics pages the server reads for hosts without an agent |
| [Filters](api-filters.md) | How to pick hosts by their facts, as the Hosts list does |
| [Metrics](api-metrics.md) | The catalog of metrics, and current values |
| [Config rules](api-config-rules.md) | The rules that decide what each agent collects |
| [Alerts](api-alerts.md) | What is firing and what has ended, and acknowledging |
| [Actions](api-actions.md) | What a host can run, running it, and what it printed |
| [Silences](api-silences.md) | Keeping notifications back for a while |
| [Annotations](api-annotations.md) | Deploys and notes marked on charts, and a host's events |
| [Maintenance windows](api-maintenance-windows.md) | Silences that come round on a schedule |
| [Alert rules](api-alert-rules.md) | What to alert on, and who to tell |
| [Notification channels](api-notification-channels.md) | Where notifications go, and testing them |
| [Remote checks](api-remote-checks.md) | Checks the server runs against other sites |
| [Map](api-map.md) | Where hosts are, and the rules that place them |
| [Server](api-server.md) | The server's own status and history |
| [Health](api-health.md) | Whether the server is up, for load balancers and uptime monitors |
| [Calculations](api-calculations.md) | One number from many hosts, as dashboards and alert rules use |
| [Dashboards](api-dashboards.md) | Dashboards, their widgets and variables |
| [API keys](api-keys.md) | Listing, adding and revoking keys |
| [Users](api-users.md) | People, their roles, and two-factor sign-in |
| [Audit log](api-audit-log.md) | Who changed what, and sign-ins |
