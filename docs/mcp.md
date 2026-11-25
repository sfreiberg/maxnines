# MCP server

MaxNines has an MCP server built in, so an AI assistant such as Claude Code, Claude or
ChatGPT can look at your hosts, alerts and metrics, and for a responder, acknowledge
alerts and silence them. Ask it things like "which hosts are unhealthy?", "what was
db-1's CPU like this morning?" or "silence the disk alerts on web-3 for an hour while
I deploy".

It's at `/mcp` on the server's usual address and port, such as
`https://maxnines.example.com/mcp`. It speaks MCP's Streamable HTTP transport.

## Before you start

Set `public_url` in the server's config, as [HTTPS](https.md) describes, especially
behind a proxy that handles HTTPS. The server gives assistants its address from it, as
`https://` for `wss://`, and they check that every address they're given matches.
Without it, the server uses the address the assistant asked for, over plain HTTP.

Where the assistant connects from matters:

- **Claude Code** runs on your computer, so it only needs to reach the server from
  there, as your browser does.
- **Claude** (claude.ai and Claude Desktop) and **ChatGPT** connect from Anthropic's
  and OpenAI's own servers, even when you use their desktop apps. The server has to be
  reachable from the internet over HTTPS, with a certificate from a public authority,
  such as an [automatic one](https.md#automatic-certificates). A server only on your
  own network, or with a private certificate, won't work with them.

## Signing in

An assistant signs in one of two ways, and either way acts as you, with at most the
[role](users.md#roles) you give it:

- **An API key.** Make one under **Settings > API keys** with the role it should have,
  and give it to the assistant as a header. This suits Claude Code.
- **Through the browser.** The assistant opens a MaxNines page, you sign in as usual,
  check which app it is and where it'll send you back to, choose the role it gets, and
  choose **Allow**. Claude and ChatGPT sign in this way, and Claude Code can too. Each
  is then listed under **Settings > Signed-in apps** by its name and where it's from,
  such as "Claude (claude.ai)", where you can revoke it.

Choose the lowest role that does what you want: Viewer to ask questions, Responder to
also let it acknowledge and silence alerts.

What an assistant does is recorded in the [audit log](audit-log.md) as you, marked as
made over MCP, such as "via API key Claude Code over MCP".

## Claude Code

With an API key:

```sh
claude mcp add --transport http maxnines https://maxnines.example.com/mcp \
  --header "Authorization: Bearer mxn_…"
```

Or through the browser, leaving the header out:

```sh
claude mcp add --transport http maxnines https://maxnines.example.com/mcp
```

Then type `/mcp` in Claude Code, choose **maxnines** and **Authenticate**. Your browser
opens the MaxNines page to allow it.

Add `--scope user` to use it in every project, rather than only the one you're in.

## Claude and Claude Desktop

1. In Claude, open **Settings > Connectors** and choose **Add custom connector**.
2. Give it a name, such as MaxNines, and the URL, `https://maxnines.example.com/mcp`.
   Leave the advanced settings empty.
3. Choose **Connect**. MaxNines opens; sign in if you need to, choose the role, and
   choose **Allow**.

A connector added on claude.ai works in Claude Desktop and Claude's mobile apps too.
In a Team or Enterprise organisation, an owner may have to add it first.

## ChatGPT

1. In ChatGPT, open **Settings > Apps & Connectors > Advanced settings** and turn on
   **Developer mode**.
2. Back in **Apps & Connectors**, choose **Create**. Give it a name, such as MaxNines,
   the URL, `https://maxnines.example.com/mcp`, and **OAuth** for authentication.
3. Choose **Create**. MaxNines opens; sign in if you need to, choose the role, and
   choose **Allow**.

In a chat, turn on developer mode and the connector from the tools menu to use it.

## Tools

An assistant is only shown the tools its role can use. Each one does what the
[API](api.md) does, with the same checks.

Every role, from Viewer up:

| Tool | What it does |
| --- | --- |
| `list_hosts` | The hosts, with whether each is online and its health, narrowed with a [filter](api-filters.md) as on the Hosts page |
| `get_host` | One host, with the facts its agent reports and what its newest readings say: its drives, RAID arrays and ZFS pools, updates, time sync, and watched and failed services |
| `list_alerts` | The alerts open now, then the most recent that have ended, for every host or one |
| `get_alert` | One alert, with the readings of what it watches around when it fired |
| `list_metrics` | The metrics MaxNines can read, with their units |
| `get_host_metric` | A host's readings of one metric over a time range |
| `query_metrics` | A metric across hosts, calculated and grouped, as [calculations](api-calculations.md) are |
| `list_checks` | The checks the server runs, and how each last went |
| `list_silences` | The silences now, then the most recent that have ended |
| `list_host_events` | Everything that happened to one host: annotations, restarts, config changes, alerts and updates |
| `list_annotations` | Annotations across all hosts |

Responders and up can also:

| Tool | What it does |
| --- | --- |
| `acknowledge_alert` | Acknowledges an open alert |
| `create_silence` | [Silences](alerts.md#silences) alerts for a while, by rule, host filter or series |
| `end_silence` | Ends a silence |

Editors and admins get the same tools as responders.

Lists give back at most 100 rows, and readings at most 10 series and 1,000 points, so
answers stay short enough for an assistant to read. Each says when it was cut short,
and the assistant can narrow what it asks for.

## How assistants find out how to sign in

For an assistant, or anything else, that signs in through the browser by itself:

- `/mcp` answers `401` without a working token, with a `WWW-Authenticate` header
  pointing at `/.well-known/oauth-protected-resource/mcp`.
- That says the MCP server is at `/mcp`, and that MaxNines signs people in to it.
- `/.well-known/oauth-authorization-server` says how. Apps don't register: each names
  itself with the address of a client metadata document describing it. See
  [Signing in apps](api-app-sign-ins.md#apps-on-the-web).
