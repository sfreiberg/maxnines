# Actions API

An action is something a host's agent can be asked to run, whose output comes back
and is kept: listing the busiest processes, saying where a disk's space is going, or
restarting a service. Some are built into the agent, and only look. The rest are
commands in the agent's own config file, which is the only place one can be added,
so the server can never make a host run something new. See [actions](alerts.md#actions).

A run looks like this, with `outcome` empty until the agent answers:

| Field | Description |
| --- | --- |
| `id` | The run |
| `host_id` | The host it ran on |
| `alert_id` | The alert it ran for, or `null` for one a person started |
| `action` | The action's name |
| `run_on` | `first`, `warning` or `critical` for an alert's, and `manual` for a person's |
| `variables` | What it was given, by name |
| `requested_by` | Who asked, for one a person started |
| `requested_ms`, `finished_ms` | When it was asked for, and when the answer came |
| `timeout_secs` | How long it was given |
| `outcome` | `succeeded`, `failed`, `timed_out`, `not_defined` if the host has no such action, or `refused` if it wasn't run, as when the host isn't connected |
| `exit_code` | What a command exited with |
| `error` | Why, when the outcome alone doesn't say |
| `output` | What it printed, to standard output and then standard error, up to 64 KiB. Treat it as text from the host |
| `truncated` | Whether it printed more than is kept |
| `duration_ms` | How long it took on the host |

## List a host's actions

`GET /api/v1/hosts/{id}/actions`

What the host's agent can be asked to run, each with the `variables` it has to be
given, and the host's last 100 runs, newest first.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/hosts/1b4c7c1d9e0e210a2cb0efd8489b9b8c/actions"
```

```json
{
  "available": [
    { "name": "disk_space", "variables": ["disk"] },
    { "name": "restart_nginx", "variables": [] },
    { "name": "top_cpu", "variables": [] }
  ],
  "runs": []
}
```

## Run an action on a host

`POST /api/v1/hosts/{id}/actions`

Needs the responder role. Takes the `action`, the `variables` it needs, and optionally
`timeout_secs`, from 1 to 600, 30 if left out. Returns `201` with the run, which is
usually still waiting: read it again for how it went. A run that can't be asked for
comes back already finished, saying why.

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"action": "disk_space", "variables": {"disk": "/var"}, "timeout_secs": 120}' \
  "$MAXNINES_URL/api/v1/hosts/1b4c7c1d9e0e210a2cb0efd8489b9b8c/actions"
```

## Get an action run

`GET /api/v1/action-runs/{id}`

## List an alert's action runs

`GET /api/v1/alerts/{id}/actions`

The runs an alert's rule asked for, oldest first.
