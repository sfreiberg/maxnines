# Host readings API

What a host's newest readings say beyond its numbers, as its pages show them: its
drives, its updates, and its services. Each is what the host's collectors last sent in
the last 5 minutes, so a host with a collector off, or that hasn't been heard from,
has nothing to say about it. The numbers themselves, such as each drive's temperature
over time, are [metrics](api-hosts.md#get-a-hosts-metric) too. Each returns `404` if
there's no such host.

## Get a host's drives

`GET /api/v1/hosts/{id}/drives`

What the [Drives](collectors-smart.md) collector last read, as the host's page shows it
under **Drives**: each drive, with `healthy` saying whether it passes its own
assessment, `true`, `false`, or `null` if it doesn't say. `name` is its model and serial
number, which its series are called, or `null` for one smartctl couldn't read, which
only has its `device`. `asleep` is `true` for a drive that was asleep, so wasn't asked,
whose readings are what it last said, and `note` is what the agent noticed about it.
`problem` says why no drive could be read, with what to do about it, such as
installing smartctl, and `drives` is empty then.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/hosts/$HOST_ID/drives"
```

```json
{
  "drives": [
    {
      "name": "Samsung SSD 980 PRO S5GX",
      "device": "/dev/nvme0",
      "healthy": true,
      "temperature_celsius": 41.0,
      "asleep": false,
      "note": null
    }
  ],
  "problem": null
}
```

## Get a host's updates

`GET /api/v1/hosts/{id}/updates`

What the [Updates](collectors-updates.md) collector last found, as the host's page
shows it under **Updates**: how many updates are `pending`, how many of them are for
`security` and how many installed packages have known vulnerabilities, where the system
says, whether a reboot is required, and how long since the package lists were
refreshed. `problem` says why nothing could be asked, with what to do about it, and the
numbers are all `null` then. `note` is what went wrong with part of it. The answer is
`null` for a host that hasn't read its updates.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/hosts/$HOST_ID/updates"
```

```json
{
  "manager": "apt",
  "pending": 12,
  "security": 3,
  "vulnerable": null,
  "reboot_required": true,
  "lists_age_secs": 7200,
  "problem": null,
  "note": null
}
```

## Get a host's services

`GET /api/v1/hosts/{id}/services`

`watched` is each service the [services](collectors-operating-system.md#services)
collector watches, as the host's metrics page shows them under **Watched services**,
with `state`, the service manager's word for it, when it isn't running. `failed` is
the services that stopped with an error, as the host's page shows them under **Failed
services**: how many, and their names, up to the 32 the agent names, with `unnamed`
counting the rest. It's `null` on a system with no such state, such as macOS and
FreeBSD.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/hosts/$HOST_ID/services"
```

```json
{
  "watched": [
    { "name": "nginx", "running": true, "state": null },
    { "name": "postgresql", "running": false, "state": "failed" }
  ],
  "failed": { "count": 1, "names": ["postgresql.service"], "unnamed": 0 }
}
```
