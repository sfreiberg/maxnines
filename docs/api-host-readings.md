# Host readings API

What a host's newest readings say beyond its numbers, as its pages show them: its
drives, its RAID arrays and ZFS pools, its updates, and its services. Each is what the
host's collectors last sent in the last 5 minutes, so a host with a collector off, or
that hasn't been heard from, has nothing to say about it. The numbers themselves, such as each drive's temperature
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

## Get a host's RAID arrays and ZFS pools

`GET /api/v1/hosts/{id}/raid`

What the [RAID and ZFS](collectors-raid.md) collector last read, as the host's page
shows it under **RAID and ZFS**: each Linux software RAID array, ZFS pool, Storage
Spaces virtual disk and AppleRAID set, by its own `name`. `kind` is `md`, `zfs`,
`storage_spaces` or `appleraid`, `level` how it's laid out in its system's words, such
as `raid1`, `raidz2` or `Mirror`, and `state` its system's own word for how it is.
`degraded`, `failed` and `rebuilding` say what the built-in alerts go by, with how far
a rebuild or scrub has got and how fast it goes while one runs. `devices` leaves out
spares and caches, and `not_working` names those of them that aren't working, with
what's wrong with each. `note` is what the system says is wrong, such as zpool's
status. The fields from `size_bytes` on are only for ZFS pools, and `null` for the
rest. `problems` says why some arrays couldn't be read, with what to do about it,
such as letting the agent run zpool. A host with no arrays or pools has both lists
empty.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/hosts/$HOST_ID/raid"
```

```json
{
  "arrays": [
    {
      "name": "md0",
      "kind": "md",
      "level": "raid1",
      "state": "recovering",
      "degraded": true,
      "failed": false,
      "rebuilding": true,
      "rebuild_percent": 3.5,
      "scrub_percent": null,
      "speed_bytes_per_sec": 2359296.0,
      "devices": 2,
      "working_devices": 1,
      "not_working": "1 missing",
      "note": null,
      "size_bytes": null,
      "used_percent": null,
      "fragmentation_percent": null,
      "read_errors": null,
      "write_errors": null,
      "checksum_errors": null,
      "data_errors": null,
      "scrub_age_secs": null,
      "scrub_repaired_bytes": null,
      "scrub_errors": null
    },
    {
      "name": "tank",
      "kind": "zfs",
      "level": "mirror",
      "state": "ONLINE",
      "degraded": false,
      "failed": false,
      "rebuilding": false,
      "rebuild_percent": null,
      "scrub_percent": null,
      "speed_bytes_per_sec": null,
      "devices": 3,
      "working_devices": 3,
      "not_working": null,
      "note": "One or more devices has experienced an unrecoverable error. An attempt was made to correct the error. Applications are unaffected.",
      "size_bytes": 1006632960,
      "used_percent": 86.0,
      "fragmentation_percent": 22.0,
      "read_errors": 0,
      "write_errors": 0,
      "checksum_errors": 3209,
      "data_errors": 0,
      "scrub_age_secs": 3600,
      "scrub_repaired_bytes": 407896064,
      "scrub_errors": 0
    }
  ],
  "problems": []
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
