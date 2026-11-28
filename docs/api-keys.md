# API keys

Keys are made by a person, on the Settings page or with `maxnines-server api-keys
create`. The API lists and revokes them, but never makes one: a key or an app that
could make keys could leave one behind that goes on working after it's revoked.
Only a hash of each key is kept, so a key can only be seen when it's created. `hint` is
the start of it, to tell keys apart. Each key acts as its owner, `user_id`, whose
email address is `owner`, with at most its `role`. Deleting a user deletes their keys.
Admins see and revoke everyone's keys, and everyone else only their own. Give each key
the [lowest role](users.md#api-keys-and-roles) that does its job.

## List API keys

`GET /api/v1/api-keys`

Every key, newest first, including revoked and expired ones.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" "$MAXNINES_URL/api/v1/api-keys"
```

```json
[
  {
    "id": 1,
    "name": "My script",
    "user_id": 1,
    "owner": "you@example.com",
    "role": "admin",
    "hint": "mxn_9689a740",
    "created_at": "2026-11-06T04:44:25.767Z",
    "expires_at": "2026-11-06T05:44:25.767Z",
    "last_used_at": "2026-11-06T04:44:45.797Z",
    "last_address": "192.168.0.20",
    "last_forwarded_for": null,
    "revoked_at": null
  }
]
```

`last_used_at` is accurate to about a minute. `last_address` is where it was last used
from, and `last_forwarded_for` what a proxy that isn't trusted said, unconfirmed.

## Add an API key

`POST /api/v1/api-keys` always answers `403`, as only a person makes keys, on the
Settings page or with `maxnines-server api-keys create`.

## Revoke an API key

`DELETE /api/v1/api-keys/{id}`

Stops a key working straight away. It stays in the list, to show what existed.

```sh
curl -X DELETE -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/api-keys/2"
```
