# API keys

Keys can also be managed on the Settings page, and with `maxnines-server api-keys`.
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
    "created_ms": 1793940265767,
    "expires_ms": 1793943865767,
    "last_used_ms": 1793940285797,
    "revoked_ms": null
  }
]
```

`last_used_ms` is accurate to about a minute.

## Add an API key

`POST /api/v1/api-keys`

| Field | Description |
| --- | --- |
| `name` | Required. What the key is for, up to 100 characters. The key belongs to whoever owns the key making it |
| `expires_in_secs` | How long it lasts. Leave it out for a key that never expires |
| `role` | `viewer`, `responder`, `editor` or `admin`: the most it can do, up to the role of the key making it, which is what it gets if left out. More than that gives `403` |

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "Deploy job", "expires_in_secs": 3600}' \
  "$MAXNINES_URL/api/v1/api-keys"
```

```json
{
  "id": 2,
  "name": "Deploy job",
  "user_id": 1,
  "owner": "you@example.com",
  "role": "admin",
  "hint": "mxn_6ffd6467",
  "key": "mxn_6ffd6467588f1ad1cbdca9b9961ff4be70e64ef4ff330c805ee3015463c00357",
  "created_ms": 1793940286623,
  "expires_ms": 1793943886623,
  "last_used_ms": null,
  "revoked_ms": null
}
```

Save `key` now, because this is the only time it's shown.

## Revoke an API key

`DELETE /api/v1/api-keys/{id}`

Stops a key working straight away. It stays in the list, to show what existed.

```sh
curl -X DELETE -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/api-keys/2"
```
