# Proxies

Proxies in front of the server, and which are trusted to pass on people's addresses.
Admins only. See [Proxies](proxies.md) for how it works.

## List

`GET /api/v1/proxies`

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" "$MAXNINES_URL/api/v1/proxies"
```

```json
{
  "configured": ["127.0.0.0/8", "::1/128"],
  "from_config": false,
  "decisions": [
    { "id": 1, "address": "10.0.1.0/24", "trusted": true, "created_ms": 1793940265767 },
    { "id": 2, "address": "cloudflare", "trusted": true, "created_ms": 1793940285797 }
  ],
  "waiting": [
    {
      "address": "10.0.2.14",
      "forwarded_for": "203.0.113.7",
      "first_ms": 1793940265767,
      "last_ms": 1793940285797,
      "requests": 12,
      "people": ["you@example.com"],
      "kind": "private",
      "provider": null,
      "suggested": "10.0.2.0/24"
    }
  ]
}
```

| Field | Meaning |
| --- | --- |
| `configured` | What `server.hcl` trusts: `trusted_proxies`, or this machine when it isn't set |
| `from_config` | Whether `configured` is from `trusted_proxies` |
| `decisions` | What admins decided. `address` is an address, a range, or a provider: `cloudflare` or `google-cloud` |
| `waiting` | Untrusted addresses that passed on someone's address, most recent first |
| `waiting[].forwarded_for` | The last address it said it was passing on |
| `waiting[].people` | Who came through it, the first five |
| `waiting[].kind` | `loopback`, `private`, `provider` or `public` |
| `waiting[].suggested` | What trusting it would cover |

`waiting` is kept in memory, so it starts empty when the server restarts.

## Decide

`POST /api/v1/proxies`

Trusts an address, range or provider, or says it's not a proxy, changing any earlier
decision about the same one. Returns `201` with the decision, or `422` for something
that isn't an address, range or provider, or a range wider than `/8` (`/32` for IPv6).

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"address": "10.0.1.0/24", "trusted": true}' \
  "$MAXNINES_URL/api/v1/proxies"
```

## Delete a decision

`DELETE /api/v1/proxies/{id}`

Returns `204`, or `404` for one that isn't there.
