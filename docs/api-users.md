# Users API

Everyone who can sign in to the web pages. Nobody can sign up, so people are only
added here, on the Settings page, or with `maxnines-server users`. Passwords can't
be read or set through the API: someone new gets a link to set their own.

## List users

`GET /api/v1/users`

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" "$MAXNINES_URL/api/v1/users"
```

```json
[
  {
    "id": 1,
    "email": "sam@example.com",
    "name": "Sam",
    "theme": "carbon",
    "time_zone": "Europe/London",
    "has_password": true,
    "created_ms": 1793977895109,
    "last_sign_in_ms": 1793978000000,
    "disabled_ms": null
  }
]
```

## Add a user

`POST /api/v1/users`

Takes an `email`, a `name`, and a `role`: `viewer`, the default, `responder`, `editor`
or `admin`. The answer holds a link for them to set a password. It works once, lasts
7 days and can't be seen again, so pass it on.

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"email": "alex@example.com", "name": "Alex"}' \
  "$MAXNINES_URL/api/v1/users"
```

```json
{
  "user": {
    "id": 2,
    "email": "alex@example.com",
    "name": "Alex",
    "role": "viewer",
    "theme": "carbon",
    "time_zone": "UTC",
    "has_password": false,
    "two_factor": false,
    "created_ms": 1793977895109,
    "last_sign_in_ms": null,
    "disabled_ms": null
  },
  "setup_url": "http://localhost:9000/setup/8f3a…"
}
```

An address that's already in use gives `409`.

## Get a user

`GET /api/v1/users/{id}`

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" "$MAXNINES_URL/api/v1/users/2"
```

## Update a user's role, theme or time zone

`PUT /api/v1/users/{id}`

Give any of them. `role` is `viewer`, `responder`, `editor` or `admin`, and taking it
from the last admin gives `409`. `theme` can be `carbon`, `midnight`, `dusk`, `paper`, `contrast`
or `system`. `time_zone` is a name from the time zone database, like
`America/New_York`, and is what the pages show times in. Everyone starts on `UTC`.

```sh
curl -X PUT -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"theme": "paper", "time_zone": "America/New_York"}' \
  "$MAXNINES_URL/api/v1/users/2"
```

## Reset a user's two-factor sign-in

`POST /api/v1/users/{id}/two-factor/reset`

Turns off [two-factor sign-in](users.md#two-factor-sign-in) for someone who's lost
their phone and their recovery codes, so they can sign in with their password and set
it up again. A user's `two_factor` says whether they have it on. Setting it up needs
the person and their phone, so it's only done on their profile page.

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/users/2/two-factor/reset"
```

## Require two-factor for everyone

`GET /api/v1/users/two-factor`

`PUT /api/v1/users/two-factor`

Whether everyone has to set up two-factor before using the pages, as
`{"required": true}`. Requiring it gives `409` unless the key's owner has two-factor
themselves. API keys keep working either way.

```sh
curl -X PUT -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"required": true}' \
  "$MAXNINES_URL/api/v1/users/two-factor"
```

## Add a setup link

`POST /api/v1/users/{id}/setup-link`

This is how a forgotten password is reset. It replaces any earlier link, and their
current password keeps working until the new link is used.

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/users/2/setup-link"
```

```json
{ "setup_url": "http://localhost:9000/setup/2c91…" }
```

## Enable a user

`POST /api/v1/users/{id}/enable`

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/users/2/enable"
```

## Disable a user

`POST /api/v1/users/{id}/disable`

This stops them signing in and signs them out straight away. Disabling the last
enabled user gives `409`, so someone can always sign in.

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/users/2/disable"
```

## Delete a user

`DELETE /api/v1/users/{id}`

Only a disabled user can be deleted. Anyone else gives `409`.

```sh
curl -X DELETE -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/users/2"
```
