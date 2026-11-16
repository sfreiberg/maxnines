# Signing in apps

The command line, the Mac menu bar app and the Windows app sign in through the
browser instead of asking for an API key. The person approves the app on a MaxNines
page, signed in however they sign in to the pages, and the app gets tokens that act as
them with at most the role they chose. Scripts and CI jobs, with nobody to approve
them, use [API keys](api-keys.md).

It's standard OAuth 2.0 for native apps, with MaxNines as its own authorization server:
the authorization code flow with PKCE and a loopback redirect
([RFC 8252](https://www.rfc-editor.org/rfc/rfc8252),
[RFC 7636](https://www.rfc-editor.org/rfc/rfc7636)), and the device flow for machines
without a browser ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)).

| Token | Lasts | Prefix |
| --- | --- | --- |
| Access token | 1 hour | `mxa_` |
| Refresh token | 90 days from when it was last used | `mxr_` |

Send the access token like a key: `Authorization: Bearer mxa_…`. Before it runs out, or
when a request gives `401`, swap the refresh token for new tokens. Each swap gives a
new refresh token and the old one stops working. If an old one is used again more
than a minute after it was swapped, it's been copied, and the whole sign in is revoked.
So an app should keep only the newest, and refresh once at a time.

Only these apps can sign in, as `client_id`:

| `client_id` | App |
| --- | --- |
| `maxnines-cli` | The command line |
| `maxnines-menubar` | The Mac menu bar app |
| `maxnines-tray` | The Windows notification area app |

## Sign in through the browser

1. Make a random `code_verifier` of 43 to 128 characters, and its `code_challenge`: the
   SHA-256 of it in base64url without padding.
2. Listen on a free port of `127.0.0.1` or `[::1]`. `localhost` isn't accepted.
3. Open the browser at `/oauth/authorize`:

```text
$MAXNINES_URL/oauth/authorize?response_type=code&client_id=maxnines-cli
  &redirect_uri=http://127.0.0.1:53682/callback&code_challenge=E9Melhoa2Owv…
  &code_challenge_method=S256&state=af0ifjsldkj&device=sam-laptop&role=responder
```

| Parameter | Description |
| --- | --- |
| `redirect_uri` | Required. Where the answer comes back, on this computer |
| `code_challenge`, `code_challenge_method` | Required. The challenge, and `S256` |
| `state` | Sent back unchanged, to check the answer is to this request |
| `device` | The computer's name, up to 100 characters, shown when approving and under Settings |
| `role` | `viewer`, `responder`, `editor` or `admin`: what to offer. The person can choose lower, and never more than their own |

The person signs in if they aren't already, and chooses **Allow** or **Deny**. The
browser comes back to `redirect_uri` with `code` and `state`, or with
`error=access_denied`. The code lasts 10 minutes and works once.

4. Swap the code for tokens:

`POST /oauth/token`

```sh
curl -X POST "$MAXNINES_URL/oauth/token" \
  -d grant_type=authorization_code -d client_id=maxnines-cli \
  -d code=mxc_… -d redirect_uri=http://127.0.0.1:53682/callback \
  -d code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

```json
{
  "access_token": "mxa_…",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "mxr_…",
  "refresh_token_expires_in": 7776000,
  "role": "responder",
  "user": "you@example.com",
  "sign_in_id": 4
}
```

Errors are `400` with `error` and `error_description`, as OAuth words them:
`invalid_grant` for a code that's wrong, used or out of date, or a verifier that
doesn't match, and `invalid_client` (`401`) for an app that isn't one of those above.

## Sign in from another device

For a machine with no browser, such as a server reached over SSH:

`POST /oauth/device`

```sh
curl -X POST "$MAXNINES_URL/oauth/device" \
  -d client_id=maxnines-cli -d device=build-box -d role=viewer
```

```json
{
  "device_code": "mxd_…",
  "user_code": "BCDF-GHJK",
  "verification_uri": "https://monitor.example.com/device",
  "verification_uri_complete": "https://monitor.example.com/device?code=BCDF-GHJK",
  "expires_in": 600,
  "interval": 5
}
```

Show the person the address and the code. They open it anywhere, sign in, check the
code and choose **Allow**. Meanwhile, ask every `interval` seconds:

```sh
curl -X POST "$MAXNINES_URL/oauth/token" \
  -d grant_type=urn:ietf:params:oauth:grant-type:device_code \
  -d client_id=maxnines-cli -d device_code=mxd_…
```

Until they answer, it's `400` with `authorization_pending`, or `slow_down` for asking
too often, which adds 5 seconds to the interval. Then it's the tokens, or
`access_denied`, or `expired_token` after 10 minutes.

## Refresh the tokens

```sh
curl -X POST "$MAXNINES_URL/oauth/token" \
  -d grant_type=refresh_token -d client_id=maxnines-cli -d refresh_token=mxr_…
```

The answer is the same as when signing in. `invalid_grant` means signing in again.

## Sign an app out

`POST /oauth/revoke`

```sh
curl -X POST "$MAXNINES_URL/oauth/revoke" \
  -d client_id=maxnines-cli -d token=mxr_…
```

Either token works. It's always `200`, whether or not the token was real.

## List signed-in apps

`GET /api/v1/app-sign-ins`

Admins see everyone's, and everyone else only their own, newest first, including
revoked and expired ones.

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" "$MAXNINES_URL/api/v1/app-sign-ins"
```

```json
[
  {
    "id": 4,
    "user_id": 1,
    "owner": "you@example.com",
    "client_id": "maxnines-cli",
    "app": "MaxNines command line",
    "device": "sam-laptop",
    "role": "responder",
    "created_ms": 1793940265767,
    "last_used_ms": 1793940285797,
    "expires_ms": 1801716285797,
    "revoked_ms": null
  }
]
```

`expires_ms` is when it stops working unless it's used before then. `last_used_ms` is
accurate to about a minute.

## Revoke a signed-in app

`DELETE /api/v1/app-sign-ins/{id}`

Returns `204`, or `404` for one that isn't there or isn't yours to revoke.
