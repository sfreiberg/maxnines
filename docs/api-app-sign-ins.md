# Signing in apps

The command line and MaxNines Desktop, for Mac, Windows and Linux, sign in through the
browser instead of asking for an API key, and so do AI assistants connecting to the
[MCP server](mcp.md). The person approves the app on a MaxNines page, signed in however
they sign in to the pages, and the app gets tokens that act as them with at most the
role they chose. Scripts and CI jobs, with nobody to approve them, use
[API keys](api-keys.md).

It's standard OAuth 2.0 for native apps, with MaxNines as its own authorization server:
the authorization code flow with PKCE and a loopback redirect
([RFC 8252](https://www.rfc-editor.org/rfc/rfc8252),
[RFC 7636](https://www.rfc-editor.org/rfc/rfc7636)), and the device flow for machines
without a browser ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)). Apps on the web
name themselves with a [client metadata document](#apps-on-the-web).

| Token | Lasts | Prefix |
| --- | --- | --- |
| Access token | 1 hour | `mxa_` |
| Refresh token | 90 days from when it was last used | `mxr_` |

Send the access token like a key: `Authorization: Bearer mxa_…`. Before it runs out, or
when a request gives `401`, swap the refresh token for new tokens. Each swap gives a
new refresh token and the old one stops working. If an old one is used again more
than a minute after it was swapped, it's been copied, and the whole sign in is revoked.
The minute counts from the swap, however often the old one is used in it. So an app
should keep only the newest, refresh once at a time, and when an answer doesn't arrive,
try again within the minute.

A signed-in app can do what its role allows, with two exceptions, which apply to API
keys too: it can't make API keys, and it can't approve another app. Only a person
signed in to the pages in a browser can do those, so neither an app nor an API key can
leave behind something that would outlast being revoked.

Each app says what it is with a `client_id`. These are MaxNines' own, which the
approval page and Signed-in apps show by name:

| `client_id` | App |
| --- | --- |
| `maxnines-cli` | The command line |
| `maxnines-desktop-mac` | MaxNines Desktop for Mac, a menu bar app |
| `maxnines-desktop-windows` | MaxNines Desktop for Windows, a notification area app |
| `maxnines-desktop-linux` | MaxNines Desktop for Linux, a tray app |

Any other app, such as your own script, can sign in through the browser with an ID of
its own: up to 64 lowercase letters, digits, dots, dashes and underscores, starting
with a letter or digit, such as `deploy-bot`. As nothing proves what an app is, the
approval page warns that it isn't one of MaxNines' own, and Signed-in apps and the
audit log show it as `deploy-bot (not one of MaxNines' own)`. The browser only ever
answers on the computer the person is at, so such an app can't be signed in from
anywhere else. Signing in from another device is only for MaxNines' own apps: with
nothing tying it to the person's computer, it's the one someone could be talked into
approving for a stranger, so other IDs get `401` with `invalid_client`.

### Apps on the web

An app that isn't on the person's computer, such as Claude or ChatGPT connecting to the
[MCP server](mcp.md), uses as its `client_id` the `https://` address of a JSON
document describing it, a client metadata document. MaxNines reads it when the
approval page opens, and keeps it for 5 minutes. It has to:

- be at an `https://` address with a path, of up to 255 characters, and be answered
  there directly, within 5 seconds, without a redirect;
- give that same address as its `client_id`;
- list where the app may be sent back to in `redirect_uris`: `https://` addresses,
  which have to match exactly, or `http://127.0.0.1` or `http://localhost` ones, which
  match on any port.

```json
{
  "client_id": "https://assistant.example.com/oauth/client.json",
  "client_name": "Example Assistant",
  "redirect_uris": ["https://assistant.example.com/oauth/callback"]
}
```

The approval page shows `client_name` with the host the document is on, and where
the person will be sent back to, and says it isn't one of MaxNines' own. Signed-in
apps and the audit log show it as `Example Assistant (assistant.example.com)`. Apps
don't register first, and there's no client secret: like the others, they prove
themselves with PKCE.

### Finding out how to sign in

`GET /.well-known/oauth-authorization-server`

Open to all, as [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) has it, for apps
that find out for themselves:

```json
{
  "issuer": "https://monitor.example.com",
  "authorization_endpoint": "https://monitor.example.com/oauth/authorize",
  "token_endpoint": "https://monitor.example.com/oauth/token",
  "revocation_endpoint": "https://monitor.example.com/oauth/revoke",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none"],
  "revocation_endpoint_auth_methods_supported": ["none"],
  "client_id_metadata_document_supported": true,
  "authorization_response_iss_parameter_supported": true
}
```

The `issuer` is the server's `public_url` as a web address, such as `https://` for
`wss://`, or without one, the address the request was made to over `http://`. The
[MCP server](mcp.md#how-assistants-find-out-how-to-sign-in) has its own document,
pointing here.

## Sign in through the browser

1. Make a random `code_verifier` of 43 to 128 characters, and its `code_challenge`: the
   SHA-256 of it in base64url without padding.
2. Listen on a free port of `127.0.0.1` or `localhost`. `[::1]` isn't accepted, as
   the approval page couldn't send the browser back to an IPv6 address.
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
| `device` | The computer's name, up to 100 characters, shown when approving and under Settings. Optional: one left out is `null` in the list of signed-in apps |
| `role` | `viewer`, `responder`, `editor` or `admin`: the most to offer, and what's picked to begin with. The person can choose lower, and never more than their own. Left out, any role up to theirs is offered, with Viewer picked |
| `resource` | Optional, as [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) has it: the server the tokens are for, which has to be this one, its address or its MCP server's, such as `https://monitor.example.com/mcp`. Anything else is `invalid_target` |

The person signs in if they aren't already, and chooses **Allow** or **Deny**. The
browser comes back to `redirect_uri` with `code` and `state`, or with
`error=access_denied`. Either way it has `iss`, the issuer above, as
[RFC 9207](https://www.rfc-editor.org/rfc/rfc9207) has it, so an app can check the
answer is from the server it asked. The code lasts 10 minutes and works once.

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
`invalid_grant` for a code that's wrong, used or out of date, a verifier that doesn't
match, or a person who can't sign in any more, `invalid_target` for a `resource` that
isn't this server, which `/oauth/token` takes too, and `invalid_client` (`401`) for an
app that isn't one of those above. A `500` is the server's own trouble, and worth trying
again.

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

At most 1,000 devices can be waiting at once. Beyond that, starting one is `503` with
`temporarily_unavailable`, until some run out.

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

Admins see everyone's, and everyone else only their own, newest first. Revoked and
expired ones stay listed for 90 days, then go. The [audit log](audit-log.md) keeps what
happened to them.

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
    "created_at": "2026-11-06T04:44:25.767Z",
    "last_used_at": "2026-11-06T04:44:45.797Z",
    "last_address": "192.168.0.20",
    "last_forwarded_for": null,
    "expires_at": "2027-02-04T04:44:45.797Z",
    "revoked_at": null
  }
]
```

`expires_at` is when it stops working unless it's used before then. `last_used_at` is
accurate to about a minute.

## Revoke a signed-in app

`DELETE /api/v1/app-sign-ins/{id}`

Returns `204`, or `404` for one that isn't there or isn't yours to revoke.
