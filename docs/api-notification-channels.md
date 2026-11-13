# Notification channels API

Where alerts go. Webhook addresses, custom webhook headers, Teams workflow URLs, PagerDuty keys, AlertOps and SIGNL4 URLs, Slack
and Telegram tokens, mail server passwords and Resend API keys can be set but never read back, so
`target_preview` only shows enough to recognize a channel.

| Field | Description |
| --- | --- |
| `name` | Required |
| `kind` | Required. `webhook`, `custom_webhook`, `email`, `resend`, `discord`, `slack`, `teams`, `pagerduty`, `alertops`, `signl4` or `telegram` |
| `target` | Required. A webhook's address, a Teams workflow's URL, email addresses separated by commas for email and Resend, a Slack channel, a PagerDuty integration key, the URL from AlertOps or SIGNL4, or a Telegram chat ID such as `-1001234567890` or `@channel` |
| `credential` | Slack's or Telegram's bot token, the mail server's password for email, the API key for Resend, or a custom webhook's headers, one to a line as `Name: value` |
| `mail` | Email and Resend only. See below |
| `request` | Custom webhooks only, and required for them. See below |
| `app_token` | Optional, Slack only. The app-level token, starting `xapp-`, that adds Acknowledge and Silence buttons |
| `severities` | Which alerts it's sent: `["warning", "critical"]`, the default, or one of them, as in [which channels hear what](alerts.md#which-channels-hear-what) |

Email and Resend channels have `mail`:

| Field | Description |
| --- | --- |
| `from` | Required. Who the email comes from, like `MaxNines <alerts@example.com>`. For Resend, on a domain verified there |
| `server` | Email only, and required for it. The mail server it goes through |
| `server.hostname` | Required. Like `smtp.example.com` |
| `server.port` | The usual port for `security` if left out: 587 for `starttls`, 465 for `tls`, 25 for `none` |
| `server.security` | `starttls`, the default, `tls`, or `none` for a relay on a trusted network |
| `server.username` | For a server that asks you to sign in. The password goes in `credential`, and needs `starttls` or `tls` |

Custom webhooks have `request`, as in [custom webhooks](notifications.md#custom-webhooks):

| Field | Description |
| --- | --- |
| `method` | `POST`, the default, `PUT` or `PATCH` |
| `content_type` | Required. Like `application/json`, which has what's filled in escaped for JSON |
| `body` | Required. A Tera template, up to 16 KiB. It's checked when saved, and a JSON body has to come out as valid JSON |

Reading a custom webhook back gives `header_names`, the names of its headers, but never
their values.

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "Status board", "kind": "custom_webhook",
       "target": "https://status.example.com/api/events",
       "credential": "Authorization: Bearer abc123",
       "request": {"method": "POST", "content_type": "application/json",
                   "body": "{\"title\": \"{{ alert.rule_name }} on {{ alert.hostname }}\", \"status\": \"{{ event }}\"}"}}' \
  "$MAXNINES_URL/api/v1/notification-channels"
```

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "Ops email", "kind": "email", "target": "ops@example.com",
       "credential": "the password",
       "mail": {"from": "MaxNines <alerts@example.com>",
                "server": {"hostname": "smtp.example.com", "username": "alerts@example.com"}}}' \
  "$MAXNINES_URL/api/v1/notification-channels"
```

## List notification channels

`GET /api/v1/notification-channels`

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/notification-channels"
```

## Add a notification channel

`POST /api/v1/notification-channels`

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "Ops", "kind": "webhook", "target": "https://hooks.example.com/abc"}' \
  "$MAXNINES_URL/api/v1/notification-channels"
```

```json
{ "id": 1 }
```

## Get a notification channel

`GET /api/v1/notification-channels/{id}`

```sh
curl -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/notification-channels/1"
```

```json
{
  "id": 1,
  "name": "Ops",
  "kind": "webhook",
  "target_preview": "https://hooks.example.com/…",
  "severities": ["warning", "critical"],
  "mail": null,
  "request": null,
  "header_names": null
}
```

## Update a notification channel

`PUT /api/v1/notification-channels/{id}`

Replaces the whole channel, including its target and credential.

```sh
curl -X PUT -H "Authorization: Bearer $MAXNINES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "On call", "kind": "webhook", "target": "https://hooks.example.com/abc"}' \
  "$MAXNINES_URL/api/v1/notification-channels/1"
```

## Test a notification channel

`POST /api/v1/notification-channels/{id}/test`

Sends a test notification. Gives `204` if it was delivered, or `502` with an `error`.

```sh
curl -X POST -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/notification-channels/1/test"
```

## Delete a notification channel

`DELETE /api/v1/notification-channels/{id}`

Anything still waiting to go through the channel is dropped, and rules stop naming it.
It's kept, marked deleted, so what was sent through it still says where it went, but
it's no longer listed or found, and its name is free for a new channel.

```sh
curl -X DELETE -H "Authorization: Bearer $MAXNINES_API_KEY" \
  "$MAXNINES_URL/api/v1/notification-channels/1"
```
