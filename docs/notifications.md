# Notification channels

## Charts

When an alert starts, or a warning becomes critical, Discord, Telegram, Slack, email and
Resend get a chart with it: the last hour of what the alert watches, on that machine or for that
calculation, with the rule's thresholds and the moment the alert started. Times on it are
in UTC, like the rest of the message. Other notifications, and other channels, are text
only. An alert about an agent going offline has nothing to chart.

The chart is drawn inside the server, so nothing else needs to be installed. If one
can't be drawn or sent, the notification goes without it, and the server's log says why.

- **Slack** needs the app to have the `files:write` permission, which apps made from the
  channel form's button have. For an app made before charts, add it under **OAuth &
  Permissions**, then **Bot Token Scopes**, and reinstall the app to the workspace.
- **Telegram** sends a photo with the alert as its caption, or for a long alert, the
  message first with the photo as a reply.
- **Email** and **Resend** show the chart under the text, for mail apps that show HTML.

## Email

An email channel sends through a mail server you choose for it, on its page under
Settings, then **Notification channels**. Different channels can use different servers.

- **From** is who the email comes from, like `MaxNines <alerts@example.com>`. Most mail
  servers only send for their own addresses.
- **Security** is STARTTLS, usually on port 587, TLS, usually on port 465, or none, which
  only suits a relay on a trusted network. Leave the port empty for the usual one.
- **Username** and **password** are for a server that asks you to sign in. They need
  STARTTLS or TLS, so the password is never sent unencrypted. The password is never shown
  again: leave it empty to keep it, or clear the username to remove both.

Email channels made before each channel had its own mail server need one set before
they send again. Until then, each notification fails and the channel's problems say so.

## Resend

[Resend](https://resend.com) sends email through its API, for a server that can't reach
a mail server or that you'd rather not run one for. The channel form walks through it:

1. In Resend, open **Domains**, choose **Add Domain**, and add the DNS records it lists
   until the domain shows as **Verified**.
2. Open **API Keys**, choose **Create API Key** with **Sending access** for that domain,
   and paste the key, which starts with `re_`, into the channel's API key box.
3. Put an address on that domain in **From**.

The key is never shown again. Each notification goes with a key Resend uses to spot a
repeat, so one retried after a timeout isn't sent twice.

## Slack buttons

Slack alerts can have **Acknowledge** and **Silence 1 hour** buttons. They need the
Slack app's app-level token as well as its bot token. The form for a Slack channel has
a button that creates the app in Slack with everything filled in, and says where in
Slack to find each token.

The server connects out to Slack to hear the buttons, using Slack's Socket Mode, so it
doesn't need to be reachable from the internet.

Pressing a button acts as the MaxNines user with the same email address as the person
in Slack, so each person needs a MaxNines account with the email they use in Slack.
Slack guests, people from other organizations through Slack Connect, and disabled
MaxNines users can't use them. Use **Test** on the channel to check both tokens.

## Microsoft Teams

Alerts go to a Teams channel through a workflow that posts whatever is sent to it.

1. In Teams, open the channel, open its **···** menu, and choose **Workflows**.
2. Choose **Post to a channel when a webhook request is received**, name it, and
   choose **Next**, then **Add workflow**.
3. Copy the URL it shows into the channel's **Sends to** box in MaxNines. Teams
   doesn't show it again, but Power Automate does, under the workflow's **When a
   Teams webhook request is received** step.

Each notification is a card with the alert, its rule, the machine and when it started,
and a **View alerts** link when the server knows its own address. Teams messages have
no chart and no buttons, as a workflow can only post. The URL works like a password,
so it's never shown again once saved.

Microsoft has retired the older Office 365 connectors, whose URLs are on
`webhook.office.com`, so those aren't accepted.

## Telegram

Alerts can go to a Telegram group, channel or private chat through a bot of your own.
When an alert resolves, the message replies to the one that said it started.

1. Message [@BotFather](https://t.me/BotFather), send `/newbot` and follow its steps. It
   gives you the bot's token.
2. Add the bot to the group that should get alerts. For a channel, make the bot an admin
   that can post. For a private chat, send the bot a message yourself.
3. Find the chat's ID by opening `https://api.telegram.org/bot<token>/getUpdates` in a
   browser and looking for `"chat":{"id":`. Group IDs start with a minus sign. A public
   channel can use its `@username` instead.
4. In MaxNines, go to Settings, then notification channels, and add a Telegram channel
   with that chat ID and the token.

The token works like a password, so it can't be read back once saved.

## On-call services

Alerts can open incidents in PagerDuty, AlertOps and SIGNL4, and close them again when
they resolve. Each alert is one incident.

Set them up in the web interface: go to Settings, then notification channels, add a
channel of that type, then add the channel to the alert rules that should use it. The
form has these steps too.

Sending a test opens an incident and closes it straight away, which can notify whoever
is on call. Keys and URLs work like passwords, so they can't be read back once saved.

### PagerDuty

1. In PagerDuty, open the service that should get the alerts, then its Integrations tab.
2. Add an integration, choose Events API V2, and copy its Integration Key.
3. Use that key as the channel's destination.

A rule's severity carries over.

### AlertOps

AlertOps lets you choose what each field in an incoming alert means, so there's a little
mapping to do. Custom integrations may depend on your AlertOps plan.

1. In AlertOps, go to Configuration, then Integrations. Under Inbound Integrations,
   choose API and add one using the Custom card, with the escalation policy you want.
2. Open its rules for opening and closing an alert. Keep the method as POST and the
   content as JSON.
3. Paste this in as the sample data:

   ```json
   {
     "alert_id": "maxnines-test",
     "host": "MaxNines",
     "link": "https://maxnines.example.com/alerts",
     "message": "This is a test notification from MaxNines.",
     "severity": "info",
     "status": "open",
     "subject": "Test"
   }
   ```

4. Map `alert_id` to both Source Name and Source Id, so each alert stays separate. A
   fixed Source Name would merge them into one.
5. Map `status` as the status field. Open an alert when it contains `open`, and close it
   when it contains `closed`.
6. Map `subject` and `message` to the text fields you want, and `link` to Source URL.
7. Leave the authorization header off, then copy the integration's URL. Do this last, as
   changing its source changes the URL.
8. Use that URL as the channel's destination.

### SIGNL4

Use `https://connect.signl4.com/webhook/` followed by your SIGNL4 team or integration
secret as the channel's destination.
