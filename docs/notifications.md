# Notification channels

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
