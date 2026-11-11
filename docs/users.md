# Users

Nobody can sign up. Every page needs someone signed in, and people are only added by
someone already here, so a new server starts with the command line:

```sh
maxnines-server users create you@example.com "Your Name"
```

That works on the main database directly, so the server needn't be running. It
prints a link for setting a password, which works once and lasts 7 days. After that,
add people on the Settings page, which gives you a link to send them. The same
command line can recover from a forgotten password with `users setup-link`.

Over plain `http://`, passwords cross the network unencrypted, so put anything beyond
a trusted network behind [HTTPS](https.md).

## Roles

Each person has a role, and each role adds to the one before:

| Role | What it adds |
| --- | --- |
| Viewer | Sees every page except Users and the audit log, and can open a rule or channel to read it. Changes their own profile and makes their own API keys |
| Responder | Acknowledges alerts and starts and ends silences, on the pages and from Slack's buttons, and adds and deletes [annotations](annotations.md) |
| Editor | Changes the setup: config rules, alert rules, notification channels, maintenance windows, checks, dashboards and the map. Approves and revokes agents |
| Admin | Adds, disables and deletes users and changes their roles. Reads the audit log, sees everyone's API keys, and deletes machines |

An admin sets roles on the Users page under Settings, or with the API. There's always
at least one admin who can sign in: the last one can't be given a lower role or
disabled. If you're locked out anyway, the command line still works:

```sh
maxnines-server users role <id> admin
```

`users create` on the command line makes an admin unless you pass `--role`. On the
Users page and through the API you choose, and the API makes a viewer if you don't
say. Everyone who was here before roles existed is an admin.

The pages only offer what your role allows, and the server checks every request
whatever a page shows.

### API keys and roles

A key acts as its owner, and has a role of its own: its owner's, or lower. A key for
a tool that only reads, like an AI assistant, can be a Viewer however much its owner
can do. A key never does more than its owner can now, so giving someone a lower role
lowers their keys with them.

## Two-factor sign-in

Anyone can add a second step to signing in: a six-digit code from an authenticator
app on their phone, such as Authy, Google Authenticator or 1Password.

1. Open your profile and choose **Set up two-factor**.
2. Scan the QR code with the app, or type in the secret shown under it.
3. Type the code the app shows, to check it works.
4. Keep the 10 recovery codes it then shows somewhere safe, away from your phone.
   They're only shown once.

If you leave before typing the code, nothing changes: the next time you open your
profile, you start again with a new QR code.

From then on, signing in asks for your password, then a code. Each recovery code
works once in place of a code, for when you can't use the app. Turning two-factor
off, or getting new recovery codes, takes your password again.

If someone loses their phone and their recovery codes, an admin can choose
**Reset two-factor** beside them on the Users page, or run:

```sh
maxnines-server users reset-two-factor <id>
```

They then sign in with their password alone and can set it up again.

An admin can also require it for everyone, from the Users page. Anyone without it is
sent to their profile to set it up before they can open anything else. The admin
turning this on has to have two-factor themselves first. API keys aren't affected:
they keep working whether or not their owner has two-factor.

Codes depend on the time, so the server's clock has to be right to within about 30
seconds. The secret each app shares is kept in the main database as it is, because
the server needs it to work out the same codes, so keep that database private.

## Time zones

Everyone sees times in UTC until they choose their own time zone on their profile.
The charts and the other times on the pages then use it, apart from a maintenance
window's schedule, which keeps the zone it was given. The API and alert messages
always use UTC, as they have no one person reading them.
