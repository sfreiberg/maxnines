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

## Time zones

Everyone sees times in UTC until they choose their own time zone on their profile.
The charts and the other times on the pages then use it, apart from a maintenance
window's schedule, which keeps the zone it was given. The API and alert messages
always use UTC, as they have no one person reading them.
