# Command line

`maxnines` works with a MaxNines server from a terminal. It only uses the server's
[API](api.md), so it can do what the pages can and nothing more, as you or as an API
key. Commands are a verb, a kind and names, like kubectl's.

```sh
maxnines login https://monitor.example.com
maxnines get alerts
maxnines silence host web-1 --for 30m --reason "Rebooting"
```

## Signing in

`maxnines login` opens your browser at the server. Sign in there if you aren't already,
choose what it may do, and choose **Allow**. It's signed in however you sign in to the
pages, two-factor included, and stays signed in for 90 days after it was last used.

```sh
maxnines login https://monitor.example.com              # saved as "monitor"
maxnines login lan http://192.168.0.155:9000            # saved as "lan"
maxnines login lan                                      # sign in to it again
maxnines login prod https://monitor.example.com --role viewer
maxnines login prod https://monitor.example.com --device   # over SSH: a code to type elsewhere
maxnines whoami
maxnines logout prod
```

`--role` is the most it asks for. The page offers that or less, and never more than
your own role. With `--device` it shows an address and a code to enter on any device,
for a machine without a browser.

Each server is a context, by name. The last one signed in to is the one used, until
`maxnines config use` or `--context` says otherwise:

```sh
maxnines config list
#    NAME  SERVER                       SIGNED IN AS
#    lan   http://192.168.0.155:9000    you@example.com (viewer)
# *  prod  https://monitor.example.com  you@example.com (responder)
maxnines config use lan
maxnines --context prod get alerts
maxnines config remove lan
```

Contexts are kept in `~/.config/maxnines/config.hcl`, or `%APPDATA%\maxnines` on
Windows. Tokens are kept in the Keychain on macOS and Credential Manager on Windows,
and on Linux and FreeBSD in `tokens.json` beside the config, readable only by you. Each
sign-in is listed under **Settings > Signed-in apps** on the server, where it can be
revoked. `MAXNINES_CONFIG_DIR` keeps everything, tokens included, in another folder.

Plain `http` is refused beyond your local network, so a sign-in never crosses the
internet unencrypted.

### In CI

Nobody can choose Allow in CI, so use an [API key](api-keys.md) there. The variables the
API docs use win over the config file:

```sh
MAXNINES_URL=https://monitor.example.com MAXNINES_API_KEY=$KEY maxnines get hosts
```

Or name a context that reads its key from a variable:

```sh
maxnines config add ci --server https://monitor.example.com --key-env CI_MAXNINES_KEY
```

## Reading

```sh
maxnines get hosts
# HOSTNAME   ID        STATUS   LAST SEEN
# web-1      3f2a1c9d  online   2s
# orders-db  9fcd430c  offline  -

maxnines get hosts --filter 'os=linux hostname=web*'
maxnines get alerts
maxnines get alerts --ended            # resolved ones
maxnines get silences
maxnines get checks -o wide
maxnines describe host web-1
maxnines describe check "Home page"
```

The kinds are `hosts`, `alerts`, `silences` and `checks`, or `host`, `h`, `al`, `sil`
and `ck`. Names are hostnames, check names, or IDs. Hostnames needn't be unique, so if
two hosts share one, maxnines lists their IDs and the start of one picks it:

```sh
maxnines get host web-1
# Error: 2 hosts are called web-1: 3f2a1c9d…, 8be04471…. Use the start of an ID instead
maxnines get host 3f2a
```

`--filter` uses the same [filters](api-filters.md) as the Hosts page, and for alerts
and checks it keeps those about matching hosts.

`-o` picks the output: `table`, `wide` for more columns, `json` for the API's own JSON,
or `name` for one `kind/name` a line.

```sh
maxnines get alerts -o json | jq '.[] | select(.severity == "critical") | .summary'
maxnines get hosts --filter 'hostname=db*' -o name
```

## Changing

```sh
maxnines ack 41 39
maxnines unack 41
maxnines silence alert 41 --for 1h --reason "Known"         # its rule, host and series only
maxnines silence host web-1 --for 30m --reason "Rebooting"
maxnines silence check "Home page" --for 2h --reason "Deploy"
maxnines silence --rule "High CPU" --filter 'hostname=web*' --for 1h --reason "Load test"
maxnines silence --all-alerts --for 1h --reason "Moving data centres"
maxnines end silence 12
maxnines approve host 44cf
maxnines open host web-1                                     # its page in the browser
```

`--for` takes `30m`, `2h`, `1d` or `2h30m`. Silencing everything has to be said with
`--all-alerts`: leaving out what a silence covers is an error, not every alert.

Anything else in the API is there through `maxnines api`, which shows its JSON.
`name=value` pairs are the query for `GET` and `DELETE`, and a JSON object otherwise:

```sh
maxnines api GET /hosts/filter-options text=os
maxnines api POST /annotations --data '{"kind": "deploy", "title": "Shop v2.4", "filter": "role=web"}'
```

## Scripting

A deploy that quiets a host, deploys, and stops if anything's firing on it afterwards:

```sh
set -e
silence=$(maxnines silence host web-1 --for 20m --reason "Deploy $SHA" -o name)
./deploy.sh web-1
maxnines get alerts --filter 'hostname=web-1' --exit-code   # 1 if any are firing
maxnines end "$silence"
```

It never prompts, so it's safe without a terminal.

| Exit code | Means |
| --- | --- |
| 0 | Done |
| 1 | `--exit-code` found something, and nothing else |
| 2 | The command was wrong |
| 3 | Not found, or a name matched more than one |
| 4 | Not signed in, the key isn't accepted, or the role doesn't allow it |
| 5 | The server refused it, and says why |
| 6 | Couldn't reach the server, or nobody allowed the sign-in in time |
| 7 | Anything else, such as the server failing |

Shell completions:

```sh
maxnines completion zsh > "${fpath[1]}/_maxnines"
maxnines completion bash > /etc/bash_completion.d/maxnines
```
