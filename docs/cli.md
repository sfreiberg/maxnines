# Command line

`maxnines` works with a MaxNines server from a terminal. It only uses the server's
[API](api.md), so it can do what the pages can and nothing more, as you or as an API
key. Commands are a verb, a kind and names, like kubectl's.

```sh
maxnines login https://monitor.example.com
maxnines get alerts
maxnines silence host web-1 --for 30m --reason "Rebooting"
```

## Installing

Each [release](https://github.com/sfreiberg/maxnines/releases) has `maxnines` for
Linux, macOS and Windows on both x86_64 and Arm, and for FreeBSD on x86_64. It's one
program that needs nothing else, and needn't be on the same machine as the server.

**Linux packages** put it in `/usr/bin` with its man pages and its completions for
bash, zsh and fish, which work in a new shell:

```sh
sudo apt install ./maxnines-cli_0.1.0-1_amd64.deb    # Debian and Ubuntu
sudo dnf install ./maxnines-cli-0.1.0-1.x86_64.rpm   # RHEL, Rocky, Alma and Fedora
```

**Windows** has an installer for x64 and Arm, such as
`maxnines-cli-<version>-x86_64-pc-windows-msvc.msi`. It puts `maxnines.exe` in
`C:\Program Files\MaxNines\Command Line` and on the `PATH` for everyone, so it works
in any command prompt opened after it. It asks nothing, so it installs silently
with `msiexec /i maxnines-cli-<version>-x86_64-pc-windows-msvc.msi /qn`.
Uninstalling it leaves everyone's sign-ins.

**Other systems** have an archive, such as
`maxnines-cli-<version>-aarch64-apple-darwin.tar.gz`, holding `maxnines` and its man
pages in `man`. Put the program somewhere on your `PATH`, and the man pages where
`man` looks:

```sh
tar -xzf maxnines-cli-0.1.0-aarch64-apple-darwin.tar.gz
cd maxnines-cli-0.1.0-aarch64-apple-darwin
sudo install -m 755 maxnines /usr/local/bin/
sudo install -d /usr/local/share/man/man1
sudo install -m 644 man/*.1 /usr/local/share/man/man1/
xattr -d com.apple.quarantine /usr/local/bin/maxnines   # macOS, until it's signed
```

`man maxnines` then lists every command, and each has a page of its own, such as
`man maxnines-silence`. They hold what `--help` says; this page has the rest.
Completions are [below](#shell-completions).

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
for a machine without a browser. The code works for as long as the server says, and
a network that drops while you type it only means maxnines asks again.

Each server is a context, by name. Signing in to a server without naming a context
uses the one it already has, whatever it's called. A new one is named after the first
part of the server's name, such as `monitor` for `monitor.example.com`, with `-2`, `-3`
and so on after it when another server's context has that. The last one signed in to
is the one used, until
`maxnines config use` or `--context` says otherwise. `login` with no server signs in
to that context again, so `maxnines --context prod login` signs in to prod. Signing
in to a context again revokes its earlier sign-in on the server:

```sh
maxnines config list
#    NAME  SERVER                       SIGNED IN AS
#    lan   http://192.168.0.155:9000    you@example.com (viewer)
# *  prod  https://monitor.example.com  you@example.com (responder)
maxnines config use lan
maxnines --context prod get alerts
maxnines config remove lan
```

Contexts are kept in `config.hcl`, in `~/.config/maxnines`, or
`$XDG_CONFIG_HOME/maxnines` when that's set, or `%APPDATA%\maxnines` on Windows.
Tokens are kept in the Keychain on macOS and Credential Manager on Windows, and on
Linux and FreeBSD in `tokens.json` beside the config, readable only by you. Anyone with
a copy of `tokens.json` is signed in as you, so keep it out of backups and shares.
Each sign-in is listed under **Settings > Signed-in apps** on the server, where it can
be revoked. `MAXNINES_CONFIG_DIR` keeps everything, tokens included, in another folder,
on every system.

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

Adding a context by the name of one that's signed in replaces it, and signs it out
first.

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

The kinds are `hosts`, `alerts`, `silences` and `checks`, or `host`, `h`, `alert`,
`al`, `silence`, `sil`, `check` and `ck`. Names are hostnames, check names, or IDs.
Hostnames needn't be unique, so if two hosts share one, maxnines lists their IDs and
the start of one picks it. If that start fits more than one, give more of it:

```sh
maxnines get host web-1
# Error: 2 hosts are called web-1: 3f2a1c9d…, 8be04471…. Use the start of an ID instead
maxnines get host 3f2a
```

`describe` and `open` find alerts that have resolved and silences that have ended too.

`--filter` uses the same [filters](api-filters.md) as the Hosts page. It keeps the hosts
that match, and alerts and checks about them. Silences have filters of their own that
only the server can match, so `--filter` with silences is an error.

`-o` picks the output: `table`, `wide` for more columns, `json` for the API's own JSON,
or `name` for one `kind/ID` a line, such as `host/3f2a1c9d4e6b…` or `alert/41`. Every
command takes those back as names.

```sh
maxnines get alerts -o json | jq '.[] | select(.severity == "critical") | .summary'
for host in $(maxnines get hosts --filter 'hostname=db*' -o name); do
  maxnines silence host "$host" --for 1h --reason "Backups"
done
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
maxnines open alert 41
```

`--for` takes a length such as `90s`, `30m`, `2h30m` or `1d`, up to the 30 days a
silence can last. Silencing everything has to be said with `--all-alerts`: leaving out
what a silence covers is an error, not every alert.

With `-o json`, a change shows the API's answer: the host for `approve`, the new
silence's ID for `silence`, and nothing for `ack`, `unack` and `end`, which the API
answers with no content.

Anything else in the API is there through `maxnines api`, which shows its JSON.
`name=value` pairs are the query for `GET` and `DELETE`, added to any the path already
has. Otherwise they're a JSON object to send, or `--data` sends one as it is, but not
both:

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

maxnines never asks anything on the terminal. On macOS, though, the Keychain may show
a dialog asking to let a new version of maxnines read its tokens, which nobody can
answer in CI. Use an API key there, which never touches the Keychain.

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

## Shell completions

The Linux packages install completions for bash, zsh and fish. Otherwise,
`maxnines completion` writes them for bash, zsh, fish, PowerShell or Elvish, to save
where your shell looks for them:

```sh
maxnines completion bash > ~/.local/share/bash-completion/completions/maxnines
maxnines completion zsh > "${fpath[1]}/_maxnines"
maxnines completion fish > ~/.config/fish/completions/maxnines.fish
```

PowerShell runs them from your profile:

```powershell
maxnines completion powershell >> $PROFILE
```
