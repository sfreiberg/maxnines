# Installing

Each [release](https://github.com/sfreiberg/maxnines/releases) has the agent and
server for Linux, macOS and Windows on both x86_64 and Arm, and for FreeBSD on x86_64.
Set up the server first, as agents report to it.

## Linux packages

The `.deb` and `.rpm` packages install each program as a systemd service that runs
as a `maxnines` user, with its config in `/etc/maxnines` and its data in `/var/lib`.
The agent is started as root and [gives that up](agents.md#running-as-root-and-giving-it-up)
before it connects, keeping a small helper for the built-in actions that need it.
Download the ones for your system, then install them:

```sh
sudo apt install ./maxnines-server_0.1.0-1_amd64.deb    # Debian and Ubuntu
sudo dnf install ./maxnines-server-0.1.0-1.x86_64.rpm   # RHEL, Rocky, Alma and Fedora
```

The server needs Ubuntu 22.04, Debian 12, RHEL 9 or newer. The agent needs nothing
else, so it installs on any of them and older.

Neither starts until it's set up. For the server, check `/etc/maxnines/server.hcl`,
start it, and add the first person who can sign in:

```sh
sudo systemctl enable --now maxnines-server
sudo -u maxnines maxnines-server --config /etc/maxnines/server.hcl \
  users create you@example.com "Your Name"
```

For an agent, set the server's address in `/etc/maxnines/agent.hcl`, start it, and
approve its host on the server's Hosts page:

```sh
sudo systemctl enable --now maxnines-agent
```

Both log to the journal, as in `journalctl -u maxnines-agent`. Installing a newer
package restarts a running service and never changes its config or asks about it.
To compare yours with the newest default, look in `/usr/share/maxnines` on Debian
and Ubuntu, or for a `.rpmnew` file next to yours on the others. `apt purge` deletes
the config as well.

## Docker

The server is also an image for x86_64 and Arm. Set `MAXNINES_PUBLIC_URL` to the
address agents will use, and keep its data in a volume:

```sh
docker run -d --name maxnines -p 9000:9000 -v maxnines:/var/lib/maxnines-server \
  -e MAXNINES_PUBLIC_URL=ws://your-server:9000/ws ghcr.io/sfreiberg/maxnines-server
docker exec maxnines maxnines-server --config /etc/maxnines/server.hcl \
  users create you@example.com "Your Name"
```

## The agent on Windows

The agent has an installer for x64 and Arm, `maxnines-agent-<version>-x86_64-pc-windows-msvc.msi`
or `maxnines-agent-<version>-aarch64-pc-windows-msvc.msi`. It asks for:

- **The server's address,** as you open it in a browser, such as
  `https://monitor.example.com`. The agent connects to `/ws` there. If the server's
  `public_url` is somewhere else, such as behind a proxy, give that instead, starting
  with `wss://`.
- **An enrollment token,** only if the server's registration rules approve agents
  with one. Leave it empty to approve the host on the Hosts page instead.

It then installs the agent as the **MaxNines Agent** service, which starts with
Windows, and starts it. The agent's program goes in `C:\Program Files\MaxNines\Agent`,
which is added to the `PATH`. Its config, token, key, logs and unsent samples go in
`C:\ProgramData\MaxNines\Agent`, which only Windows and administrators can open.

To change the server later, open **Settings > Apps > Installed apps**, choose
**MaxNines Agent** and then **Modify**. It asks again, keeps the token if you
leave it empty, and restarts the service. Anything you've added to `agent.hcl` by
hand is kept. From a command prompt opened as administrator, this does the same:

```powershell
maxnines-agent --config C:\ProgramData\MaxNines\Agent\agent.hcl configure --server-url https://monitor.example.com
```

To install it on many computers at once, such as with Intune, Group Policy or
Configuration Manager, give the answers as properties and install it silently:

```powershell
msiexec /i maxnines-agent-<version>-x86_64-pc-windows-msvc.msi SERVER_URL=https://monitor.example.com ENROLLMENT_TOKEN=<token> /qn
```

The token is saved for the agent but never written to the installer's log.
Upgrading is the same without the properties, and keeps the server and token.
Uninstalling removes the program and the service but keeps
`C:\ProgramData\MaxNines\Agent`, so reinstalling brings back the same host rather
than a new one to approve.

The installer isn't signed yet, so Windows may warn that it's from an unknown
publisher. Choose **More info** and then **Run anyway**.

## Other systems

The macOS, FreeBSD and Windows server downloads are archives holding the program, an
example config and a README. Unpack one and see [running an agent](agents.md) or
[Windows services](windows-services.md). The macOS programs aren't signed by Apple
yet, so clear the flag that stops them opening first:

```sh
xattr -d com.apple.quarantine maxnines-agent
```

## Checking a download

Each release lists every file's SHA-256 in `SHA256SUMS`. GitHub also records that
each file was built by this repository's release workflow, which you can check with
the GitHub CLI:

```sh
gh attestation verify maxnines-agent-0.1.0-x86_64-unknown-linux-musl.tar.gz \
  --repo sfreiberg/maxnines
```

## Checking what's installed

Each program prints its version, the commit it was built from, when it was built and
the system it's for:

```sh
maxnines-agent version
maxnines-server version
```

`--version` prints just the version.
