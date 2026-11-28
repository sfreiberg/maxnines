# Installing

Each [release](https://github.com/sfreiberg/maxnines/releases) has the agent,
server and [command line](cli.md#installing) for Linux, macOS and Windows on both
x86_64 and Arm, and for FreeBSD on x86_64. Set up the server first, as agents report
to it.

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
address agents will use, and keep its data in a volume. Each release is tagged with
its version, such as `0.1.0-alpha.11`, and `latest` is the newest release that isn't
a pre-release, once there is one:

```sh
docker run -d --name maxnines -p 9000:9000 -v maxnines:/var/lib/maxnines-server \
  -e MAXNINES_PUBLIC_URL=ws://your-server:9000/ws ghcr.io/sfreiberg/maxnines-server:<version>
docker exec maxnines maxnines-server --config /etc/maxnines/server.hcl \
  users create you@example.com "Your Name"
```

## Windows

They run on Windows 10 and 11, and Windows Server 2016 and later. Older versions
can't run them.

The server and the agent each have an installer for x64 and Arm, such as
`maxnines-server-<version>-x86_64-pc-windows-msvc.msi` or
`maxnines-agent-<version>-aarch64-pc-windows-msvc.msi`. Each installs a service that
starts with Windows, puts its program in `C:\Program Files\MaxNines` on the `PATH`,
and keeps its config and data in `C:\ProgramData\MaxNines`, which only Windows and
administrators can open. Logs are in a `logs` folder there, a file for each day,
kept for 14 days.

To change what the installer asked later, open **Settings > Apps > Installed apps**,
choose the program and then **Modify**. It asks again and restarts the service. A
setting you leave as it was keeps what the config has, so changes you've made to the
config by hand stay unless you change the same setting in Modify. The server's
installer shows your answers from last time, which may not show a change made by hand
since; the agent's shows what its config says now.
After editing the config by hand, restart the service, such as with
`Restart-Service MaxNinesServer`.

Upgrading keeps the config. Uninstalling removes the program and the service but keeps
`C:\ProgramData\MaxNines`, so reinstalling the server brings back everything, and
reinstalling an agent brings back the same host rather than a new one to approve.

The installers aren't signed yet, so Windows may warn that they're from an unknown
publisher. Choose **More info** and then **Run anyway**.

### The server

The server's installer asks for:

- **The address** people will open in a browser and agents will connect to, such as
  `https://monitor.example.com`. It starts as this computer's name on port 9000.
  Behind a proxy, give the proxy's address.
- **The port** to listen on, which Windows Firewall lets through.
- **[HTTPS](https.md):** none, an automatic certificate from Let's Encrypt, or your own
  certificate from files. Either kind needs an address starting with `https://`.
- **The first administrator,** as nobody can sign up. When the installer finishes, it
  opens the page for them to set a password.

To install it without the questions, give the answers as properties. Everything but
the administrator has a default:

```powershell
msiexec /i maxnines-server-<version>-x86_64-pc-windows-msvc.msi SERVER_ADDRESS=https://monitor.example.com PORT=443 HTTPS=automatic ACME_EMAIL=you@example.com ADMIN_EMAIL=you@example.com ADMIN_NAME="Your Name" /qn
```

The server runs as its own account, `NT SERVICE\MaxNinesServer`, which Windows makes
for the service and which can open little but its data folder. It can read
`server.hcl` but not change it, so that a server someone has taken over can't choose
what the installer does next. The installer lets it read the certificate and key you
give it, wherever they are. If you point
`server.hcl` at other files by hand, such as a `password_file` or a registration
rule's `token_file`, put them in `C:\ProgramData\MaxNines\Server` or let the
account read them:

```powershell
icacls C:\path\to\file /grant "NT SERVICE\MaxNinesServer:R"
```

The same goes for a renewed certificate: copying it over the old file keeps the
permission, but deleting the old one first loses it.

`HTTPS` is `none`, `automatic` or `files`, with `CERTIFICATE_FILE` and `KEY_FILE`. A
silent install doesn't keep the link for setting a password, so get it from a command
prompt opened as administrator:

```powershell
maxnines-server --config C:\ProgramData\MaxNines\Server\server.hcl users list
maxnines-server --config C:\ProgramData\MaxNines\Server\server.hcl users setup-link <id>
```

### The agent

The agent's installer asks for:

- **The server's address,** as you open it in a browser. The agent connects to `/ws`
  there. If the server's `public_url` is somewhere else, give that instead, starting
  with `wss://`.
- **An enrollment token,** only if the server's registration rules approve agents
  with one. Leave it empty to approve the host on the Hosts page instead. Modify keeps
  the token if you leave it empty.

To install it on many computers at once, such as with Intune, Group Policy or
Configuration Manager, give the answers as properties and install it silently:

```powershell
msiexec /i maxnines-agent-<version>-x86_64-pc-windows-msvc.msi SERVER_URL=https://monitor.example.com ENROLLMENT_TOKEN=<token> /qn
```

The token is saved for the agent but never written to the installer's log.

## Other systems

The macOS and FreeBSD downloads are archives holding the program, an example config
and a README. Unpack one and see [running an agent](agents.md). The macOS programs
aren't signed by Apple
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

`--version` prints just the version, and is all the command line has:
`maxnines --version`.
