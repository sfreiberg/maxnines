# Installing

Each [release](https://github.com/sfreiberg/maxnines/releases) has the agent and
server for Linux, macOS and Windows on both x86_64 and Arm, and for FreeBSD on x86_64.
Set up the server first, as agents report to it.

## Linux packages

The `.deb` and `.rpm` packages install each program as a systemd service that runs
as a `maxnines` user, with its config in `/etc/maxnines` and its data in `/var/lib`.
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
package restarts a running service and keeps your changes to its config.

## Docker

The server is also an image for x86_64 and Arm. Set `MAXNINES_PUBLIC_URL` to the
address agents will use, and keep its data in a volume:

```sh
docker run -d --name maxnines -p 9000:9000 -v maxnines:/var/lib/maxnines-server \
  -e MAXNINES_PUBLIC_URL=ws://your-server:9000/ws ghcr.io/sfreiberg/maxnines-server
docker exec maxnines maxnines-server --config /etc/maxnines/server.hcl \
  users create you@example.com "Your Name"
```

## Other systems

The macOS, Windows and FreeBSD downloads are archives holding the program, an example
config and a README. Unpack one and see [running an agent](agents.md) or
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
