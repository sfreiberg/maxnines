# Running an agent

Without a package, an agent is one file you copy to a machine and start yourself. On
Windows, [run it as a service](windows-services.md) instead. Download it
from a [release](https://github.com/sfreiberg/maxnines/releases), or build it with
`cargo build --release -p maxnines-agent`.

Put `maxnines-agent` in a folder of its own, with an `agent.hcl` beside it that says
where the server is:

```hcl
server {
  url = "ws://your-server:9000/ws"
}

state_dir = "state"
```

The URL has to match the server's `public_url`. Use `wss://` for anything beyond a
trusted network. Everything else about what to monitor comes from the server, and the
example `agent.hcl` in each download explains the settings an agent can have of its
own.

Then start it:

```sh
./maxnines-agent
```

It creates a key in `state`, logs its agent ID, and waits to be approved. Approve it
on the Agents page, or from the command line with an API key:

```sh
export MAXNINES_API_KEY=$(maxnines-server api-keys create "Admin")
maxnines-server agents approve <agent-id>
```

It starts reporting within a few seconds, and from then on it reconnects by itself.
It stops with Ctrl+C or when the terminal closes, so use `nohup` or `tmux` to keep it
running after you log out. Samples are kept in `state` while the server can't be
reached, and sent when it's back.

- **One key per machine.** Copy the program and `agent.hcl` to another machine, but
  never `state`. The key inside it is the agent's identity, so a copy looks like the
  same machine. If two machines do share a key, each connection knocks the other off,
  and the Agents page shows the agent reconnecting over and over.
- **Names aren't unique.** The key is the agent's identity, so two machines can share
  a name, such as a caching name server in every office, and a renamed machine
  simply reports under its new name.
- **Only administrators should be able to change `agent.hcl`.** Custom metrics in it
  are commands the agent runs, so anyone who can edit the file can run commands as
  the agent. Keep it owned by the agent's user or root and not writable by others.
- **Upgrade the server first.** Older agents work with a newer server, but a newer
  agent may need things an older server doesn't have. The Agents page marks agents
  older than the one released with the server **Update available**, and any newer
  than the server **Newer than server**.
- **macOS and downloads:** a file that came through a browser or AirDrop is blocked
  until you run `xattr -d com.apple.quarantine maxnines-agent`.
- **Other commands:** `./maxnines-agent facts` prints what it reports about the
  machine, and `./maxnines-agent identity show` prints its ID once it's been started.
  Use `-c` to point any of them at a config file somewhere else.

## Disks

An agent reports how full each disk is, and how much is read and written, for every
file system on the machine's own storage. Mounts that are really files, memory or
another file system seen again aren't reported at all:

- **macOS:** disk images, such as a mounted installer, network shares, and the system's hidden
  volumes.
- **Linux:** loop devices, such as snaps and mounted image files, container layers,
  network shares, and memory file systems like `tmpfs`.
- **FreeBSD:** memory disks, null mounts such as jails', and memory file systems.
- **Windows:** mounted ISOs. Attached virtual disks, such as a Dev Drive, are reported.

On a Mac, the volumes in one APFS container share its space, so they're always exactly
as full as each other. Only one is reported for each container: `/` for the startup
disk, and otherwise the first by mount point.

To watch only some disks, list their mount points in a config rule under **Disk mount
points**. Those are reported whatever they are, even a disk image or every volume in
a container.

## Removing an agent

When a machine is gone for good, revoke its agent on its page, then delete it. That
takes its metrics, facts and alerts with it, and can't be undone. From the command
line:

```sh
maxnines-server agents revoke <agent-id>
maxnines-server agents delete <agent-id>
```

Stop the agent on the machine first, if it's still there. Otherwise it comes back as
a new agent waiting to be approved, and an approval rule may let it straight in.
