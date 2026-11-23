# Containers

On Linux, the `containers` collector reports on every Docker or Podman container on
its host: whether it's up, its CPU, memory, network and disk use, and how often it has
restarted.

## Turning it on

Turn on `containers` in a config rule, under **Collectors**. It's off until then,
because reading containers needs the agent's user to be allowed Docker's socket, and
that's as good as root on the host:

```sh
sudo usermod -aG docker maxnines
sudo systemctl restart maxnines-agent
```

The agent finds the socket at `/var/run/docker.sock`, or Podman's at
`/run/podman/podman.sock`, or wherever `DOCKER_HOST` says in the agent's environment.

Other systems run containers inside a Linux virtual machine, as Docker Desktop does on
macOS and Windows, so only the Linux agent reads them.

## What's reported

Each metric has a series for each container, named as Docker names it, so one that
Compose recreates keeps its history. An agent reports at most 64 containers.

| Metric | Unit | Series | What it is |
| --- | --- | --- | --- |
| `container.up` | 1 or 0 | Each container | Whether it's up |
| `container.cpu` | % | Each container | Its CPU use |
| `container.memory` | Bytes | Each container | Its memory use |
| `container.memory_limit` | % | Each container | Its memory use against its limit, when it has one |
| `container.received` | Bytes a second | Each container | Received over the network |
| `container.sent` | Bytes a second | Each container | Sent over the network |
| `container.read` | Bytes a second | Each container | Read from disk |
| `container.written` | Bytes a second | Each container | Written to disk |
| `container.restarts` | Number | Each container | How many times it has restarted |

A container is **up** while it's running and its health check, if it has one, doesn't
call it unhealthy. One that stopped with an error, keeps restarting, or is unhealthy
is down. One that exited cleanly isn't counted either way, as that's a job finishing
or a service stopped on purpose.

## Built-in alerts

| Alert | When |
| --- | --- |
| **Container down** | A container has been down for a minute, saying the state it's in, such as *Container web on web-1 is exited* |
