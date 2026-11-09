# Windows services

The agent and the server can both run as Windows services, which start with the
machine and restart after a failure. Everything below is for the agent, and works the
same for the server with `maxnines-server.exe`, `server.hcl` and `MaxNinesServer`.

Put the program somewhere permanent, because the service runs it from where it was when
you installed it. Put `agent.hcl` in a folder of its own, then let only Windows and
administrators into that folder, because it will hold the private key and, for the
server, the databases:

```powershell
New-Item -ItemType Directory C:\ProgramData\MaxNines
icacls C:\ProgramData\MaxNines /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"
```

Then, from a PowerShell window opened as administrator:

```powershell
& "C:\Program Files\MaxNines\maxnines-agent.exe" -c C:\ProgramData\MaxNines\agent.hcl service install
Start-Service MaxNinesAgent
```

Relative paths in the config, like `state_dir = "state"`, mean the folder the config
is in. Logs are in a `logs` folder beside it, with a file for each day, and the last
14 days are kept.

Use `Stop-Service` and `Restart-Service` as you would for anything else. The service
runs as Local System. To remove it, which leaves the config and data in place:

```powershell
& "C:\Program Files\MaxNines\maxnines-agent.exe" service uninstall
```
