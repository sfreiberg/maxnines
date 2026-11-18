# Installs the agent's MSI on a Windows machine, as an administrator, and checks
# what it did: the service, the config it wrote, who can read it, and that the
# token stays out of the log. Then Modify, an upgrade and an uninstall.
#
#   packaging/windows/test-agent-install.ps1 -Msi maxnines-agent.msi -Upgrade newer.msi
#
# The server it points at isn't there, which the agent copes with by retrying.
param(
    [Parameter(Mandatory)] [string] $Msi,
    # The same agent with a higher version.
    [Parameter(Mandatory)] [string] $Upgrade
)
$ErrorActionPreference = 'Stop'
# msiexec can't open a package from a relative path.
$Msi = (Resolve-Path $Msi).Path
$Upgrade = (Resolve-Path $Upgrade).Path

$data = 'C:\ProgramData\MaxNines\Agent'
$config = Join-Path $data 'agent.hcl'
$program = 'C:\Program Files\MaxNines\Agent\'
$logs = Join-Path ($env:RUNNER_TEMP ?? [IO.Path]::GetTempPath()) 'msi-logs'
New-Item -ItemType Directory -Force $logs | Out-Null

function Check([bool] $ok, [string] $what) {
    if (-not $ok) { throw "Failed: $what" }
    Write-Host "ok: $what"
}

function Msiexec([string] $name, [string[]] $arguments) {
    $log = Join-Path $logs "$name.log"
    $process = Start-Process msiexec.exe -Wait -PassThru `
        -ArgumentList ($arguments + @('/qn', '/l*v', "`"$log`""))
    if ($process.ExitCode -ne 0) {
        Get-Content $log -Tail 100
        throw "msiexec $name exited with $($process.ExitCode)"
    }
    $log
}

function Service-Pid {
    (Get-CimInstance Win32_Service -Filter "Name='MaxNinesAgent'").ProcessId
}

# Running, and still running a moment later, so it didn't start and then fail.
function Check-Running([string] $when) {
    Start-Sleep -Seconds 5
    $service = Get-Service MaxNinesAgent
    Check ($service.Status -eq 'Running') "the service is running $when"
}

function Url-In-Config {
    (Get-Content $config -Raw) -match 'url = "([^"]*)"' | Out-Null
    $Matches[1]
}

# Install, as a silent install with the questions given as properties.
$token = "token-$([guid]::NewGuid())"
$log = Msiexec 'install' @('/i', "`"$Msi`"", 'SERVER_URL=http://127.0.0.1:9', "ENROLLMENT_TOKEN=$token")

Check-Running 'after installing'
$service = Get-Service MaxNinesAgent
Check ($service.StartType -eq 'Automatic') 'the service starts with Windows'
Check ((Url-In-Config) -eq 'ws://127.0.0.1:9/ws') 'the config has the server, as an agent address'
Check ((Get-Content (Join-Path $data 'enrollment.token') -Raw) -eq $token) 'the token is saved'
Check (-not (Select-String -Path $log -SimpleMatch $token -Quiet)) 'the token is not in the log'
Check ((Get-ItemProperty 'HKLM:\SOFTWARE\MaxNines\Agent').SERVER_URL -eq 'http://127.0.0.1:9') 'the server is remembered for Modify, as it was typed'

$acl = Get-Acl $data
$who = $acl.Access | ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique
Check $acl.AreAccessRulesProtected 'the data folder does not inherit permissions'
Check ((Compare-Object $who @('BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM')) -eq $null) "only Windows and administrators can open the data folder (found: $($who -join ', '))"

$failure = sc.exe qfailure MaxNinesAgent | Out-String
Check ($failure -match 'RESTART -- Delay = 30000') "Windows restarts it 30 seconds after a failure:`n$failure"
$flag = sc.exe qfailureflag MaxNinesAgent | Out-String
Check ($flag -match 'TRUE') "stopping with an error counts as failing:`n$flag"
$preshutdown = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\MaxNinesAgent').PreshutdownTimeout
Check ($preshutdown -eq 60000) "it gets a minute to stop when Windows shuts down (found: $preshutdown)"

$path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
Check ($path.Split(';') -contains $program) 'the program is on the PATH'
Check ((& "$program\maxnines-agent.exe" --config $config facts | Out-String) -match '"hostname"') 'the installed program runs from the command line'

# The service writes its log beside the config.
$started = $false
for ($i = 0; $i -lt 30 -and -not $started; $i++) {
    $started = [bool](Get-ChildItem (Join-Path $data 'logs') -File -ErrorAction SilentlyContinue |
        Select-String -SimpleMatch 'agent started' -Quiet)
    if (-not $started) { Start-Sleep -Seconds 1 }
}
Check $started 'the service logs that the agent started'

# Something added by hand has to survive the installer.
Add-Content $config "`nfacts = { added = `"by hand`" }"

# Modify, as Settings > Apps does without the dialogs: a new server, no token.
$before = Service-Pid
Msiexec 'modify' @('/i', "`"$Msi`"", 'SERVER_URL=https://example.invalid') | Out-Null
Check-Running 'after Modify'
Check ((Url-In-Config) -eq 'wss://example.invalid/ws') 'Modify changes the server'
Check ((Get-Content $config -Raw) -match 'added = "by hand"') 'Modify keeps what was added by hand'
Check ((Get-Content (Join-Path $data 'enrollment.token') -Raw) -eq $token) 'Modify without a token keeps the one there is'
Check ((Service-Pid) -ne $before) 'Modify restarts the service'

# The server changed by hand, which the agent remembers when it restarts.
(Get-Content $config -Raw).Replace('wss://example.invalid/ws', 'wss://by-hand.invalid/ws') |
    Set-Content $config -NoNewline
Restart-Service MaxNinesAgent
Start-Sleep -Seconds 5
Check ((Get-ItemProperty 'HKLM:\SOFTWARE\MaxNines\Agent').SERVER_URL -eq 'https://by-hand.invalid') 'a server set by hand is remembered for Modify'

# An upgrade, without saying the server again.
Msiexec 'upgrade' @('/i', "`"$Upgrade`"") | Out-Null
Check-Running 'after upgrading'
Check ((Url-In-Config) -eq 'wss://by-hand.invalid/ws') 'upgrading keeps the server set by hand'
Check ((Get-Content $config -Raw) -match 'added = "by hand"') 'upgrading keeps what was added by hand'
$products = Get-CimInstance Win32_Product -Filter "Name='MaxNines Agent'"
Check (@($products).Count -eq 1) 'upgrading replaces the old version'

# Uninstall.
Msiexec 'uninstall' @('/x', "`"$Upgrade`"") | Out-Null
Check ($null -eq (Get-Service MaxNinesAgent -ErrorAction SilentlyContinue)) 'uninstalling removes the service'
Check (Test-Path $config) 'uninstalling keeps the config'
Check (Test-Path (Join-Path $data 'state\agent.key')) "uninstalling keeps the agent's key"
$path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
Check (-not ($path.Split(';') -contains $program)) 'uninstalling takes the program off the PATH'
Check (-not (Test-Path 'HKLM:\SOFTWARE\MaxNines\Agent')) 'uninstalling forgets the server'

# A silent install with no server, now that none is remembered, is refused.
$refused = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @('/i', "`"$Msi`"", '/qn')
Check ($refused.ExitCode -ne 0) 'a silent install without SERVER_URL is refused'

Write-Host 'The installer works.'
