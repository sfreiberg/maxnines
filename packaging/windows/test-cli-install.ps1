# Installs the command line's MSI on a Windows machine, as an administrator, and
# checks what it did: the program, on the PATH, that runs from a new command
# prompt. Then an upgrade and an uninstall.
#
#   packaging/windows/test-cli-install.ps1 -Msi maxnines-cli.msi -Upgrade newer.msi -Version 0.1.0
#
# On Arm, -X64OnArm names an x64 installer, which should refuse to install.
param(
    [Parameter(Mandatory)] [string] $Msi,
    # The same program with a higher version.
    [Parameter(Mandatory)] [string] $Upgrade,
    # What maxnines --version should say.
    [Parameter(Mandatory)] [string] $Version,
    [string] $X64OnArm
)
$ErrorActionPreference = 'Stop'
# msiexec can't open a package from a relative path.
$Msi = (Resolve-Path $Msi).Path
$Upgrade = (Resolve-Path $Upgrade).Path

$program = 'C:\Program Files\MaxNines\Command Line\'
$logs = Join-Path ($env:RUNNER_TEMP ?? [IO.Path]::GetTempPath()) 'msi-logs'
New-Item -ItemType Directory -Force $logs | Out-Null

function Check([bool] $ok, [string] $what) {
    if (-not $ok) { throw "Failed: $what" }
    Write-Host "ok: $what"
}

function Msiexec([string] $name, [string[]] $arguments) {
    $log = Join-Path $logs "cli-$name.log"
    $process = Start-Process msiexec.exe -Wait -PassThru `
        -ArgumentList ($arguments + @('/qn', '/l*v', "`"$log`""))
    if ($process.ExitCode -ne 0) {
        Get-Content $log -Tail 100 | Out-Host
        throw "msiexec $name exited with $($process.ExitCode)"
    }
}

# What a command prompt opened now would run for maxnines, with the PATH Windows
# gives it rather than the one this script started with.
function Maxnines-In-A-New-Prompt {
    $path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $found = $path.Split(';') | Where-Object { $_ -and (Test-Path (Join-Path $_ 'maxnines.exe')) } |
        Select-Object -First 1
    if ($found) { Join-Path $found 'maxnines.exe' }
}

# On Arm, the x64 installer refuses, naming the one to use, before installing
# anything.
if ($X64OnArm) {
    $log = Join-Path $logs 'cli-x64-on-arm.log'
    $refused = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @(
        '/i', "`"$((Resolve-Path $X64OnArm).Path)`"", '/qn', '/l*v', "`"$log`"")
    Check ($refused.ExitCode -eq 1603) 'the x64 installer refuses on Arm'
    Check ((Get-Content $log -Raw) -match 'aarch64 in its name') 'it says which installer to use'
    Check (-not (Test-Path $program)) 'it installs nothing'
}

Msiexec 'install' @('/i', "`"$Msi`"")
Check (Test-Path (Join-Path $program 'maxnines.exe')) 'the program is installed'
Check (Test-Path (Join-Path $program 'LICENSE.txt')) 'the licence is installed beside it'
$path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
Check ($path.Split(';') -contains $program) 'its folder is on the PATH'
$found = Maxnines-In-A-New-Prompt
Check ($found -eq (Join-Path $program 'maxnines.exe')) "a new command prompt finds it (found: $found)"
$said = (& $found --version | Out-String).Trim()
Check ($said -eq "maxnines $Version") "it runs and says its version (said: $said)"
# Nothing to sign in to, but it runs a command end to end and exits as documented.
$config = Join-Path ($env:RUNNER_TEMP ?? [IO.Path]::GetTempPath()) 'maxnines-config'
$env:MAXNINES_CONFIG_DIR = $config
& $found get hosts 2>$null | Out-Null
Check ($LASTEXITCODE -eq 4) "with no sign-in it says so, exiting 4 (exited $LASTEXITCODE)"
Remove-Item Env:MAXNINES_CONFIG_DIR
# Otherwise the step would end with that exit code, as if this had failed.
$global:LASTEXITCODE = 0

# An upgrade.
Msiexec 'upgrade' @('/i', "`"$Upgrade`"")
$products = Get-CimInstance Win32_Product -Filter "Name='MaxNines Command Line'"
Check (@($products).Count -eq 1) 'upgrading replaces the old version'
$path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
Check (@($path.Split(';') | Where-Object { $_ -eq $program }).Count -eq 1) 'its folder is on the PATH once'

# Uninstall.
Msiexec 'uninstall' @('/x', "`"$Upgrade`"")
Check (-not (Test-Path (Join-Path $program 'maxnines.exe'))) 'uninstalling removes the program'
$path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
Check (-not ($path.Split(';') -contains $program)) 'uninstalling takes it off the PATH'
Check (-not (Test-Path 'HKLM:\SOFTWARE\MaxNines\Command Line')) 'uninstalling leaves nothing in the registry'

Write-Host 'The installer works.'
exit 0
