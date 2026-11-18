# Installs the server's MSI on a Windows machine, as an administrator, and checks
# what it did: the service, the config it wrote, the first administrator and
# their link, the firewall and who can read the data. Then Modify, an upgrade
# and an uninstall.
#
#   packaging/windows/test-server-install.ps1 -Msi maxnines-server.msi -Upgrade newer.msi
param(
    [Parameter(Mandatory)] [string] $Msi,
    # The same server with a higher version.
    [Parameter(Mandatory)] [string] $Upgrade
)
$ErrorActionPreference = 'Stop'
# msiexec can't open a package from a relative path.
$Msi = (Resolve-Path $Msi).Path
$Upgrade = (Resolve-Path $Upgrade).Path

$data = 'C:\ProgramData\MaxNines\Server'
$config = Join-Path $data 'server.hcl'
$program = 'C:\Program Files\MaxNines\Server\'
$temp = $env:RUNNER_TEMP ?? [IO.Path]::GetTempPath()
$logs = Join-Path $temp 'msi-logs'
$link = Join-Path $temp 'MaxNines setup.url'
New-Item -ItemType Directory -Force $logs | Out-Null

function Check([bool] $ok, [string] $what) {
    if (-not $ok) { throw "Failed: $what" }
    Write-Host "ok: $what"
}

function Msiexec([string] $name, [string[]] $arguments) {
    $log = Join-Path $logs "server-$name.log"
    $process = Start-Process msiexec.exe -Wait -PassThru `
        -ArgumentList ($arguments + @('/qn', '/l*v', "`"$log`""))
    if ($process.ExitCode -ne 0) {
        Get-Content $log -Tail 100 | Out-Host
        throw "msiexec $name exited with $($process.ExitCode)"
    }
    $log
}

function Service-Pid {
    (Get-CimInstance Win32_Service -Filter "Name='MaxNinesServer'").ProcessId
}

# The sign-in page, once the server has started, which can take a while the
# first time as it sets up its databases.
function Check-Answering([int] $port, [string] $when, [string] $scheme = 'http') {
    $answered = $false
    for ($i = 0; $i -lt 90 -and -not $answered; $i++) {
        try {
            $response = Invoke-WebRequest "${scheme}://localhost:$port/login" -UseBasicParsing -TimeoutSec 5 -SkipCertificateCheck
            $answered = $response.StatusCode -eq 200
        } catch {
            Start-Sleep -Seconds 1
        }
    }
    if (-not $answered) {
        Get-ChildItem (Join-Path $data 'logs') -File -ErrorAction SilentlyContinue |
            ForEach-Object { Get-Content $_.FullName -Tail 40 }
    }
    Check $answered "the server answers $scheme on port $port $when"
    Check ((Get-Service MaxNinesServer).Status -eq 'Running') "the service is running $when"
}

# A setting's value as text, with HCL's doubled backslashes undone.
function Setting([string] $name) {
    (Get-Content $config -Raw) -match "(?m)^\s*$name\s*=\s*`"([^`"]*)`"" | Out-Null
    $Matches[1].Replace('\\', '\')
}

function Users {
    @(& "$program\maxnines-server.exe" --config $config users list | Where-Object { $_ })
}

# Install, as a silent install with the questions given as properties, and the
# link put where the finish page would open it.
$log = Msiexec 'install' @('/i', "`"$Msi`"", 'SERVER_ADDRESS=http://localhost:9123', 'PORT=9123',
    'ADMIN_EMAIL=admin@example.com', 'ADMIN_NAME="First Admin"', "SETUP_LINK_FILE=`"$link`"")

Check-Answering 9123 'after installing'
Check ((Get-Service MaxNinesServer).StartType -eq 'Automatic') 'the service starts with Windows'
$account = (Get-CimInstance Win32_Service -Filter "Name='MaxNinesServer'").StartName
Check ($account -eq 'NT SERVICE\MaxNinesServer') "the service runs as its own account (found: $account)"
Check ((Setting 'listen') -eq '0.0.0.0:9123') 'the config listens on the port'
Check ((Setting 'public_url') -eq 'ws://localhost:9123/ws') 'the config has the address, as an agent address'
Check ((Setting 'path') -eq (Join-Path $data 'metrics.duckdb')) 'the metrics are kept with the config'

$users = @(Users)
Check ($users.Count -eq 1 -and $users[0] -match 'admin@example.com') "the first administrator is added (found: $users)"
$url = (Get-Content $link | Where-Object { $_ -like 'URL=*' }) -replace '^URL=', ''
Check ($url -like 'http://localhost:9123/setup/*') "the link to set a password is saved for the finish page (found: $url)"
$token = $url.Split('/')[-1]
Check (-not (Select-String -Path $log -SimpleMatch $token -Quiet)) 'the link is not in the log'
$page = Invoke-WebRequest $url -UseBasicParsing
Check ($page.StatusCode -eq 200 -and $page.Content -match 'password') 'the link opens the page for setting a password'

$remembered = Get-ItemProperty 'HKLM:\SOFTWARE\MaxNines\Server'
Check ($remembered.SERVER_ADDRESS -eq 'http://localhost:9123' -and $remembered.PORT -eq '9123' -and $remembered.HTTPS -eq 'none') 'the settings are remembered for Modify'

$acl = Get-Acl $data
$who = $acl.Access | ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique
Check $acl.AreAccessRulesProtected 'the data folder does not inherit permissions'
Check ((Compare-Object $who @('BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM', 'NT SERVICE\MaxNinesServer', 'OWNER RIGHTS')) -eq $null) "only Windows, administrators and the server can open the data folder (found: $($who -join ', '))"
$rights = [Security.AccessControl.FileSystemRights]
$own = $acl.Access | Where-Object { $_.IdentityReference.Value -eq 'NT SERVICE\MaxNinesServer' }
Check (-not ($own | Where-Object { $_.FileSystemRights -band $rights::ChangePermissions })) 'the server cannot change who can open its data folder'
$itself = $own | Where-Object { -not ($_.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) }
Check (-not ($itself.FileSystemRights -band $rights::Delete)) 'the server cannot delete or rename its data folder'
$owners = $acl.Access | Where-Object { $_.IdentityReference.Value -eq 'OWNER RIGHTS' }
Check (-not ($owners.FileSystemRights -band $rights::ChangePermissions)) 'the server cannot change who can open the files it makes'

# The config, and the settings saved for Modify, are out of the server's reach.
$configAcl = Get-Acl $config
$serverOnConfig = $configAcl.Access | Where-Object { $_.IdentityReference.Value -eq 'NT SERVICE\MaxNinesServer' }
Check ($configAcl.AreAccessRulesProtected -and $serverOnConfig -and -not ($serverOnConfig | Where-Object { $_.FileSystemRights -band ($rights::Write -bor $rights::Delete -bor $rights::ChangePermissions) })) 'the server can only read its config'
$keyAcl = Get-Acl 'HKLM:\SOFTWARE\MaxNines\Server'
Check (-not ($keyAcl.Access | Where-Object { $_.IdentityReference.Value -eq 'NT SERVICE\MaxNinesServer' })) 'the server cannot change the settings saved for Modify'

$rule = Get-NetFirewallRule -DisplayName 'MaxNines Server' -ErrorAction SilentlyContinue
Check ($null -ne $rule -and $rule.Direction -eq 'Inbound' -and $rule.Action -eq 'Allow') 'Windows Firewall lets the server through'

$failure = sc.exe qfailure MaxNinesServer | Out-String
Check ($failure -match 'RESTART -- Delay = 30000') "Windows restarts it 30 seconds after a failure:`n$failure"
$path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
Check ($path.Split(';') -contains $program) 'the program is on the PATH'

# Something added by hand has to survive the installer.
Add-Content $config "`nregistration {`n  rule `"office`" {`n    action       = `"approve`"`n    source_cidrs = [`"10.0.0.0/8`"]`n    token_file   = `"office.token`"`n  }`n}"

# Modify, as Settings > Apps does without the dialogs: a new port and address.
$before = Service-Pid
Msiexec 'modify' @('/i', "`"$Msi`"", 'SERVER_ADDRESS=http://localhost:9124', 'PORT=9124') | Out-Null
Check-Answering 9124 'after Modify'
Check ((Service-Pid) -ne $before) 'Modify restarts the service'
Check ((Setting 'public_url') -eq 'ws://localhost:9124/ws') 'Modify changes the address'
Check ((Get-Content $config -Raw) -match 'rule "office"') 'Modify keeps what was added by hand'
Check ((Users).Count -eq 1) 'Modify adds nobody'

# The port changed by hand, then Modify given the answers it would show, as
# they were: the change by hand stays.
(Get-Content $config -Raw).Replace('0.0.0.0:9124', '0.0.0.0:9125').Replace('localhost:9124', 'localhost:9125') |
    Set-Content $config -NoNewline
Restart-Service MaxNinesServer
Check-Answering 9125 'after a change by hand'
Msiexec 'modify-unchanged' @('/i', "`"$Msi`"", 'SERVER_ADDRESS=http://localhost:9124', 'PORT=9124') | Out-Null
Check-Answering 9125 'after Modify with the answers left as they were'
Check ((Get-ItemProperty 'HKLM:\SOFTWARE\MaxNines\Server').PORT -eq '9125') 'Modify remembers the change by hand'

# HTTPS from a certificate in a folder only administrators can open, which
# the server's own account can't read until the installer lets it.
$certs = 'C:\maxnines-test-certs'
New-Item -ItemType Directory -Force $certs | Out-Null
icacls $certs /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
$rsa = [Security.Cryptography.RSA]::Create(2048)
$request = [Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=localhost', $rsa,
    [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
$names = [Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
$names.AddDnsName('localhost')
$request.CertificateExtensions.Add($names.Build())
$certificate = $request.CreateSelfSigned([DateTimeOffset]::Now.AddDays(-1), [DateTimeOffset]::Now.AddDays(30))
Set-Content (Join-Path $certs 'server.crt') $certificate.ExportCertificatePem()
Set-Content (Join-Path $certs 'server.key') $rsa.ExportPkcs8PrivateKeyPem()
Msiexec 'https' @('/i', "`"$Msi`"", 'SERVER_ADDRESS=https://localhost:9126', 'PORT=9126', 'HTTPS=files',
    "CERTIFICATE_FILE=$certs\server.crt", "KEY_FILE=$certs\server.key") | Out-Null
Check-Answering 9126 'with a certificate only administrators could read' 'https'
Check ((Get-ItemProperty 'HKLM:\SOFTWARE\MaxNines\Server').HTTPS -eq 'files') 'HTTPS from files is remembered for Modify'

# An upgrade, without saying anything again.
Msiexec 'upgrade' @('/i', "`"$Upgrade`"") | Out-Null
Check-Answering 9126 'after upgrading' 'https'
Check ((Get-Content $config -Raw) -match 'rule "office"') 'upgrading keeps what was added by hand'
Check ((Users).Count -eq 1) 'upgrading keeps the users'
$products = Get-CimInstance Win32_Product -Filter "Name='MaxNines Server'"
Check (@($products).Count -eq 1) 'upgrading replaces the old version'

# Uninstall.
Msiexec 'uninstall' @('/x', "`"$Upgrade`"") | Out-Null
Check ($null -eq (Get-Service MaxNinesServer -ErrorAction SilentlyContinue)) 'uninstalling removes the service'
Check ($null -eq (Get-NetFirewallRule -DisplayName 'MaxNines Server' -ErrorAction SilentlyContinue)) 'uninstalling removes the firewall rule'
Check (Test-Path $config) 'uninstalling keeps the config'
Check (Test-Path (Join-Path $data 'maxnines.sqlite')) 'uninstalling keeps the databases'
$path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
Check (-not ($path.Split(';') -contains $program)) 'uninstalling takes the program off the PATH'

Remove-Item $certs -Recurse -Force

Write-Host 'The installer works.'
