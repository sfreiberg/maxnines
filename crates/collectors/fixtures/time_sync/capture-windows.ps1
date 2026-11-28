# Captures the Windows Time Service's performance counters, with what w32tm says
# beside them, as found, after a resync, with the service stopped and started
# again, so the time_sync collector is tested against what Windows really says.
# Meant for capture-time-sync-outputs.yml.
$ErrorActionPreference = 'Continue'
$version = [Environment]::OSVersion.Version
$out = "out/windows-$($version.Major).$($version.Minor).$($version.Build)"
New-Item -ItemType Directory -Force $out | Out-Null

function Capture($name) {
    try {
        (Get-Counter -Counter '\Windows Time Service\*' -ErrorAction Stop).CounterSamples |
            Select-Object Path, CookedValue, Status |
            ConvertTo-Json -Compress |
            Set-Content -NoNewline "$out/$name.json"
    } catch {
        $_.Exception.Message | Set-Content -NoNewline "$out/$name.error"
    }
    w32tm /query /status /verbose *> "$out/$name.w32tm.txt"
}

w32tm /query /source *> "$out/source.txt"
w32tm /query /configuration *> "$out/configuration.txt"
(Get-Service w32time).Status | Set-Content -NoNewline "$out/service.txt"
Capture 'as-found'
w32tm /resync /force *> "$out/resync.txt"
Start-Sleep 30
Capture 'resynced'
Stop-Service w32time -Force
Start-Sleep 5
Capture 'stopped'
Start-Service w32time
Start-Sleep 30
Capture 'started'
