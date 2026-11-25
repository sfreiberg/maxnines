# Builds a Storage Spaces pool on virtual hard disks and keeps what the agent's
# raid collector reads at each step, by running its own script, crates/agent/src/raid.ps1:
# no pools, healthy mirror, parity and simple virtual disks, one disk gone, and a
# repair once it's back. What Windows' own commands say in full is kept beside it.
# The capture-raid-outputs workflow runs it as an administrator on a Windows
# runner, in Windows PowerShell as the agent does, by hand only. Each step is kept
# under out/<system>/storage-spaces/.
$ErrorActionPreference = 'Continue'
$os = Get-CimInstance Win32_OperatingSystem
$root = if ($env:OUT) { $env:OUT } else { 'out' }
$out = Join-Path $root ("windows-" + $os.Version + "\storage-spaces")
New-Item -ItemType Directory -Force -Path $out | Out-Null
$script = Join-Path $PSScriptRoot '..\..\src\raid.ps1'
$work = 'C:\raid-capture'
New-Item -ItemType Directory -Force -Path $work | Out-Null
"$($os.Caption) $($os.Version)" | Set-Content -Encoding ascii (Join-Path $out 'version')

function Snap($step) {
    # As the agent runs it.
    $agent = & powershell.exe -NoProfile -NonInteractive -Command (Get-Content -Raw $script) 2>&1
    $code = $LASTEXITCODE
    [IO.File]::WriteAllText((Join-Path $out "$step.json"), (($agent | Out-String).TrimEnd() + "`n"))
    "$code" | Set-Content -Encoding ascii (Join-Path $out "$step.code")
    # Everything Windows says, for reference.
    $full = [ordered]@{
        Pools = @(Get-StoragePool | Select-Object -Property * -ExcludeProperty Cim*)
        VirtualDisks = @(Get-VirtualDisk | Select-Object -Property * -ExcludeProperty Cim*)
        PhysicalDisks = @(Get-PhysicalDisk | Select-Object -Property * -ExcludeProperty Cim*)
        Jobs = @(Get-StorageJob | Select-Object -Property * -ExcludeProperty Cim*)
    }
    [IO.File]::WriteAllText((Join-Path $out "$step.full.json"), (ConvertTo-Json -Depth 3 -InputObject $full))
    Write-Output "== $step"
    $agent
}

function Invoke-DiskPart($lines) {
    $file = Join-Path $work 'diskpart.txt'
    [IO.File]::WriteAllLines($file, $lines)
    diskpart.exe /s $file | Out-Null
}

Snap 'empty'

$vhds = 1..3 | ForEach-Object { Join-Path $work "disk$_.vhdx" }
foreach ($vhd in $vhds) {
    Invoke-DiskPart @("create vdisk file=`"$vhd`" maximum=8192 type=expandable", "select vdisk file=`"$vhd`"", 'attach vdisk')
}
Start-Sleep -Seconds 5
$poolable = @(Get-PhysicalDisk -CanPool $true)
Get-PhysicalDisk | Select-Object FriendlyName, BusType, CanPool, CannotPoolReason, Size |
    Format-Table -AutoSize | Out-String -Width 200 | Set-Content -Encoding ascii (Join-Path $out 'poolable.txt')
Get-Content (Join-Path $out 'poolable.txt')

$subsystem = Get-StorageSubSystem | Where-Object { $_.FriendlyName -like 'Windows Storage*' } | Select-Object -First 1
New-StoragePool -FriendlyName 'Pool1' -StorageSubSystemUniqueId $subsystem.UniqueId -PhysicalDisks $poolable | Out-Null
New-VirtualDisk -StoragePoolFriendlyName 'Pool1' -FriendlyName 'Mirror1' -ResiliencySettingName Mirror -NumberOfDataCopies 2 -Size 2GB -ProvisioningType Fixed | Out-Null
New-VirtualDisk -StoragePoolFriendlyName 'Pool1' -FriendlyName 'Parity1' -ResiliencySettingName Parity -Size 2GB -ProvisioningType Fixed | Out-Null
New-VirtualDisk -StoragePoolFriendlyName 'Pool1' -FriendlyName 'Simple1' -ResiliencySettingName Simple -Size 1GB -ProvisioningType Fixed | Out-Null
Start-Sleep -Seconds 5
Snap 'healthy'

# One disk goes away.
Invoke-DiskPart @("select vdisk file=`"$($vhds[2])`"", 'detach vdisk')
Start-Sleep -Seconds 15
Snap 'disk-gone'

# It comes back and the virtual disks are repaired.
Invoke-DiskPart @("select vdisk file=`"$($vhds[2])`"", 'attach vdisk')
Start-Sleep -Seconds 10
Snap 'disk-back'
Get-VirtualDisk | Where-Object { $_.FriendlyName -ne 'Simple1' } | Repair-VirtualDisk -AsJob | Out-Null
$seen = $false
foreach ($try in 1..300) {
    $running = @(Get-StorageJob | Where-Object { [string]$_.JobState -eq 'Running' })
    if ($running.Count -gt 0) {
        Snap 'repairing'
        $seen = $true
        break
    }
    Start-Sleep -Milliseconds 200
}
if (-not $seen) { Write-Output 'never saw a repair running' }
foreach ($try in 1..300) {
    if (@(Get-StorageJob | Where-Object { [string]$_.JobState -eq 'Running' }).Count -eq 0) { break }
    Start-Sleep -Seconds 1
}
Start-Sleep -Seconds 5
Snap 'repaired'
exit 0
