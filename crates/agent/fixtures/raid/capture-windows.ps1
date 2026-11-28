# Builds a Storage Spaces pool on virtual hard disks and keeps what the agent's
# raid collector reads at each step, by running its own script,
# crates/agent/src/raid.ps1: no pools, healthy mirror, parity and simple virtual
# disks, one disk gone, a repair once it's back, and a disk retired and repaired
# away from. What Windows' own commands say in full is kept beside it.
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

$vhds = 1..4 | ForEach-Object { Join-Path $work "disk$_.vhdx" }
foreach ($vhd in $vhds) {
    Invoke-DiskPart @("create vdisk file=`"$vhd`" maximum=8192 type=expandable", "select vdisk file=`"$vhd`"", 'attach vdisk')
}
Start-Sleep -Seconds 5
# Only the virtual hard disks: some runners have a spare disk of their own.
$poolable = @(Get-PhysicalDisk -CanPool $true | Where-Object { [string]$_.BusType -eq 'File Backed Virtual' })
Get-PhysicalDisk | Select-Object FriendlyName, BusType, CanPool, CannotPoolReason, Size |
    Format-Table -AutoSize | Out-String -Width 200 | Set-Content -Encoding ascii (Join-Path $out 'poolable.txt')
Get-Content (Join-Path $out 'poolable.txt')

$subsystem = Get-StorageSubSystem | Where-Object { $_.FriendlyName -like 'Windows Storage*' } | Select-Object -First 1
New-StoragePool -FriendlyName 'Pool1' -StorageSubSystemUniqueId $subsystem.UniqueId -PhysicalDisks $poolable | Out-Null
New-VirtualDisk -StoragePoolFriendlyName 'Pool1' -FriendlyName 'Mirror1' -ResiliencySettingName Mirror -NumberOfDataCopies 2 -Size 2GB -ProvisioningType Fixed | Out-Null
New-VirtualDisk -StoragePoolFriendlyName 'Pool1' -FriendlyName 'Parity1' -ResiliencySettingName Parity -NumberOfColumns 3 -Size 2GB -ProvisioningType Fixed | Out-Null
New-VirtualDisk -StoragePoolFriendlyName 'Pool1' -FriendlyName 'Simple1' -ResiliencySettingName Simple -NumberOfColumns 4 -Size 1GB -ProvisioningType Fixed | Out-Null
Start-Sleep -Seconds 5
Snap 'healthy'

# Wait-Repair: catches a repair running, if one does, then waits for them all.
function Wait-Repair($step) {
    foreach ($try in 1..300) {
        if (@(Get-StorageJob | Where-Object { [string]$_.JobState -eq 'Running' }).Count -gt 0) {
            Snap $step
            Write-Output (Get-StorageJob | Format-Table Name, JobState, PercentComplete, BytesProcessed, BytesTotal | Out-String)
            break
        }
        Start-Sleep -Milliseconds 200
    }
    foreach ($try in 1..300) {
        if (@(Get-StorageJob | Where-Object { [string]$_.JobState -eq 'Running' }).Count -eq 0) { break }
        Start-Sleep -Seconds 1
    }
}

# A volume on the mirror, so a repair has something to copy.
Get-VirtualDisk -FriendlyName 'Mirror1' | Get-Disk | Initialize-Disk -PartitionStyle GPT -PassThru |
    New-Partition -UseMaximumSize -DriveLetter M | Format-Volume -FileSystem NTFS -Confirm:$false | Out-Null

# One disk goes away, as if pulled.
Dismount-DiskImage -ImagePath $vhds[3] | Out-Null
Start-Sleep -Seconds 15
Snap 'disk-gone'

# Written to while it was gone, the mirror has a copy to bring up to date when it
# comes back.
$block = New-Object byte[] (64MB)
(New-Object Random).NextBytes($block)
$file = [IO.File]::OpenWrite('M:\data.bin')
foreach ($i in 1..16) { $file.Write($block, 0, $block.Length) }
$file.Close()
Mount-DiskImage -ImagePath $vhds[3] -NoDriveLetter | Out-Null
Get-VirtualDisk | Where-Object { $_.FriendlyName -ne 'Simple1' } | Repair-VirtualDisk -AsJob | Out-Null
Wait-Repair 'repairing'
Start-Sleep -Seconds 5
Snap 'repaired'

# A disk retired, as before replacing it, which the mirror is repaired away from.
$retired = Get-PhysicalDisk | Where-Object { [string]$_.BusType -eq 'File Backed Virtual' } | Select-Object -First 1
$retired | Set-PhysicalDisk -Usage Retired
Start-Sleep -Seconds 5
Snap 'retired'
Get-VirtualDisk -FriendlyName 'Mirror1' | Repair-VirtualDisk -AsJob | Out-Null
Wait-Repair 'retired-repairing'
Start-Sleep -Seconds 5
Snap 'retired-repaired'
exit 0
