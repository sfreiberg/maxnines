# Each Storage Spaces virtual disk, with its pool, its health and how far a repair
# has got, as JSON, always a list. The agent's raid collector runs it in Windows
# PowerShell, and the capture-raid-outputs workflow runs this same file.
$ErrorActionPreference = 'Stop'
$found = foreach ($pool in @(Get-StoragePool | Where-Object { -not $_.IsPrimordial })) {
    $disks = @($pool | Get-PhysicalDisk)
    $unhealthy = @($disks | Where-Object { [string]$_.HealthStatus -ne 'Healthy' }).Count
    foreach ($disk in @($pool | Get-VirtualDisk)) {
        $job = @($disk | Get-StorageJob | Where-Object { [string]$_.JobState -eq 'Running' }) | Select-Object -First 1
        [pscustomobject]@{
            Name = $disk.FriendlyName
            Pool = $pool.FriendlyName
            Resiliency = $disk.ResiliencySettingName
            Redundancy = $disk.PhysicalDiskRedundancy
            HealthStatus = [string]$disk.HealthStatus
            OperationalStatus = @($disk.OperationalStatus | ForEach-Object { [string]$_ })
            Size = $disk.Size
            Disks = $disks.Count
            UnhealthyDisks = $unhealthy
            RepairPercent = $job.PercentComplete
        }
    }
}
ConvertTo-Json -Compress -InputObject @($found)
