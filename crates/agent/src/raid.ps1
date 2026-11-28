# Each Storage Spaces virtual disk, with its pool, its health and the repairs
# running on it, as JSON, always a list. The agent's raid collector runs it in
# Windows PowerShell, and the capture-raid-outputs workflow runs this same file.
$ErrorActionPreference = 'Stop'
$found = foreach ($pool in @(Get-StoragePool | Where-Object { -not $_.IsPrimordial })) {
    $disks = @($pool | Get-PhysicalDisk)
    $unhealthy = @($disks | Where-Object { [string]$_.HealthStatus -ne 'Healthy' }).Count
    foreach ($disk in @($pool | Get-VirtualDisk)) {
        $jobs = @($disk | Get-StorageJob | Where-Object { [string]$_.JobState -eq 'Running' } | ForEach-Object {
            [pscustomobject]@{
                Name = $_.Name
                PercentComplete = $_.PercentComplete
                BytesProcessed = $_.BytesProcessed
                BytesTotal = $_.BytesTotal
            }
        })
        [pscustomobject]@{
            Name = $disk.FriendlyName
            Pool = $pool.FriendlyName
            Resiliency = $disk.ResiliencySettingName
            HealthStatus = [string]$disk.HealthStatus
            OperationalStatus = @($disk.OperationalStatus | ForEach-Object { [string]$_ })
            Disks = $disks.Count
            UnhealthyDisks = $unhealthy
            Jobs = $jobs
        }
    }
}
ConvertTo-Json -Compress -Depth 4 -InputObject @($found)
