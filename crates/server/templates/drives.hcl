# Each drive's SMART health, which the agent reads with smartctl on Linux, macOS
# and FreeBSD, and from Windows' own storage counters on Windows. The Host
# template's settings turn the smart collector on.

template "drives" {
  name        = "Drives"
  description = "Each drive's SMART health: whether it passes its own assessment, its temperature, bad sectors and wear."

  alert "drive_failing" {
    name     = "Drive failing"
    critical = "smart.healthy < 1"
    for      = "1m"
    summary  = "Drive {{ series }} on {{ hostname }} fails its own SMART assessment"
  }

  # Reallocated sectors were moved in time, but any at all is the best sign
  # there is that a disk is on its way out. Each count is its own alert, as a
  # drive that doesn't report one would otherwise silence the other.
  alert "drive_reallocated" {
    name    = "Drive has reallocated sectors"
    warning = "smart.reallocated > 0"
    for     = "1m"
  }

  # Sectors waiting to be reallocated are ones the drive couldn't read, so data
  # may already be lost.
  alert "drive_unreadable" {
    name     = "Drive has unreadable sectors"
    critical = "smart.pending > 0"
    for      = "1m"
  }

  # An NVMe drive reports all three together.
  alert "drive_spare_low" {
    name     = "Drive running out of spare"
    critical = "smart.spare < smart.spare_threshold || smart.critical_warning > 0"
    for      = "1m"
  }

  alert "drive_worn" {
    name    = "Drive nearly worn out"
    warning = "smart.used >= 90"
    for     = "1m"
  }

  alert "drive_hot" {
    name     = "Drive too hot"
    warning  = "smart.temperature > 60"
    critical = "smart.temperature > 70"
    for      = "15m"
  }
}
