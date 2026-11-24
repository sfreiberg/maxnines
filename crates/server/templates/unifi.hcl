# What's watched on the UniFi devices a UniFi check reads, each a host of its own.
# A device going offline is its host going offline, which the Host template's
# alert covers, so these are what's left: a device working too hard, and
# firmware waiting.

template "unifi" {
  name        = "UniFi"
  description = "The devices a UniFi console has adopted, read by a UniFi check: their CPU and memory, and firmware waiting to be put on."

  # A device's host has facts under unifi, which nothing else has.
  applies_to = "has(facts.unifi)"

  alert "cpu_high" {
    name     = "UniFi device CPU high"
    warning  = "unifi.cpu > 80"
    critical = "unifi.cpu > 95"
    for      = "10m"
  }

  # A console keeps much of its memory busy on purpose, so only nearly all of it
  # counts.
  alert "memory_high" {
    name     = "UniFi device memory high"
    warning  = "unifi.memory > 90"
    critical = "unifi.memory > 97"
    for      = "15m"
  }

  # Many put updates on by hand at a time that suits them, so this is off until
  # turned on.
  alert "firmware_update" {
    name    = "UniFi firmware update available"
    warning = "unifi.firmware_update > 0"
    for     = "1d"
    enabled = false
  }
}
