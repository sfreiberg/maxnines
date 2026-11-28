# What a Mac has that other hosts don't: its GPU, which the agent reads on macOS.

template "macos" {
  name        = "macOS"
  description = "What's read on Macs beyond what every host has: the GPU."
  os          = ["macos"]

  # As the config rule named macOS, which applies after Host's.
  config {
    collectors = {
      gpu = { enabled = true }
    }
  }
}
