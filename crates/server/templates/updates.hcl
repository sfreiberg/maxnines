# Whether each host is up to date, which the agent reads from the host's own
# package manager: apt, dnf, zypper, pacman or apk on Linux, pkg on FreeBSD,
# softwareupdate on macOS and Windows Update on Windows. The Host template's
# settings turn the updates collector on.

template "updates" {
  name        = "Updates"
  description = "Whether each host is up to date: updates and security updates waiting, a reboot waiting to finish one, and package lists that have stopped being refreshed."

  # A few days leaves time for automatic updates, or a weekly patch day, to get
  # there first.
  alert "security_updates" {
    name    = "Security updates waiting"
    warning = "updates.security > 0"
    for     = "3d"
    summary = "{{ hostname }} has {{ updates.security }} security updates waiting"
  }

  alert "reboot_required" {
    name    = "Reboot required"
    warning = "updates.reboot_required >= 1"
    for     = "7d"
    summary = "{{ hostname }} has needed a reboot to finish updating for a week"
  }

  # dnf only refreshes lists that have expired, after up to two days, so a week
  # means the timer that refreshes them has stopped.
  alert "lists_stale" {
    name    = "Package lists not refreshed"
    warning = "updates.lists_age > duration('168h')"
    for     = "1h"
    summary = "{{ hostname }}'s package lists haven't been refreshed for {{ updates.lists_age }}"
  }

  # FreeBSD's pkg audit lists installed packages with known vulnerabilities.
  alert "vulnerable_packages" {
    name    = "Packages with known vulnerabilities"
    warning = "updates.vulnerable > 0"
    for     = "1d"
    summary = "{{ hostname }} has {{ updates.vulnerable }} packages with known vulnerabilities"
  }
}
