# Updates

The `updates` collector reads whether a host is up to date: how many updates are
waiting, how many of them fix security problems where the system says so, whether the
host needs a reboot to finish an update, and how long ago its package lists were
refreshed. It's on for every host, from the built-in **Host** template's settings, and
the built-in **Updates** template alerts on what it reads.

Each host is asked every hour, and first within two minutes of the agent starting. The
host's page shows what was found under **Updates**, and the
[API](api-host-readings.md#get-a-hosts-updates) gives it too.

## How each system is read

Each system is asked through the package manager its distribution uses, picked from
`/etc/os-release` on Linux. The agent never refreshes the package lists itself: it
reads the ones the system already has, which the system's own timers keep fresh, and
reports how old they are so lists that have stopped being refreshed are noticed.

| System | Asks | Security updates | Reboot required |
| --- | --- | --- | --- |
| Debian, Ubuntu and others like them | `apt-get -s dist-upgrade`, a simulation that changes nothing and takes no lock | Those coming from a `-security` archive | A newer kernel installed, or `/run/reboot-required` |
| RHEL, Rocky, Alma, CentOS, Fedora, Amazon Linux | `dnf -C check-update`, or yum where there's no dnf | `dnf -C updateinfo list --security`, counting packages | A newer kernel installed, or `needs-restarting -r` |
| openSUSE and SLES | `zypper --no-refresh list-updates` | `zypper --no-refresh list-patches --category security`, counting patches | A newer kernel installed |
| Arch | `checkupdates --nosync`, from pacman-contrib | Not published by Arch | A newer kernel installed |
| Alpine | `apk --no-network list --upgradable` | Not published by Alpine | A newer kernel installed |
| FreeBSD | `pkg version -vURl '<'` | Not counted: `pkg audit` gives packages with known vulnerabilities instead | The installed kernel differs from the running one |
| macOS | `softwareupdate -l --no-scan`, what macOS's own daily check last found | Not counted | Not reported |
| Windows | Windows Update, searching what it last found | Updates with a Microsoft security rating, or in the Security Updates category | Windows Update or Windows' servicing says a reboot is waiting |

A newer kernel means one of the same kind as the running one, such as Ubuntu's
`-generic`, with a higher version in `/lib/modules`, or the running kernel's own
modules gone, as Arch removes them when it upgrades. A container sees no kernels, so it
reports no reboot either way.

On macOS, an upgrade to the next major version, such as macOS 27 from macOS 26, is
listed by softwareupdate but isn't counted: it's an upgrade to choose, not an update
waiting.

On Windows, `PendingFileRenameOperations` isn't read, as installers and antivirus set
it all the time without a reboot being needed.

### What it needs

- **Arch:** `checkupdates` comes with pacman-contrib, and needs fakeroot, which it
  doesn't bring: `pacman -S pacman-contrib fakeroot`. Without either, the host's page
  says so and nothing is read.
- Everything reads as the agent's own user, with nothing to set up and no root. dnf and
  yum read the system's package lists with `-C` whoever runs them.

### Keeping package lists fresh

What's waiting is only as current as the package lists:

- Debian and Ubuntu refresh them twice a day with `apt-daily.timer`.
- Fedora and RHEL's family refresh them with `dnf-makecache.timer`. dnf only fetches
  lists that have expired, by default after 48 hours, so they can be two days old.
- openSUSE refreshes them as its update timers run.
- Arch, Alpine and FreeBSD don't refresh them on their own. Run `pacman -Sy`,
  `apk update` or `pkg update` on a schedule, such as from cron, or the **Package lists
  not refreshed** alert will say so.
- macOS checks once a day, and Windows Update on its own schedule.

## What's reported

Each metric has one series for the host. A metric the system doesn't report, such as
security updates on Arch, has no series.

| Metric | Unit | Series | What it is |
| --- | --- | --- | --- |
| `updates.pending` | Number | The host | Updates waiting to be installed |
| `updates.security` | Number | The host | How many of them fix security problems, where the system says |
| `updates.vulnerable` | Number | The host, on FreeBSD | Installed packages with known vulnerabilities, from `pkg audit` |
| `updates.reboot_required` | 1 or 0 | The host | Whether it needs a reboot to finish an update |
| `updates.lists_age` | Seconds | The host | How long ago its package lists were refreshed |

## Built-in alerts

The built-in **Updates** template brings these:

| Alert | When | Severity |
| --- | --- | --- |
| **Security updates waiting** | Security updates have been waiting for 3 days | Warning |
| **Reboot required** | The host has needed a reboot for 7 days | Warning |
| **Package lists not refreshed** | The package lists are more than 7 days old | Warning |
| **Packages with known vulnerabilities** | FreeBSD's `pkg audit` has listed vulnerable packages for a day | Warning |

The waits leave time for automatic updates, or a weekly patch day, to get there first.
Each can be changed or turned off on the template's page. A wait carries on through a
restart of the server.
