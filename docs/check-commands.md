# Check commands

Thousands of monitoring plugins already exist in the Nagios style, for databases,
RAID controllers, appliances, licences and much else, and most teams have a few of
their own. An agent can run them as **check commands**, so anything one of them
checks shows up in MaxNines with nothing else to install.

The [Monitoring Plugins](https://www.monitoring-plugins.org/) project has the common
ones, packaged as `monitoring-plugins` on Debian and Ubuntu, `nagios-plugins-all` on
Fedora and RHEL (from EPEL), and `monitoring-plugins` in Homebrew.

## Defining one

A check command is defined in the agent's own config file, `agent.hcl`, by name:

```hcl
check_command "raid" {
  command = ["/usr/lib/nagios/plugins/check_raid"]
}

check_command "ntp" {
  command      = ["/usr/lib/nagios/plugins/check_ntp_time", "-H", "pool.ntp.org", "-w", "0.5", "-c", "1"]
  timeout_secs = 20
}
```

- `command` is the program, then each of its arguments. It runs directly, not through
  a shell, so there's no quoting to get wrong and nothing a shell would expand.
- `timeout_secs` is how long it gets, from 1 to 300 seconds. It defaults to 30. One
  that takes longer is stopped, along with anything it started, and counts as
  unknown.
- A name has letters, digits, `.`, `-` and `_`.

Restart the agent after changing the file. Then list the names under **Check
commands** in a [config rule](api-config-rules.md), one to a line, to run them on the
hosts the rule applies to. They run with every sample, or less often if the rule's
interval says so.

The server only chooses which names to run. It can never add a command or change one,
so whoever controls the server can't make a host run anything new. A name the server
asks for that a host doesn't define reports as unknown, saying so.

## What's reported

A plugin says how things are by how it exits:

| Exit code | Status |
|---|---|
| 0 | OK |
| 1 | Warning |
| 2 | Critical |
| 3, or anything else | Unknown |

| Metric | What it is |
|---|---|
| **Check command status** | The status above, as 0 to 3 |
| **Check command passing** | 1 while it's OK, 0 otherwise, which isn't charted |
| **Check command values** | Its performance data, as below |

The first line a plugin prints says why, such as `RAID CRITICAL - md0 degraded`. Up
to 256 characters of it are sent to the server and shown on the host's metrics page
beside each command's status. Don't use a plugin that prints a secret on its first
line.

### Performance data

Anything after a `|` on the first line, or on a later line, is performance data:
values separated by spaces, each as `label=value[unit];warn;crit;min;max`.

```text
DISK OK - free space: / 3326 MB (56%); | /=2643MB;5948;5958;0;5968 'root inodes'=12%
```

Each value becomes a series named by the command and its label, such as `disk /` and
`disk root inodes`. Times are kept in seconds and sizes in bytes, so `250ms` becomes
0.25 and `2KB` becomes 2048. Percentages and counters (`c`) are kept as they are. The
warning and critical levels after the value are left out, as an alert rule sets its
own. A value of `U`, meaning it couldn't be measured, is skipped, and so is anything
that isn't a number. Up to 32 values are kept from each run.

## Writing your own

A check command can be any program, in any language, that:

- prints one line saying how things are, with any
  [performance data](#performance-data) after a `|`
- exits with 0 for OK, 1 for a warning, 2 for critical or 3 for unknown

The agent runs it as its own user, gives it no input, and reads up to 8 KiB of what it
prints. Anything it prints to standard error is ignored. It has to finish within its
`timeout_secs`, 30 seconds unless the definition says otherwise.

Some things to keep in mind:

- When it can't tell how things are, such as a directory it can't read, it should say
  why and exit with 3, rather than report OK.
- The first line is shown in MaxNines, so it shouldn't contain a password or anything
  else secret.
- It can decide what's a warning and what's critical itself, as the examples below do,
  or always exit with 0 and only report values, leaving the limits to an alert rule on
  **Check command values**. Limits in an alert rule can be changed in MaxNines without
  touching the host.

### Examples

Each of these counts the files in a directory, warning at 10 and critical at 50:

```text
FILES WARNING - 12 files in /srv/queue | files=12
```

They report `files` as a value, which MaxNines names after the check command, such as
`queue files` for one defined as `queue`.

**Bash**, or any other shell, saved as `check_files` and made executable with
`chmod +x check_files`:

```sh
#!/bin/sh
# Counts the files in a directory: a warning at 10, critical at 50.
dir="$1"
if [ ! -d "$dir" ]; then
  echo "FILES UNKNOWN - $dir isn't a directory"
  exit 3
fi
count=$(find "$dir" -maxdepth 1 -type f | wc -l | tr -d ' ')
if [ "$count" -ge 50 ]; then
  status=CRITICAL code=2
elif [ "$count" -ge 10 ]; then
  status=WARNING code=1
else
  status=OK code=0
fi
echo "FILES $status - $count files in $dir | files=$count"
exit $code
```

**Python**, saved as `check_files` and made executable with `chmod +x check_files`:

```python
#!/usr/bin/env python3
"""Counts the files in a directory: a warning at 10, critical at 50."""
import os
import sys

directory = sys.argv[1] if len(sys.argv) > 1 else ""
try:
    count = sum(1 for entry in os.scandir(directory) if entry.is_file())
except OSError as error:
    print(f"FILES UNKNOWN - can't read {directory}: {error.strerror}")
    sys.exit(3)

if count >= 50:
    status, code = "CRITICAL", 2
elif count >= 10:
    status, code = "WARNING", 1
else:
    status, code = "OK", 0
print(f"FILES {status} - {count} files in {directory} | files={count}")
sys.exit(code)
```

**Go**, built with `go build -o check_files` in a directory with this as `main.go`,
after `go mod init check_files`:

```go
// Counts the files in a directory: a warning at 10, critical at 50.
package main

import (
	"fmt"
	"os"
)

func main() {
	dir := ""
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Printf("FILES UNKNOWN - %v\n", err)
		os.Exit(3)
	}
	count := 0
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			count++
		}
	}

	status, code := "OK", 0
	if count >= 50 {
		status, code = "CRITICAL", 2
	} else if count >= 10 {
		status, code = "WARNING", 1
	}
	fmt.Printf("FILES %s - %d files in %s | files=%d\n", status, count, dir, count)
	os.Exit(code)
}
```

**Rust**, built with `rustc -O main.rs -o check_files`, or as `src/main.rs` in a Cargo
project:

```rust
// Counts the files in a directory: a warning at 10, critical at 50.
use std::{env, fs, process};

fn main() {
    let dir = env::args().nth(1).unwrap_or_default();
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) => {
            println!("FILES UNKNOWN - can't read {dir}: {error}");
            process::exit(3);
        }
    };
    let count = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .count();

    let (status, code) = if count >= 50 {
        ("CRITICAL", 2)
    } else if count >= 10 {
        ("WARNING", 1)
    } else {
        ("OK", 0)
    };
    println!("FILES {status} - {count} files in {dir} | files={count}");
    process::exit(code);
}
```

### Running one

Copy it to the host, then define it in `agent.hcl` as above:

```hcl
check_command "queue" {
  command = ["/usr/local/bin/check_files", "/srv/queue"]
}
```

A script runs through its `#!` line, so it needs one, and needs to be executable. On
Windows, which doesn't read `#!` lines, name the interpreter first, by its full path
on that host:

```hcl
check_command "queue" {
  command = ["C:\\Program Files\\Python313\\python.exe", "C:\\checks\\check_files.py", "D:\\queue"]
}
```

Go and Rust build to a single program with nothing else to install. Build it for the
host's system, such as with `GOOS=linux GOARCH=amd64 go build` or
`cargo build --release --target x86_64-unknown-linux-musl`.

Before relying on one, run it as the agent's user and check what it prints and its
exit code:

```sh
./check_files /srv/queue; echo "exit $?"
```

## Alerting

To be told when a plugin says something is wrong, add an alert rule on **Check command
status** for the command, such as **above 1** for critical and **above 0** for a
warning first. Its performance data can be alerted on like any other metric.
