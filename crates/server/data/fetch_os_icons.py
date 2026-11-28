#!/usr/bin/env python3
"""Fetches the operating system logos the pages show next to each machine.

The logos are the projects' own, from two open source icon sets at fixed versions:

- Simple Icons (CC0, https://simpleicons.org) for everything it has.
- Font Awesome Free (icons CC BY 4.0, https://fontawesome.com) for Windows, which
  Simple Icons doesn't carry. Its notice stays in the file, which is the credit
  the licence asks for.

The logos themselves are their owners' trademarks, used only to show which system
a machine runs. NetBSD is left out: its logo may not be cut down to fit an icon
without the NetBSD Foundation's written permission.

Run it from anywhere, and commit what it writes:

    python3 crates/server/data/fetch_os_icons.py

Systems the pages draw go in assets/static/os, which is built into the server.
Linux distributions go in data/os-icons/distributions, kept for later and not
built in.
"""

import re
import sys
import urllib.request
from pathlib import Path

SIMPLE_ICONS = "https://cdn.jsdelivr.net/npm/simple-icons@16.37.0/icons/{}.svg"
FONT_AWESOME = "https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@7.3.1/svgs/brands/{}.svg"

# The name the server gives each system, and where its logo comes from.
SYSTEMS = {
    "macos": SIMPLE_ICONS.format("apple"),
    "linux": SIMPLE_ICONS.format("linux"),
    "windows": FONT_AWESOME.format("windows"),
    "freebsd": SIMPLE_ICONS.format("freebsd"),
    "openbsd": SIMPLE_ICONS.format("openbsd"),
}

DISTRIBUTIONS = [
    "almalinux", "alpinelinux", "archlinux", "centos", "debian", "deepin",
    "elementary", "endeavouros", "fedora", "gentoo", "kalilinux", "kubuntu",
    "linuxmint", "manjaro", "mxlinux", "nixos", "opensuse", "popos",
    "raspberrypi", "redhat", "rockylinux", "slackware", "suse", "ubuntu",
    "voidlinux", "zorin",
]

HERE = Path(__file__).resolve().parent
BUILT_IN = HERE.parent / "assets" / "static" / "os"
KEPT = HERE / "os-icons" / "distributions"


def fetch(url):
    with urllib.request.urlopen(url, timeout=30) as response:
        return response.read().decode("utf-8")


def tidy(svg):
    """Keeps the drawing and any licence notice. The pages give each icon its own
    name, so the set's title goes, and the shape is drawn as a mask in the page's
    own colour, so colours don't matter."""
    if not svg.lstrip().startswith("<svg") or "<script" in svg or re.search(r"\son\w+\s*=", svg):
        raise ValueError("not a plain SVG")
    svg = re.sub(r"<title>.*?</title>", "", svg, flags=re.S)
    svg = re.sub(r'\s(role|fill)="[^"]*"', "", svg)
    return svg.strip() + "\n"


def main():
    BUILT_IN.mkdir(parents=True, exist_ok=True)
    KEPT.mkdir(parents=True, exist_ok=True)
    for name, url in SYSTEMS.items():
        (BUILT_IN / f"{name}.svg").write_text(tidy(fetch(url)))
        print(f"{name}: {url}")
    for name in DISTRIBUTIONS:
        url = SIMPLE_ICONS.format(name)
        (KEPT / f"{name}.svg").write_text(tidy(fetch(url)))
        print(f"{name}: {url}")


if __name__ == "__main__":
    sys.exit(main())
