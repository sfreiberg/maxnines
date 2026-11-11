# MaxNines

MaxNines is fast, low-resource, open source monitoring software, written in Rust.
It's meant to be running and useful within minutes of installing it, with great
defaults instead of a pile of configuration.

![The overview, with every host's health at a glance](docs/screenshots/overview.png)

![A host's charts, updating live](docs/screenshots/charts.png)

## Goals

- **Fast and light.** A small agent that barely registers on the hosts it
  watches, and a server that handles a large fleet on modest hardware.
- **Quick to set up.** Install the server, add agents, and see useful charts and
  alerts straight away.
- **Great defaults.** The things most people need to watch are covered out of the
  box, with sensible alerts, so configuration is for fine-tuning rather than
  getting started.
- **Open source and self-hosted.** It runs on your own servers and your data stays
  with you.

MaxNines is in early development and isn't ready for production use yet.

## Documentation

The [documentation](docs/SUMMARY.md) covers installing, setting up and using
MaxNines. Every server also shows it on its Docs page, matching the version it runs.
Start with [Installing](docs/installing.md).

The [database design](database/README.md) shows every table and how they connect.

## Get in touch

If you'd like to help guide the project, we'd love to hear from you. What you need
from monitoring, what gets in your way today, and what you'd leave out are all
welcome and genuinely useful. Open an issue or start a discussion here on GitHub.
