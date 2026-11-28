# Introduction

MaxNines is fast, low-resource, open source monitoring software, written in Rust.
It's meant to be running and useful within minutes of installing it, with great
defaults instead of a pile of configuration.

It's two programs:

- **`maxnines-server`** keeps the metrics, shows these pages, sends alerts and answers
  the [API](api.md). You run one, and everything it offers shares a single port.
- **`maxnines-agent`** runs on each host you want to watch, and reports to the
  server over one connection. What it watches is set on the server, so an agent's own
  config only says how to reach it.

To get started, [install](installing.md) the server, add the first
[user](users.md), then install an agent on each host and approve it on the
Hosts page.

This documentation comes with the server, on its Docs page, so it always describes
the version you're running.

## Getting help

- **Questions, ideas and how you're using MaxNines:** start a thread in
  [Discussions](https://github.com/sfreiberg/maxnines/discussions).
- **Something that's broken:** open an
  [issue](https://github.com/sfreiberg/maxnines/issues). Say which version you run,
  which `maxnines-server version` and `maxnines-agent version` print, and what you saw.
- **A security problem:** email [security@maxnines.com](mailto:security@maxnines.com)
  rather than posting it in public.
