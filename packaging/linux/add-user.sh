#!/bin/sh
# Before installing: both packages run as the maxnines user, which has no shell
# and no home of its own.
set -e
if ! getent group maxnines >/dev/null; then
  groupadd --system maxnines
fi
if ! getent passwd maxnines >/dev/null; then
  useradd --system --gid maxnines --no-create-home --home-dir /nonexistent \
    --shell /usr/sbin/nologin --comment "MaxNines" maxnines
fi
#DEBHELPER#
