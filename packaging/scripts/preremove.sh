#!/bin/sh
# preremove — stop + disable the systemd units before
# files vanish. We DON'T remove the elsereno user / group
# here — operators may have chown'd custom files to them
# and removing the uid would orphan those files.
#
# Persistent state (/var/lib/elsereno, /var/log/elsereno,
# /etc/elsereno) is left alone on package remove so the
# operator can reinstall + resume without losing data.
# `apt purge` (which calls postrm purge) is the verb that
# wipes those — purge handling lives in a separate script
# (deb-only) that nfpm doesn't expose; if needed, add
# postremove with --postremove and a `purge` arg parse.

set -e

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl stop elsereno-serve.service 2>/dev/null || true
    systemctl stop elsereno-audit.service 2>/dev/null || true
    systemctl disable elsereno-serve.service 2>/dev/null || true
    systemctl disable elsereno-audit.service 2>/dev/null || true
fi

exit 0
