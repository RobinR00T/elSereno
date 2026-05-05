#!/bin/sh
# preinstall — runs BEFORE files unpack on deb/rpm/apk.
# Creates the elsereno system user + group if absent. The
# user is what /etc/elsereno + /var/lib/elsereno +
# /var/log/elsereno end up owned by; the systemd units
# drop to it.
#
# This script is fed to nfpm's `scripts.preinstall`. It's
# bash-portable; uses only POSIX constructs so it works on
# every distro nfpm produces packages for.

set -e

if ! getent group elsereno >/dev/null 2>&1; then
    groupadd --system elsereno || addgroup --system elsereno
fi

if ! getent passwd elsereno >/dev/null 2>&1; then
    useradd --system \
        --gid elsereno \
        --home-dir /var/lib/elsereno \
        --no-create-home \
        --shell /usr/sbin/nologin \
        --comment "ElSereno daemon" \
        elsereno \
        2>/dev/null \
    || adduser --system \
        --ingroup elsereno \
        --home /var/lib/elsereno \
        --no-create-home \
        --shell /usr/sbin/nologin \
        --gecos "ElSereno daemon" \
        elsereno
fi

exit 0
