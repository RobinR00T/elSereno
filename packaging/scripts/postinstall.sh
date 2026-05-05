#!/bin/sh
# postinstall — runs AFTER files unpack. Creates the
# /etc/elsereno + state dirs (the tmpfiles config handles
# /run, but persistent state needs a one-time mkdir +
# chown), then sets up the systemd units.
#
# The script is idempotent: re-running on upgrade is a no-op.

set -e

# 0. systemd-tmpfiles applies our drop-in for /run, /var/lib,
#    /var/log. Safe to skip when the cmd isn't present
#    (e.g. inside a container without systemd).
if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/elsereno.conf 2>/dev/null || true
fi

# 1. /etc/elsereno is shipped by the package (config
#    sample lands there) but the package doesn't own the
#    directory itself; ensure mode + ownership.
mkdir -p /etc/elsereno
chmod 0750 /etc/elsereno
chown elsereno:elsereno /etc/elsereno || true

# 2. State + log dirs. systemd-tmpfiles creates them on
#    boot, but until the next boot they don't exist —
#    create now so an immediate `systemctl start` works.
mkdir -p /var/lib/elsereno
chmod 0750 /var/lib/elsereno
chown elsereno:elsereno /var/lib/elsereno || true

mkdir -p /var/log/elsereno
chmod 0750 /var/log/elsereno
chown elsereno:elsereno /var/log/elsereno || true

# 3. systemd unit reload. Safe to skip when systemctl
#    isn't on PATH (containers, build VMs).
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    # Don't auto-enable — operators decide when to start.
    # Print a hint instead.
    cat <<'EOF'

elsereno installed. The dashboard is OFF by default.

To enable + start:
  1. Edit /etc/elsereno/elsereno.yaml (sample at
     /usr/share/doc/elsereno/elsereno.yaml.sample).
  2. Initialise + unlock the vault:
       elsereno vault init
       elsereno vault unlock
  3. Stage the passphrase 0600:
       echo "<passphrase>" > /etc/elsereno/vault.passphrase
       chmod 0600 /etc/elsereno/vault.passphrase
       chown elsereno:elsereno /etc/elsereno/vault.passphrase
  4. Enable + start the unit:
       systemctl enable --now elsereno-serve.service

For the audit daemon (SOC fan-in, optional):
       systemctl enable --now elsereno-audit.service

Verify:  elsereno doctor
Logs:    journalctl -u elsereno-serve -f

EOF
fi

exit 0
