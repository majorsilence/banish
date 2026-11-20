#!/bin/sh
set -e
# Nothing is started or enabled for you: review /etc/banish/banish.json first.
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
cat <<'MSG'

Banish is installed but not running.
  1. Review /etc/banish/banish.json (the default rules watch sshd; the store is a local SQLite file).
  2. Start the agent:           sudo systemctl enable --now banish-agent
     Or the central registry:   sudo systemctl enable --now banish-api
  Documentation: /usr/share/doc/banish/DEPLOYMENT.md

MSG
exit 0
