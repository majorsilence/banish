#!/bin/sh
set -e
# On removal (not on upgrade) stop the services. Bans in the firewall are rebuilt from the store when the agent runs again.
case "$1" in
    remove|0)
        if [ -d /run/systemd/system ]; then
            for unit in banish-agent banish-api; do
                systemctl disable --now "$unit" >/dev/null 2>&1 || true
            done
        fi
        ;;
esac
exit 0
