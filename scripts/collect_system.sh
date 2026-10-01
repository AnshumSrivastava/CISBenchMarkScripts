#!/usr/bin/env bash
# collect_system.sh - Distribution-agnostic system discovery collector
set -euo pipefail

echo "=== OS ==="
if [ -f /etc/os-release ]; then
    cat /etc/os-release
elif [ -f /usr/lib/os-release ]; then
    cat /usr/lib/os-release
else
    echo "NAME=Unknown"
    echo "ID=linux"
fi

echo "=== KERNEL ==="
uname -a

echo "=== CURRENT USER ==="
id

echo "=== INIT SYSTEM ==="
if [ -f /proc/1/comm ]; then
    cat /proc/1/comm
else
    ps -p 1 -o comm= 2>/dev/null || echo "unknown"
fi

echo "=== AVAILABLE TOOLS ==="
for tool in systemctl journalctl ss ufw firewall-cmd nft iptables awk grep sed sshd; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo "$tool: available"
    else
        echo "$tool: unavailable"
    fi
done
