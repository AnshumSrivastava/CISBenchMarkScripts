#!/usr/bin/env bash
# scripts/ssh/audit_ssh.sh - SSH daemon configuration auditor
set -euo pipefail

echo "=========================================="
echo " [Category: SSH] SSH Daemon Security Audit"
echo "=========================================="

if command -v sshd >/dev/null 2>&1; then
    echo "sshd binary: $(command -v sshd)"
    echo "--- Effective Runtime Directives (sshd -T) ---"
    sshd -T 2>/dev/null | grep -Ei '^(permitrootlogin|passwordauthentication|clientaliveinterval|clientalivecountmax|maxauthtries)' || true
else
    echo "sshd command unavailable. Inspecting configuration files directly..."
fi

for conf in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
    if [ -f "$conf" ]; then
        echo -e "\n--- File: $conf ---"
        grep -Ei '^[[:space:]]*(permitrootlogin|passwordauthentication|clientaliveinterval|clientalivecountmax|maxauthtries)' "$conf" || echo "  (no matched directives)"
    fi
done
