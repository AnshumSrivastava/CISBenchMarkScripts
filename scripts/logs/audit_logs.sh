#!/usr/bin/env bash
# scripts/logs/audit_logs.sh - Authentication log events monitor
set -euo pipefail

echo "=========================================="
echo " [Category: Logs] Authentication Log Monitor"
echo "=========================================="

echo "--- Recent Failed Login Attempts (Last 24 Hours) ---"
if command -v journalctl >/dev/null 2>&1; then
    journalctl --since "24 hours ago" --no-pager 2>/dev/null | grep -Ei '(failed password|authentication failure|invalid user)' | tail -n 10 || echo "  No failed login entries found in journald."
elif [ -f /var/log/auth.log ]; then
    grep -Ei '(failed password|authentication failure|invalid user)' /var/log/auth.log 2>/dev/null | tail -n 10 || echo "  No failed login entries found in /var/log/auth.log."
elif [ -f /var/log/secure ]; then
    grep -Ei '(failed password|authentication failure|invalid user)' /var/log/secure 2>/dev/null | tail -n 10 || echo "  No failed login entries found in /var/log/secure."
else
    echo "  No accessible authentication log file found."
fi

echo -e "\n--- Recent Successful Logins / Sessions ---"
if command -v last >/dev/null 2>&1; then
    last -n 10 2>/dev/null || echo "last query failed"
fi
