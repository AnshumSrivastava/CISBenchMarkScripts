#!/usr/bin/env bash
# scripts/accounts/audit_accounts.sh - Accounts category security auditor
set -euo pipefail

echo "=========================================="
echo " [Category: Accounts] Account Security"
echo "=========================================="

echo "--- UID 0 Account Audit (/etc/passwd) ---"
awk -F: '($3 == 0) { printf "  UID 0 Account: %s (UID: %s, Shell: %s)\n", $1, $3, $7 }' /etc/passwd

echo -e "\n--- Empty Password Audit (/etc/shadow) ---"
if [ -r /etc/shadow ]; then
    EMPTY_USERS=$(awk -F: '($2 == "") { print $1 }' /etc/shadow)
    if [ -n "$EMPTY_USERS" ]; then
        echo "  [FAIL] Accounts with empty password: $EMPTY_USERS"
    else
        echo "  [PASS] No accounts with empty password fields."
    fi
else
    echo "  [WARN] /etc/shadow not readable by current user (requires root/sudo for direct read)."
fi

echo -e "\n--- Password Ageing Limits (/etc/login.defs) ---"
if [ -f /etc/login.defs ]; then
    grep -E '^[[:space:]]*PASS_(MAX|MIN|WARN)_' /etc/login.defs || echo "  No PASS_* directives configured."
else
    echo "  /etc/login.defs not present."
fi

echo -e "\n--- Default User UMASK (/etc/login.defs) ---"
if [ -f /etc/login.defs ]; then
    grep -E '^[[:space:]]*UMASK[[:space:]]+' /etc/login.defs || echo "  UMASK directive not set."
fi
