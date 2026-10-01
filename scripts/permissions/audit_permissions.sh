#!/usr/bin/env bash
# scripts/permissions/audit_permissions.sh - Permissions category security auditor
set -euo pipefail

echo "=========================================="
echo " [Category: Permissions] File Permissions"
echo "=========================================="

echo "--- Core Account Files (/etc/passwd, /etc/group) ---"
ls -ld /etc/passwd /etc/group 2>/dev/null || true

echo -e "\n--- Shadow Passwords File (/etc/shadow) ---"
ls -ld /etc/shadow 2>/dev/null || true

echo -e "\n--- Sudoers Configuration (/etc/sudoers and /etc/sudoers.d/) ---"
ls -ld /etc/sudoers 2>/dev/null || true
if [ -d /etc/sudoers.d ]; then
    ls -la /etc/sudoers.d 2>/dev/null || true
fi

echo -e "\n--- World-Writable Files in /etc (up to 10 entries) ---"
find /etc -maxdepth 3 -type f -perm -0002 2>/dev/null | head -n 10 || echo "None found or access restricted."
