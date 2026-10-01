#!/usr/bin/env bash
# scripts/system/audit_system.sh - System category baseline collector
set -euo pipefail

echo "=========================================="
echo " [Category: System] System & Kernel Audit"
echo "=========================================="

echo "--- OS Release ---"
if [ -f /etc/os-release ]; then
    grep -E '^(NAME|VERSION|ID|PRETTY_NAME)=' /etc/os-release
elif [ -f /usr/lib/os-release ]; then
    grep -E '^(NAME|VERSION|ID|PRETTY_NAME)=' /usr/lib/os-release
fi

echo -e "\n--- Kernel & Architecture ---"
uname -srmo

echo -e "\n--- Init System (PID 1) ---"
if [ -f /proc/1/comm ]; then
    cat /proc/1/comm
else
    ps -p 1 -o comm= 2>/dev/null || echo "unknown"
fi

echo -e "\n--- Core Dump Restriction (fs.suid_dumpable) ---"
sysctl fs.suid_dumpable 2>/dev/null || cat /proc/sys/fs/suid_dumpable 2>/dev/null || echo "unreadable"

echo -e "\n--- Address Space Layout Randomization (kernel.randomize_va_space) ---"
sysctl kernel.randomize_va_space 2>/dev/null || cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo "unreadable"

echo -e "\n--- System Inventory Completed ---"
