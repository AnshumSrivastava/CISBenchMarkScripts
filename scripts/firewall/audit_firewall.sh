#!/usr/bin/env bash
# scripts/firewall/audit_firewall.sh - Host firewall state and ruleset inspector
set -euo pipefail

echo "=========================================="
echo " [Category: Firewall] Firewall Inspection"
echo "=========================================="

echo "--- UFW Status ---"
if command -v ufw >/dev/null 2>&1; then
    ufw status 2>/dev/null || echo "ufw query requires root or returned error"
else
    echo "ufw: not installed"
fi

echo -e "\n--- Firewalld Status ---"
if command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --state 2>/dev/null || echo "firewalld: not active"
else
    echo "firewall-cmd: not installed"
fi

echo -e "\n--- NFTables Ruleset ---"
if command -v nft >/dev/null 2>&1; then
    nft list ruleset 2>/dev/null | head -n 20 || echo "nft ruleset empty or query requires root"
else
    echo "nft: not installed"
fi

echo -e "\n--- IPTables Ruleset ---"
if command -v iptables >/dev/null 2>&1; then
    iptables -L -n -v 2>/dev/null | head -n 20 || echo "iptables query requires root"
else
    echo "iptables: not installed"
fi
