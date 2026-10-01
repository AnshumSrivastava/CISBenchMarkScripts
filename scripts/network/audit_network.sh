#!/usr/bin/env bash
# scripts/network/audit_network.sh - Network listening sockets & sysctl audit
set -euo pipefail

echo "=========================================="
echo " [Category: Network] Network Security Audit"
echo "=========================================="

echo "--- Listening Network Sockets (TCP/UDP) ---"
if command -v ss >/dev/null 2>&1; then
    ss -tulpen
elif command -v netstat >/dev/null 2>&1; then
    netstat -tulpen
else
    echo "ss and netstat not available."
fi

echo -e "\n--- IPv4 Forwarding (net.ipv4.ip_forward) ---"
sysctl net.ipv4.ip_forward 2>/dev/null || cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "unreadable"

echo -e "\n--- ICMP Redirect Acceptance ---"
sysctl net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects 2>/dev/null || echo "unreadable"
