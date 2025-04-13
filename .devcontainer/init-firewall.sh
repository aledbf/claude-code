#!/bin/bash
set -euo pipefail  # Exit on error, undefined vars, and pipeline failures
IFS=$'\n\t'       # Stricter word splitting

echo "Configuring firewall rules with custom PROXY_REDIRECT chain..."

# === Flush existing rules ===
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
# Try to delete the custom chain if it exists from a previous run
iptables -t nat -X PROXY_REDIRECT 2>/dev/null || true
# Remove the old ipset if it exists
ipset destroy allowed-domains 2>/dev/null || true

# === Base Rules (filter table) ===
# Allow loopback traffic
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow outbound DNS
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
# Allow inbound DNS responses
iptables -A INPUT -p udp --sport 53 -j ACCEPT

# Allow established/related connections (important for return traffic)
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# === NAT Redirection using custom chain ===
# Create the new chain in the nat table
iptables -t nat -N PROXY_REDIRECT

# Rules within the PROXY_REDIRECT chain:
# Redirect HTTP traffic to Privoxy
iptables -t nat -A PROXY_REDIRECT -p tcp --dport 80 -j REDIRECT --to-port 31265
# Redirect HTTPS traffic to Privoxy
iptables -t nat -A PROXY_REDIRECT -p tcp --dport 443 -j REDIRECT --to-port 31265

# Rules in the OUTPUT chain (nat table) to jump to our custom chain:
# IMPORTANT: Exclude traffic destined for Privoxy itself to prevent redirection loops!
iptables -t nat -A OUTPUT -p tcp -d 127.0.0.1 --dport 31265 -j RETURN
# For all other TCP traffic on ports 80 and 443, jump to the PROXY_REDIRECT chain
iptables -t nat -A OUTPUT -p tcp -m tcp --dport 80 -j PROXY_REDIRECT
iptables -t nat -A OUTPUT -p tcp -m tcp --dport 443 -j PROXY_REDIRECT

# === Default Policies (filter table) ===
# Drop everything else by default
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP # This policy applies *after* NAT OUTPUT rules

echo "Firewall configuration complete."
