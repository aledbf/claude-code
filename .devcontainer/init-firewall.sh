#!/bin/bash
set -euo pipefail  # Exit on error, undefined vars, and pipeline failures
IFS=$'\n\t'       # Stricter word splitting

echo "Configuring firewall rules with custom CLAUDE_CODE chains..."

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root" >&2
  exit 1
fi

# === Create CLAUDE_CODE chains (if they don't exist) ===
# Create the custom chains in each table we'll use
if ! iptables -L CLAUDE_CODE_FILTER >/dev/null 2>&1; then
  echo "Creating CLAUDE_CODE_FILTER chain for filter table"
  iptables -N CLAUDE_CODE_FILTER
else
  echo "CLAUDE_CODE_FILTER chain already exists"
  iptables -F CLAUDE_CODE_FILTER
fi

if ! iptables -t nat -L CLAUDE_CODE_NAT >/dev/null 2>&1; then
  echo "Creating CLAUDE_CODE_NAT chain for nat table"
  iptables -t nat -N CLAUDE_CODE_NAT
else
  echo "CLAUDE_CODE_NAT chain already exists"
  iptables -t nat -F CLAUDE_CODE_NAT
fi

# === Set up chain references ===
# Make sure all traffic goes through our chains first
# For filter table (INPUT, OUTPUT)
iptables -C INPUT -j CLAUDE_CODE_FILTER 2>/dev/null || iptables -I INPUT 1 -j CLAUDE_CODE_FILTER
iptables -C OUTPUT -j CLAUDE_CODE_FILTER 2>/dev/null || iptables -I OUTPUT 1 -j CLAUDE_CODE_FILTER

# For nat table (OUTPUT only)
iptables -t nat -C OUTPUT -j CLAUDE_CODE_NAT 2>/dev/null || iptables -t nat -I OUTPUT 1 -j CLAUDE_CODE_NAT

# === Base Rules (filter table - using CLAUDE_CODE_FILTER) ===
# Allow loopback traffic
iptables -A CLAUDE_CODE_FILTER -i lo -j ACCEPT
iptables -A CLAUDE_CODE_FILTER -o lo -j ACCEPT

# Allow outbound DNS
iptables -A CLAUDE_CODE_FILTER -p udp --dport 53 -j ACCEPT

# Allow inbound DNS responses
iptables -A CLAUDE_CODE_FILTER -p udp --sport 53 -j ACCEPT

# Allow SSH
iptables -A CLAUDE_CODE_FILTER -p tcp --dport 22 -j ACCEPT

# Allow established/related connections
iptables -A CLAUDE_CODE_FILTER -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow root user traffic
iptables -A CLAUDE_CODE_FILTER -p tcp -m owner --uid-owner root -j ACCEPT

# Allow Privoxy traffic using source port
iptables -A CLAUDE_CODE_FILTER -p tcp --sport 31265 -j ACCEPT

# Direct access rule for metadata server
iptables -A CLAUDE_CODE_FILTER -d 169.254.169.254/32 -j ACCEPT

# === NAT Redirection rules (in CLAUDE_CODE_NAT) ===
# Exclude traffic destined for Privoxy itself
iptables -t nat -A CLAUDE_CODE_NAT -p tcp -d 127.0.0.1 --dport 31265 -j RETURN

# Exclude the metadata server from proxying
iptables -t nat -A CLAUDE_CODE_NAT -p tcp -d 169.254.169.254/32 -j RETURN

# For HTTP traffic, redirect to Privoxy
iptables -t nat -A CLAUDE_CODE_NAT -p tcp --dport 80 -j REDIRECT --to-port 31265

# For HTTPS traffic, redirect to Privoxy
iptables -t nat -A CLAUDE_CODE_NAT -p tcp --dport 443 -j REDIRECT --to-port 31265

# === Default Policies (filter table) - commented out for review ===
# These are left commented out to avoid locking yourself out
# Uncomment only after thorough testing
# iptables -P INPUT DROP
# iptables -P FORWARD DROP
# iptables -P OUTPUT DROP

echo "CLAUDE_CODE firewall rules successfully applied"

# Optional: Display current rules for verification
echo "Current NAT rules:"
iptables -t nat -L -v
echo "Current filter rules:"
iptables -L -v

