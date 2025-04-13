#!/bin/bash
set -euo pipefail  # Exit on error, undefined vars, and pipeline failures
IFS=$'\n\t'       # Stricter word splitting

exit 0	

echo "Configuring firewall rules with custom PROXY_REDIRECT chain..."

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root" >&2
  exit 1
fi

# Check if the PROXY_REDIRECT chain already exists
if ! iptables -t nat -L PROXY_REDIRECT >/dev/null 2>&1; then
  echo "Creating PROXY_REDIRECT chain"
  iptables -t nat -N PROXY_REDIRECT
else
  echo "PROXY_REDIRECT chain already exists"
  # Clear the chain but keep it in place
  iptables -t nat -F PROXY_REDIRECT
fi

# === Base Rules (filter table) - adding with proper checks ===
# We use -C to check if the rule exists before adding it

# Allow loopback traffic
iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || iptables -A INPUT -i lo -j ACCEPT
iptables -C OUTPUT -o lo -j ACCEPT 2>/dev/null || iptables -A OUTPUT -o lo -j ACCEPT

# Allow outbound DNS
iptables -C OUTPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || iptables -A OUTPUT -p udp --dport 53 -j ACCEPT

# Allow inbound DNS responses
iptables -C INPUT -p udp --sport 53 -j ACCEPT 2>/dev/null || iptables -A INPUT -p udp --sport 53 -j ACCEPT

# Allow SSH
iptables -C INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow established/related connections (important for return traffic)
iptables -C INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -C OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -C OUTPUT -p tcp -m owner --uid-owner root -j ACCEPT  || iptables -A OUTPUT -p tcp -m owner --uid-owner root -j ACCEPT
# Alternative approach using source port if Privoxy doesn't run under its own user
iptables -C OUTPUT -p tcp --sport 31265 -j ACCEPT 2>/dev/null || iptables -A OUTPUT -p tcp --sport 31265 -j ACCEPT

# === Direct access rule for metadata server (169.254.169.254) ===
iptables -C OUTPUT -d 169.254.169.254/32 -j ACCEPT 2>/dev/null || iptables -A OUTPUT -d 169.254.169.254/32 -j ACCEPT

# === NAT Redirection using custom chain - with proper scoping ===
# Rules within the PROXY_REDIRECT chain:
# Redirect HTTP traffic to Privoxy
iptables -t nat -A PROXY_REDIRECT -p tcp --dport 80 -j REDIRECT --to-port 31265
# Redirect HTTPS traffic to Privoxy
iptables -t nat -A PROXY_REDIRECT -p tcp --dport 443 -j REDIRECT --to-port 31265

# Rules in the OUTPUT chain (nat table) to jump to our custom chain:
# First, check if these rules already exist before adding

# IMPORTANT: Exclude traffic destined for Privoxy itself to prevent redirection loops!
if ! iptables -t nat -C OUTPUT -p tcp -d 127.0.0.1 --dport 31265 -j RETURN 2>/dev/null; then
  iptables -t nat -A OUTPUT -p tcp -d 127.0.0.1 --dport 31265 -j RETURN
fi

# Exclude the metadata server (169.254.169.254) from proxying
if ! iptables -t nat -C OUTPUT -p tcp -d 169.254.169.254/32 -j RETURN 2>/dev/null; then
  iptables -t nat -A OUTPUT -p tcp -d 169.254.169.254/32 -j RETURN
fi

# For all other TCP traffic on ports 80 and 443, jump to the PROXY_REDIRECT chain
if ! iptables -t nat -C OUTPUT -p tcp -m tcp --dport 80 -j PROXY_REDIRECT 2>/dev/null; then
  iptables -t nat -A OUTPUT -p tcp -m tcp --dport 80 -j PROXY_REDIRECT
fi

if ! iptables -t nat -C OUTPUT -p tcp -m tcp --dport 443 -j PROXY_REDIRECT 2>/dev/null; then
  iptables -t nat -A OUTPUT -p tcp -m tcp --dport 443 -j PROXY_REDIRECT
fi

# === Default Policies (filter table) - commented out for review ===
# These are left commented out to avoid locking yourself out
# Uncomment only after thorough testing
# iptables -P INPUT DROP
# iptables -P FORWARD DROP
# iptables -P OUTPUT DROP

echo "Firewall rules successfully applied"

# Optional: Display current rules for verification
echo "Current NAT rules:"
iptables -t nat -L -v
echo "Current filter rules:"
iptables -L -v

