#!/bin/bash
set -euo pipefail  # Exit on error, undefined vars, and pipeline failures
IFS=$'\n\t'       # Stricter word splitting

# Disable command echo for cleaner logs
set +x

# Consistent naming and file locations
FLAG_FILE="/var/run/firewall/configured"
READY_FILE="/tmp/firewall-initialized"  # Changed to match Dockerfile expectation

#READY_FILE="/var/run/firewall/ready"
LOG_LEVEL="info"  # Options: debug, info, warning, error
PROXY_PORT=31265
CHAINS_PREFIX="CLAUDE"

# Create firewall directory
mkdir -p "$(dirname "$FLAG_FILE")"


log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') [FIREWALL] $1"
}

if [ "$(id -u)" -ne 0 ]; then
  log "ERROR: This script must be run as root" >&2
  exit 1
fi

if [ -f "$FLAG_FILE" ]; then
  log "Firewall already configured, skipping..."
  # Ensure ready file exists even on restart
  touch "$READY_FILE"
  # Keep the script running to prevent runit from restarting it
  exec sleep infinity
fi

log "Configuring firewall rules with ${CHAINS_PREFIX} chains..."

# Define chain names for clarity
FILTER_CHAIN="${CHAINS_PREFIX}_FILTER"
NAT_CHAIN="${CHAINS_PREFIX}_NAT"
LOGGING_CHAIN="${CHAINS_PREFIX}_LOGGING"

# === Clean up existing rules ===
log "Cleaning up existing rules"

# Save default policies before reset
DEFAULT_INPUT_POLICY=$(iptables -S INPUT | head -1 | cut -d' ' -f3)
DEFAULT_OUTPUT_POLICY=$(iptables -S OUTPUT | head -1 | cut -d' ' -f3)

# First remove references to our custom chains (if they exist)
iptables -t nat -D OUTPUT -j "$NAT_CHAIN" 2>/dev/null || true
iptables -D OUTPUT -j "$FILTER_CHAIN" 2>/dev/null || true
iptables -D OUTPUT -j "$LOGGING_CHAIN" 2>/dev/null || true

# Then flush the chains
iptables -F "$FILTER_CHAIN" 2>/dev/null || true
iptables -t nat -F "$NAT_CHAIN" 2>/dev/null || true
iptables -F "$LOGGING_CHAIN" 2>/dev/null || true

# Finally delete the chains
iptables -X "$FILTER_CHAIN" 2>/dev/null || true
iptables -t nat -X "$NAT_CHAIN" 2>/dev/null || true
iptables -X "$LOGGING_CHAIN" 2>/dev/null || true

# === Create custom chains ===
log "Creating custom chains"
iptables -t nat -N "$NAT_CHAIN"
iptables -N "$FILTER_CHAIN"
iptables -N "$LOGGING_CHAIN"

# === Set up basic allow rules directly in INPUT/OUTPUT chains ===
log "Setting up basic rules"

# Allow loopback traffic
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow SSH (both incoming and outgoing)
iptables -A INPUT -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

# Allow established/related connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# === AWS specific rules ===
# Allow access to AWS metadata service
iptables -A OUTPUT -d 169.254.169.254/32 -j ACCEPT
# Allow NTP for time sync (important for certificates)
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT


# === Configure NAT chain for proxying ===
log "Setting up NAT chain for proxying"

# Exclude certain destinations from proxying
iptables -t nat -A "$NAT_CHAIN" -p tcp -d 169.254.169.254/32 -j RETURN
iptables -t nat -A "$NAT_CHAIN" -o lo -j RETURN

# Redirect HTTP/HTTPS to Squid proxy for non-root users
iptables -t nat -A "$NAT_CHAIN" -p tcp --dport 80 -m owner ! --uid-owner root -j REDIRECT --to-port 31265
iptables -t nat -A "$NAT_CHAIN" -p tcp --dport 443 -m owner ! --uid-owner root -j REDIRECT --to-port 31266

# === Configure outbound access rules ===
log "Setting up outbound access rules"

# Allow DNS queries
iptables -A "$FILTER_CHAIN" -p udp --dport 53 -j ACCEPT
iptables -A "$FILTER_CHAIN" -p tcp --dport 53 -j ACCEPT

# Allow root to do anything
iptables -A "$FILTER_CHAIN" -m owner --uid-owner root -j ACCEPT

# Explicitly block non-root users from accessing HTTP/HTTPS ports directly
iptables -A "$FILTER_CHAIN" -p tcp -m multiport --dports 80,443 -m owner ! --uid-owner root -j DROP
log "Blocked direct HTTP/HTTPS access for non-root users"

# Rate limit connections to reduce potential abuse
iptables -A "$FILTER_CHAIN" -p tcp --syn -m limit --limit 20/s --limit-burst 100 -j ACCEPT

# === Add custom chains to main chains ===
log "Adding custom chains to main chains"
iptables -t nat -A OUTPUT -j "$NAT_CHAIN"
iptables -A OUTPUT -j "$FILTER_CHAIN"
iptables -A OUTPUT -j "$LOGGING_CHAIN"

# Set default policies
if [ "$DEFAULT_INPUT_POLICY" = "DROP" ]; then
  iptables -P INPUT DROP
else
  log "Keeping existing INPUT policy: $DEFAULT_INPUT_POLICY"
fi

if [ "$DEFAULT_OUTPUT_POLICY" = "DROP" ]; then
  iptables -P OUTPUT DROP
else
  # Enhance security by setting OUTPUT policy to DROP
  log "Setting OUTPUT policy to DROP for improved security"
  iptables -P OUTPUT DROP
fi

# === Show summary for verification ===
log "Firewall configuration completed"
log "Current NAT rules:"
iptables -t nat -L -v
log "Current filter rules:"
iptables -L -v

# Create flag file to indicate successful configuration
touch "$FLAG_FILE"

# Signal to other services that firewall is ready
log "Signaling firewall ready status"
touch "$READY_FILE"

# Keep the script running to prevent runit from restarting it
exec sleep infinity
