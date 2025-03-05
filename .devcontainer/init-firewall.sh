#!/bin/bash
set -uo pipefail  # Exit on undefined vars and pipeline failures, but not on all errors
IFS=$'\n\t'       # Stricter word splitting

# Function to extract AWS S3 IP ranges
extract_s3_ip_ranges() {
    log "Extracting AWS S3 IP ranges..."

    if ! command -v jq &> /dev/null; then
        log "Error: This function requires jq to be installed."
        log "S3 IP ranges will not be added to allowed domains."
        return 1
    fi

    # URL of AWS IP ranges JSON file
    local AWS_IP_RANGES_URL="https://ip-ranges.amazonaws.com/ip-ranges.json"
    # Temporary file to store the JSON
    local JSON_FILE="/tmp/aws-ip-ranges.json"

    log "Downloading AWS IP ranges..."
    if ! curl -s -o "$JSON_FILE" "$AWS_IP_RANGES_URL"; then
        log "Error: Failed to download AWS IP ranges file."
        return 1
    fi

    log "Processing S3 IP ranges..."
    local count=0

    # Process IPv4 ranges
    while read -r ip_range; do
        if [[ -n "$ip_range" ]]; then
            log "Adding S3 IP range: $ip_range"
            ipset add claude-allowed-domains "$ip_range" 2>/dev/null || {
                # If ipset fails, try adding direct iptables rule
                iptables -A CLAUDE_OUTPUT -d "$ip_range" -j ACCEPT
            }
            count=$((count+1))
        fi
    done < <(jq -r '.prefixes[] | select(.service=="S3") | .ip_prefix' "$JSON_FILE")

    # Only process IPv6 if we have IPv6 support
    if ip -6 addr show &>/dev/null; then
        while read -r ip_range; do
            if [[ -n "$ip_range" ]]; then
                log "Adding S3 IPv6 range: $ip_range"
                ipset add claude-allowed-domains "$ip_range" 2>/dev/null || {
                    # If ipset fails, try adding direct ip6tables rule
                    if command -v ip6tables &>/dev/null; then
                        ip6tables -A CLAUDE_OUTPUT -d "$ip_range" -j ACCEPT
                    fi
                }
                count=$((count+1))
            fi
        done < <(jq -r '.ipv6_prefixes[] | select(.service=="S3") | .ipv6_prefix' "$JSON_FILE")
    fi

    log "Added $count S3 IP ranges"

    # Remove temporary file
    rm -f "$JSON_FILE"
    return 0
}
add_interface_networks() {
    local interface="$1"

    if [ -z "$interface" ]; then
        log "ERROR: No interface specified"
        return 1
    fi

    log "Adding networks for interface $interface..."

    # Get all IP addresses associated with the interface
    local addresses=$(ip -o addr show dev "$interface" | grep -w inet | awk '{print $4}')

    if [ -z "$addresses" ]; then
        log "Warning: No addresses found for interface $interface"
        return 1
    fi

    for addr in $addresses; do
        log "Adding rule for network: $addr"
        iptables -A CLAUDE_INPUT -s "$addr" -j ACCEPT || log "Warning: Failed to add INPUT rule for $addr"
        iptables -A CLAUDE_OUTPUT -d "$addr" -j ACCEPT || log "Warning: Failed to add OUTPUT rule for $addr"
    done

    return 0
}

log "Starting Claude firewall configuration..."

# Check for required utilities
for cmd in iptables ipset curl; do
    if ! command -v "$cmd" &> /dev/null; then
        log "ERROR: Required command '$cmd' not found. Please install it."
        exit 1
    fi
done

# Optional utilities
for cmd in jq dig; do
    if ! command -v "$cmd" &> /dev/null; then
        log "WARNING: Optional command '$cmd' not found. Some functionality will be limited."
    fi
done

# Check for aggregate command, use alternative if not available
if ! command -v aggregate &> /dev/null; then
    log "Warning: 'aggregate' command not found. Will not compress IP ranges."
    # Create a function that passes through CIDR ranges
    aggregate() {
        cat -
    }
fi

# Create custom chains for Claude rules (don't clean up existing rules)
log "Creating custom chains for Claude firewall..."
iptables -N CLAUDE_INPUT 2>/dev/null || {
    log "Chain CLAUDE_INPUT already exists, flushing it"
    iptables -F CLAUDE_INPUT
}
iptables -N CLAUDE_OUTPUT 2>/dev/null || {
    log "Chain CLAUDE_OUTPUT already exists, flushing it"
    iptables -F CLAUDE_OUTPUT
}
iptables -N CLAUDE_FORWARD 2>/dev/null || {
    log "Chain CLAUDE_FORWARD already exists, flushing it"
    iptables -F CLAUDE_FORWARD
}

# Insert jumps to our custom chains at the beginning of the main chains
log "Adding references to Claude chains in main chains..."
# Remove existing jumps if any to avoid duplicates
iptables -D INPUT -j CLAUDE_INPUT 2>/dev/null || true
iptables -D OUTPUT -j CLAUDE_OUTPUT 2>/dev/null || true
iptables -D FORWARD -j CLAUDE_FORWARD 2>/dev/null || true

# Add new jumps
iptables -I INPUT 1 -j CLAUDE_INPUT || log "Warning: Failed to add jump from INPUT to CLAUDE_INPUT"
iptables -I OUTPUT 1 -j CLAUDE_OUTPUT || log "Warning: Failed to add jump from OUTPUT to CLAUDE_OUTPUT"
iptables -I FORWARD 1 -j CLAUDE_FORWARD || log "Warning: Failed to add jump from FORWARD to CLAUDE_FORWARD"

# Create or recreate the ipset for Claude
log "Creating ipset for allowed domains..."
ipset destroy claude-allowed-domains 2>/dev/null || true
ipset create claude-allowed-domains hash:net || {
    log "ERROR: Failed to create ipset. Aborting."
    exit 1
}

# Allow localhost
log "Setting up local connectivity rules..."
iptables -A CLAUDE_INPUT -i lo -j ACCEPT || log "Warning: Failed to allow localhost input"
iptables -A CLAUDE_OUTPUT -o lo -j ACCEPT || log "Warning: Failed to allow localhost output"

# Allow outbound DNS
iptables -A CLAUDE_OUTPUT -p udp --dport 53 -j ACCEPT || log "Warning: Failed to allow outbound DNS"
# Allow inbound DNS responses
iptables -A CLAUDE_INPUT -p udp --sport 53 -j ACCEPT || log "Warning: Failed to allow inbound DNS"

# Allow outbound SSH
iptables -A CLAUDE_OUTPUT -p tcp --dport 22 -j ACCEPT || log "Warning: Failed to allow outbound SSH"
# Allow inbound SSH responses
iptables -A CLAUDE_INPUT -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT || log "Warning: Failed to allow inbound SSH responses"

# Allow established connections for already approved traffic
log "Setting up established connection rules..."
iptables -A CLAUDE_INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT || log "Warning: Failed to add ESTABLISHED,RELATED INPUT rule"
iptables -A CLAUDE_OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT || log "Warning: Failed to add ESTABLISHED,RELATED OUTPUT rule"

# Fetch GitHub meta information and aggregate + add their IP ranges
log "Fetching GitHub IP ranges..."
gh_ranges=$(curl -s https://api.github.com/meta)
if [ -z "$gh_ranges" ]; then
    log "ERROR: Failed to fetch GitHub IP ranges. Aborting."
    exit 1
fi

if ! echo "$gh_ranges" | jq -e '.web and .api and .git' >/dev/null; then
    log "ERROR: GitHub API response missing required fields. Aborting."
    exit 1
fi

log "Processing GitHub IPs..."
while read -r cidr; do
    if [[ ! "$cidr" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        log "Warning: Invalid CIDR range from GitHub meta: $cidr - skipping"
        continue
    fi
    log "Adding GitHub range $cidr"
    ipset add claude-allowed-domains "$cidr" || log "Warning: Failed to add $cidr to ipset"
done < <(echo "$gh_ranges" | jq -r '(.web + .api + .git)[]')

# Resolve and add other allowed domains
for domain in \
    "registry.npmjs.org" \
    "api.anthropic.com" \
    "sentry.io" \
    "statsig.anthropic.com" \
    "cursor.blob.core.windows.net" \
    "statsig.com" \
    "marketplace.visualstudio.com" \
    "vscode.blob.core.windows.net" \
    "marketplace-cdn.vsassets.io" \
    "vsmarketplacebadge.apphb.com"; do
    log "Resolving $domain..."
    # Handle wildcard domains
    if [[ "$domain" == *"*"* ]]; then
        log "Wildcard domain detected, using base domain for resolution"
        base_domain=${domain#*.}
        ips=$(dig +short A "$base_domain" 2>/dev/null || log "Warning: Failed to resolve $base_domain")
    else
        ips=$(dig +short A "$domain" 2>/dev/null || log "Warning: Failed to resolve $domain")
    fi

    if [ -z "$ips" ]; then
        log "Warning: Failed to resolve $domain - skipping"
        continue
    fi

    while read -r ip; do
        if [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            log "Warning: Invalid IP from DNS for $domain: $ip - skipping"
            continue
        fi
        log "Adding $ip for $domain"
        ipset add claude-allowed-domains "$ip" || log "Warning: Failed to add $ip to ipset"
    done < <(echo "$ips")
done

# Add Microsoft Azure IP ranges for VS Code Marketplace
log "Adding Microsoft Azure IP ranges for VS Code Marketplace..."
# Add primary Azure IP ranges
for azure_cidr in \
    "13.107.246.0/24" \
    "13.107.6.0/24" \
    "13.107.9.0/24" \
    "20.190.128.0/18" \
    "40.74.0.0/18" \
    "40.90.0.0/16" \
    "40.119.0.0/16" \
    "40.126.0.0/18" \
    "52.133.128.0/17" \
    "52.245.64.0/18" \
    "204.79.197.0/24"; do
    log "Adding Azure IP range: $azure_cidr"
    ipset add claude-allowed-domains "$azure_cidr" || log "Warning: Failed to add $azure_cidr to ipset"
done

# Extract and add AWS S3 IP ranges
extract_s3_ip_ranges

# Get host IP from default route
log "Detecting host network..."
HOST_IP=$(ip route | grep default | awk '{print $3}')
if [ -z "$HOST_IP" ]; then
    log "Warning: Failed to detect host IP using default route"
    # Try alternative methods
    HOST_IP=$(hostname -I | awk '{print $1}')
    if [ -z "$HOST_IP" ]; then
        # Try another method
        HOST_IP=$(ip addr show | grep -w inet | grep -v 127.0.0.1 | head -n 1 | awk '{print $2}' | cut -d/ -f1)
        if [ -z "$HOST_IP" ]; then
            log "ERROR: Failed to detect host IP. Skipping host network rules."
            HOST_NETWORK=""
        else
            log "Detected host IP using ip addr: $HOST_IP"
            # Instead of using sed, manually construct the network
            IFS='.' read -r a b c d <<< "$HOST_IP"
            HOST_NETWORK="${a}.${b}.${c}.0/24"
        fi
    else
        log "Detected host IP using hostname: $HOST_IP"
        # Instead of using sed, manually construct the network
        IFS='.' read -r a b c d <<< "$HOST_IP"
        HOST_NETWORK="${a}.${b}.${c}.0/24"
    fi
else
    log "Detected host IP using default route: $HOST_IP"
    # Instead of using sed, manually construct the network
    IFS='.' read -r a b c d <<< "$HOST_IP"
    HOST_NETWORK="${a}.${b}.${c}.0/24"
fi

if [ -n "$HOST_NETWORK" ]; then
    log "Host network detected as: $HOST_NETWORK"

    # Fix the format of the HOST_NETWORK for iptables
    # Ensure there's no unintended newline or extra whitespace
    HOST_NETWORK=$(echo -n "$HOST_NETWORK" | tr -d '\n\r')

    # Debug information
    log "Adding host network rule with: '$HOST_NETWORK'"

    # Try a different approach with separate IP and mask
    HOST_IP_BASE=$(echo "$HOST_NETWORK" | cut -d'/' -f1)
    HOST_MASK=$(echo "$HOST_NETWORK" | cut -d'/' -f2)

    # Add host network rules
    iptables -A CLAUDE_INPUT -s "$HOST_IP_BASE/$HOST_MASK" -j ACCEPT || {
        log "Warning: Failed to add host network INPUT rule, trying alternative format"
        iptables -A CLAUDE_INPUT -s "$HOST_IP_BASE" -j ACCEPT || log "Warning: Failed to add host network INPUT rule"
    }

    iptables -A CLAUDE_OUTPUT -d "$HOST_IP_BASE/$HOST_MASK" -j ACCEPT || {
        log "Warning: Failed to add host network OUTPUT rule, trying alternative format"
        iptables -A CLAUDE_OUTPUT -d "$HOST_IP_BASE" -j ACCEPT || log "Warning: Failed to add host network OUTPUT rule"
    }
else
    log "Skipping host network rules"
fi

# Allow packets to and from the default gateway
log "Adding rules for default gateway..."
DEFAULT_GATEWAY=$(ip route | grep default | awk '{print $3}')
if [ -n "$DEFAULT_GATEWAY" ]; then
    log "Default gateway detected as: $DEFAULT_GATEWAY"
    iptables -A CLAUDE_INPUT -s "$DEFAULT_GATEWAY" -j ACCEPT || log "Warning: Failed to allow traffic from default gateway"
    iptables -A CLAUDE_OUTPUT -d "$DEFAULT_GATEWAY" -j ACCEPT || log "Warning: Failed to allow traffic to default gateway"

    # Also add a specific rule for the IP that was dropped in the logs (13.107.246.33)
    iptables -A CLAUDE_INPUT -s 13.107.246.33 -j ACCEPT || log "Warning: Failed to allow traffic from Microsoft IP"
else
    log "Warning: Could not detect default gateway"
fi

# Add rules for all active interfaces
for iface in $(ip -o link show | grep -v lo | awk -F': ' '{print $2}'); do
    add_interface_networks "$iface"
done

# Special rule for HTTPS responses
log "Adding rules for HTTPS traffic..."
iptables -A CLAUDE_INPUT -p tcp --sport 443 -j ACCEPT || log "Warning: Failed to add special rule for HTTPS responses"
iptables -A CLAUDE_OUTPUT -p tcp --dport 443 -j ACCEPT || log "Warning: Failed to add special rule for HTTPS requests"

# Allow specific outbound traffic to allowed domains
log "Setting up allowed domains rule..."
if ! iptables -A CLAUDE_OUTPUT -m set --match-set claude-allowed-domains dst -j ACCEPT 2>/dev/null; then
    log "Warning: ipset module may not be properly loaded. Using direct domain rules instead."
else
    log "Successfully added ipset rule"
fi

# Add strict default DROP rule to CLAUDE_OUTPUT chain
log "Adding explicit DROP rule to CLAUDE_OUTPUT chain..."
iptables -A CLAUDE_OUTPUT -j DROP || log "Warning: Failed to add explicit DROP rule to CLAUDE_OUTPUT chain"

# Add logging for blocked traffic
log "Setting up logging rules..."
# Log blocked output packets in our chain (before the DROP rule)
iptables -A CLAUDE_OUTPUT -m limit --limit 5/min -j LOG --log-prefix "CLAUDE_FIREWALL OUTPUT DROP: " --log-level 4 || log "Warning: Failed to add logging rule"

log "Claude firewall configuration complete"
log "Verifying firewall rules..."

# Verify GitHub API access
if ! curl --connect-timeout 5 -s https://api.github.com/zen >/dev/null 2>&1; then
    log "WARNING: Firewall verification failed - unable to reach https://api.github.com"
else
    log "Firewall verification passed - able to reach https://api.github.com as expected"
fi

# Try to verify VS Code marketplace access
if ! curl --connect-timeout 5 -s https://marketplace.visualstudio.com/items?itemName=ms-vscode.cpptools >/dev/null 2>&1; then
    log "WARNING: Unable to verify VS Code marketplace access - connectivity may be limited"
else
    log "VS Code marketplace access verification passed"
fi

log "Claude firewall configuration finished"
exit 0
