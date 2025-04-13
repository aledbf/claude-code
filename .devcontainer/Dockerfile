FROM node:20

ARG TZ
ENV TZ="$TZ"

# Install basic development tools and runit
RUN apt update && apt install -y \
  less git procps fzf zsh ca-certificates man-db unzip \
  gnupg2 gh iptables ipset iproute2 dnsutils \
  aggregate sudo xz-utils jq lsof net-tools nano \
  runit netcat-openbsd \
  squid-openssl openssl ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  && apt clean

RUN mkdir -p /etc/service/log/main && \
  echo '#!/bin/sh' > /etc/service/log/run && \
  echo 'exec svlogd -tt /var/log/runit' >> /etc/service/log/run && \
  chmod +x /etc/service/log/run && \
  mkdir -p /var/log/runit

RUN mkdir -p /etc/squid/ssl_cert && \
  chmod 700 /etc/squid/ssl_cert && \
  cd /etc/squid/ssl_cert && \
  openssl req -new -newkey rsa:2048 -sha256 -days 3650 -nodes -x509 \
    -keyout squid.key -out squid.crt \
    -subj "/CN=Squid Proxy CA"

RUN cat squid.key squid.crt > squid.pem && \
  chmod 400 squid.pem squid.key && \
  chown proxy:proxy -R /etc/squid/ssl_cert

COPY <<EOF /etc/squid/squid.conf
# Basic settings
http_port 31265 intercept
# SSL Bump Configuration
https_port 31266 intercept ssl-bump generate-host-certificates=on dynamic_cert_mem_cache_size=4MB cert=/etc/squid/ssl_cert/squid.pem

# SSL Bump rules
acl step1 at_step SslBump1
ssl_bump peek step1
ssl_bump bump all

# Access control and whitelist
acl whitelist dstdomain "/etc/squid/whitelist.txt"
acl blocked_ports port 80 443
http_access allow localhost
http_access allow whitelist
http_access deny blocked_ports
http_access allow all

# Logging
access_log daemon:/var/log/squid/access.log combined
cache_log /var/log/squid/cache.log
EOF

RUN cp /etc/squid/ssl_cert/squid.crt /usr/local/share/ca-certificates/ && \
  update-ca-certificates

RUN mkdir -p /etc/service/squid /etc/service/init-firewall /etc/service/user-shell

# Set up init-firewall service
COPY --chmod=755 <<EOF /etc/service/init-firewall/run
#!/bin/sh
# Run once, then exit
/usr/local/bin/init-firewall.sh
# Touch a file to indicate this has run
touch /tmp/firewall-initialized
# Exit - this service only needs to run once
exit 0
EOF

# Set up squid service (waits for firewall)
COPY --chmod=755 <<EOF /etc/service/squid/run
#!/bin/sh
# Wait for firewall to be initialized
while [ ! -f /tmp/firewall-initialized ]; do
  echo "Waiting for firewall to initialize..."
  sleep 1
done
echo "Starting squid service..."
exec /usr/sbin/squid -N -f /etc/squid/squid.conf
EOF

# Set up user-shell service (waits for squid)
COPY --chmod=755 <<EOF /etc/service/user-shell/run
#!/bin/sh
# Wait for squid to be ready
until nc -z localhost 31265; do
  echo "Waiting for squid to be ready..."
  sleep 1
done
echo "Starting user shell..."

# Create a flag file to indicate the shell service has started
touch /tmp/user-shell-started

# Instead of starting a new shell, keep service alive
while true; do
  sleep 3600
done

EOF

# Make service logs available
RUN mkdir -p /var/log/squid /var/log/init-firewall /var/log/user-shell && \
    chmod -R 755 /etc/service

# Add a helper script to check service status
COPY --chmod=755 <<EOF /usr/local/bin/service-status
#!/bin/sh
echo "Runit Service Status:"
echo "==================="
sv status /etc/service/*
EOF

# Ensure default node user has access to /usr/local/share
RUN mkdir -p /usr/local/share/npm-global && \
  chown -R node:node /usr/local/share

ARG USERNAME=node

# Persist bash history.
RUN SNIPPET="export PROMPT_COMMAND='history -a' && export HISTFILE=/commandhistory/.bash_history" \
  && mkdir -p /commandhistory \
  && touch /commandhistory/.bash_history \
  && chown -R $USERNAME /commandhistory

# Set `DEVCONTAINER` environment variable to help with orientation
ENV DEVCONTAINER=true

# Create workspace and config directories and set permissions
RUN mkdir -p /workspace /home/node/.claude && \
  chown -R node:node /workspace /home/node/.claude

WORKDIR /workspace

RUN ARCH=$(dpkg --print-architecture) && \
  wget "https://github.com/dandavison/delta/releases/download/0.18.2/git-delta_0.18.2_${ARCH}.deb" && \
  dpkg -i "git-delta_0.18.2_${ARCH}.deb" && \
  rm "git-delta_0.18.2_${ARCH}.deb"

# Install global packages - as root, runit will handle user switching
ENV NPM_CONFIG_PREFIX=/usr/local/share/npm-global
ENV PATH=$PATH:/usr/local/share/npm-global/bin

# Set the default shell to zsh
ENV SHELL=/bin/zsh

# Default powerline10k theme - using su to run as node user
RUN wget -O /tmp/zsh-in-docker.sh https://github.com/deluan/zsh-in-docker/releases/download/v1.2.0/zsh-in-docker.sh && \
    chmod +x /tmp/zsh-in-docker.sh && \
    su node -c "/tmp/zsh-in-docker.sh -p git -p fzf \
      -a 'source /usr/share/doc/fzf/examples/key-bindings.zsh' \
      -a 'source /usr/share/doc/fzf/examples/completion.zsh' \
      -a 'export PROMPT_COMMAND=\"history -a\" && export HISTFILE=/commandhistory/.bash_history' \
      -x" && \
    rm /tmp/zsh-in-docker.sh

# Install Claude - using su to run as node user
RUN su node -c "npm install -g @anthropic-ai/claude-code"

# Copy and set up firewall script
COPY init-firewall.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/init-firewall.sh

# Copy Squid whitelist
COPY whitelist.txt /etc/squid/whitelist.txt

# Make node user able to check service status
RUN echo "node ALL=(root) NOPASSWD: /usr/local/bin/service-status" > /etc/sudoers.d/node-services && \
    chmod 0440 /etc/sudoers.d/node-services

# Customize zsh for the node user
RUN echo "alias status='sudo /usr/local/bin/service-status'" >> /home/node/.zshrc && \
    chown node:node /home/node/.zshrc

# Setting the ENTRYPOINT to runit
ENTRYPOINT ["runsvdir", "-P", "/etc/service"]
CMD ["sleep", "infinity"]

# Stay as root for container startup - runit needs to run as root
USER root
