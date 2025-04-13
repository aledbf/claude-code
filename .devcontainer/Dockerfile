FROM node:20

ARG TZ
ENV TZ="$TZ"

# Install basic development tools and iptables/ipset
RUN apt update && apt install -y \
  less \
  git \
  procps \
  fzf \
  zsh \
  ca-certificates \
  man-db \
  unzip \
  privoxy \
  gnupg2 \
  gh \
  iptables \
  ipset \
  iproute2 \
  dnsutils \
  aggregate \
  sudo \
  xz-utils \
  jq \
  lsof net-tools \
  && rm -rf /var/lib/apt/lists/* \
  && apt clean

# S6 configuration
ARG S6_OVERLAY_VERSION=3.1.5.0
ENV S6_KEEP_ENV=1
ENV S6_BEHAVIOUR_IF_STAGE2_FAILS=2
ENV S6_CMD_WAIT_FOR_SERVICES=1
ENV S6_LOGGING=0

# Download and install s6-overlay properly - using the recommended approach
RUN case "$(uname -m)" in \
    x86_64) S6_ARCH="x86_64";; \
    aarch64) S6_ARCH="aarch64";; \
    *) echo "Unsupported architecture" && exit 1;; \
  esac \
  && curl -fsSL "https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz" -o /tmp/s6-overlay-noarch.tar.xz \
  && curl -fsSL "https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-${S6_ARCH}.tar.xz" -o /tmp/s6-overlay-${S6_ARCH}.tar.xz \
  && tar -C / -Jxpf /tmp/s6-overlay-noarch.tar.xz \
  && tar -C / -Jxpf /tmp/s6-overlay-${S6_ARCH}.tar.xz \
  && rm -f /tmp/s6-overlay-*.tar.xz

# Create necessary directories for s6
RUN mkdir -p /etc/s6-overlay/s6-rc.d \
             /etc/services.d \
             /var/run/s6 \
             /var/log/s6

# Create a simple s6 service for privoxy in the legacy format (simpler to start with)
RUN mkdir -p /etc/services.d/privoxy
COPY --chmod=755 <<EOF /etc/services.d/privoxy/run
#!/bin/sh
exec 2>&1
exec privoxy --no-daemon /etc/privoxy/config
EOF

# Create a simple s6 service for init-firewall in the legacy format
RUN mkdir -p /etc/services.d/init-firewall
COPY --chmod=755 <<EOF /etc/services.d/init-firewall/run
#!/bin/sh
exec 2>&1
/usr/local/bin/init-firewall.sh
# Sleep to keep the service running - this is a workaround
exec sleep infinity
EOF

# Ensure default node user has access to /usr/local/share
RUN mkdir -p /usr/local/share/npm-global && \
  chown -R node:node /usr/local/share

ARG USERNAME=node

# Persist bash history.
RUN SNIPPET="export PROMPT_COMMAND='history -a' && export HISTFILE=/commandhistory/.bash_history" \
  && mkdir /commandhistory \
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

# Install global packages - as root, s6 will handle user switching
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

# Copy Privoxy configuration
COPY privoxy.conf /etc/privoxy/config
COPY whitelist.txt /etc/privoxy/whitelist.txt

# Setting the ENTRYPOINT to s6 will start the init system
ENTRYPOINT ["/init"]
CMD ["sleep", "infinity"]

# Stay as root for container startup - s6 needs to run as root
USER root

RUN echo "node ALL=(root) NOPASSWD: /command/s6-svstat" > /etc/sudoers.d/node-s6 && \
  chmod 0440 /etc/sudoers.d/node-s6

