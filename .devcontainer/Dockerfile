FROM node:20

ARG TZ
ENV TZ="$TZ"

# Install basic development tools and iptables/ipset
RUN apt update && apt install -y less \
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
  jq

# --- Install s6-overlay ---
ARG S6_OVERLAY_VERSION=3.1.6.2
RUN ARCH=$(dpkg --print-architecture) && \
    wget -q "https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-${ARCH}.tar.xz" -O /tmp/s6-overlay.tar.xz && \
    tar -C / -Jxpf /tmp/s6-overlay.tar.xz && \
    rm /tmp/s6-overlay.tar.xz

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
ENV SHELL /bin/zsh

# Default powerline10k theme - using su to run as node user
RUN su node -c "sh -c \"$(wget -O- https://github.com/deluan/zsh-in-docker/releases/download/v1.2.0/zsh-in-docker.sh)\" -- \
  -p git \
  -p fzf \
  -a \"source /usr/share/doc/fzf/examples/key-bindings.zsh\" \
  -a \"source /usr/share/doc/fzf/examples/completion.zsh\" \
  -a \"export PROMPT_COMMAND='history -a' && export HISTFILE=/commandhistory/.bash_history\" \
  -x"

# Install Claude - using su to run as node user
RUN su node -c "npm install -g @anthropic-ai/claude-code"

# Copy and set up firewall script
COPY init-firewall.sh /usr/local/bin/
# Copy Privoxy configuration
COPY privoxy.conf /etc/privoxy/config
COPY whitelist.txt /etc/privoxy/whitelist.txt
# Copy s6 service definitions
COPY s6-services/ /etc/s6-overlay/s6-rc.d/

# Set permissions on scripts
RUN chmod +x /usr/local/bin/init-firewall.sh \
             /etc/s6-overlay/s6-rc.d/init-firewall/run \
             /etc/s6-overlay/s6-rc.d/privoxy/run \
             /etc/s6-overlay/s6-rc.d/user-shell/run

# s6 as entrypoint
ENTRYPOINT ["/init"]
CMD ["/bin/zsh"]
