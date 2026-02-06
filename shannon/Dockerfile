#
# Multi-stage Dockerfile for Pentest Agent
# Uses Ubuntu for broad compatibility

# Builder stage - Install tools and dependencies
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    curl \
    wget \
    ca-certificates \
    libpcap-dev \
    # Language runtimes
    golang-go \
    python3 \
    python3-pip \
    ruby \
    ruby-dev \
    # Security tools
    nmap \
    bash \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js 22
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# Set environment variables for Go
ENV GOPATH=/go
ENV PATH=$GOPATH/bin:/usr/local/go/bin:$PATH
ENV CGO_ENABLED=1

# Create directories
RUN mkdir -p $GOPATH/bin

# Install Go-based security tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Install WhatWeb from GitHub (Ruby-based tool)
RUN git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb && \
    chmod +x /opt/whatweb/whatweb && \
    gem install addressable && \
    echo '#!/bin/bash' > /usr/local/bin/whatweb && \
    echo 'cd /opt/whatweb && exec ./whatweb "$@"' >> /usr/local/bin/whatweb && \
    chmod +x /usr/local/bin/whatweb

# Install Python-based tools
RUN pip3 install --no-cache-dir --break-system-packages schemathesis

# Runtime stage
FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    bash \
    curl \
    ca-certificates \
    libpcap0.8t64 \
    nmap \
    python3 \
    ruby \
    # Chromium and dependencies
    chromium-browser \
    fonts-liberation \
    libnss3 \
    libfreetype6 \
    libharfbuzz0b \
    libx11-6 \
    libxcomposite1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    fontconfig \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js 22
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# Copy Go binaries from builder
COPY --from=builder /go/bin/subfinder /usr/local/bin/

# Copy WhatWeb from builder
COPY --from=builder /opt/whatweb /opt/whatweb
COPY --from=builder /usr/local/bin/whatweb /usr/local/bin/whatweb

# Install WhatWeb Ruby dependencies in runtime stage
RUN gem install addressable

# Copy Python packages from builder
COPY --from=builder /usr/lib/python3/dist-packages /usr/lib/python3/dist-packages
COPY --from=builder /usr/local/lib/python3.*/dist-packages /usr/local/lib/python3.12/dist-packages
COPY --from=builder /usr/local/bin/schemathesis /usr/local/bin/

# Create non-root user for security
RUN groupadd -g 1001 pentest && \
    useradd -u 1001 -g pentest -s /bin/bash -m pentest

# Set working directory
WORKDIR /app

# Copy package files first for better caching
COPY package*.json ./
COPY mcp-server/package*.json ./mcp-server/

# Install Node.js dependencies (including devDependencies for TypeScript build)
RUN npm ci && \
    cd mcp-server && npm ci && cd .. && \
    npm cache clean --force

# Copy application source code
COPY . .

# Build TypeScript (mcp-server first, then main project)
RUN cd mcp-server && npm run build && cd .. && npm run build

# Remove devDependencies after build to reduce image size
RUN npm prune --production && \
    cd mcp-server && npm prune --production

# Create directories for session data and ensure proper permissions
RUN mkdir -p /app/sessions /app/deliverables /app/repos /app/configs && \
    mkdir -p /tmp/.cache /tmp/.config /tmp/.npm && \
    chmod 777 /app && \
    chmod 777 /tmp/.cache && \
    chmod 777 /tmp/.config && \
    chmod 777 /tmp/.npm && \
    chown -R pentest:pentest /app

# Switch to non-root user
USER pentest

# Configure Git to trust all directories
RUN git config --global --add safe.directory '*'

# Set environment variables
ENV NODE_ENV=production
ENV PATH="/usr/local/bin:$PATH"
ENV SHANNON_DOCKER=true
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
ENV PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium-browser
ENV npm_config_cache=/tmp/.npm
ENV HOME=/tmp
ENV XDG_CACHE_HOME=/tmp/.cache
ENV XDG_CONFIG_HOME=/tmp/.config

# Set entrypoint
ENTRYPOINT ["node", "dist/shannon.js"]
