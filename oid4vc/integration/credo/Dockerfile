# =============================================================================
# Stage 1: Build stage with native dependencies
# Note: Using slim-bookworm instead of alpine because @openwallet-foundation/askar-nodejs
# requires glibc (not musl libc). Alpine causes "__isnan: symbol not found" errors.
# Note: Node 20+ required for @credo-ts/node@0.6.x dependencies (@noble/curves, @sd-jwt, etc)
# =============================================================================
FROM --platform=linux/amd64 node:20-slim AS build

WORKDIR /app

# Install build dependencies for native modules
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    make \
    g++ \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy package files first (for layer caching)
COPY package.json package-lock.json* ./

# Install all dependencies (use npm install if no lock file exists)
# Set npm config to ignore scripts during `npm ci` to bypass pnpm-only checks
# in @sphereon/pex (@sphereon/pex has `preinstall: npx only-allow pnpm` which
# is blocked by org npm security policy).
# After install, rebuild the native modules that need their install scripts:
#   - @2060.io/ffi-napi and @2060.io/ref-napi: native FFI bindings (compiled)
#   - @openwallet-foundation/askar-nodejs: prebuilt binary selector
# Targeting specific packages avoids triggering @sphereon/pex lifecycle scripts.
RUN npm config set ignore-scripts true && \
    if [ -f package-lock.json ]; then npm ci; else npm install; fi && \
    npm config set ignore-scripts false && \
    npm rebuild @2060.io/ffi-napi @2060.io/ref-napi @openwallet-foundation/askar-nodejs

# Copy source code
COPY . .

# Build TypeScript
RUN npm run build

# Prune dev dependencies for production
RUN npm prune --production

# =============================================================================
# Stage 2: Production runtime
# =============================================================================
FROM --platform=linux/amd64 node:20-slim

WORKDIR /app

# Install only runtime dependencies (curl for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy built application and production node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/package.json ./

# Healthcheck
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=10 \
  CMD curl -f http://localhost:${PORT:-3020}/health || exit 1

EXPOSE 3020

CMD ["npm", "start"]
