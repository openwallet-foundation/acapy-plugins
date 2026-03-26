# Use node:20-slim (Debian) instead of Alpine for consistency with Credo
# and to avoid potential glibc compatibility issues with native modules
FROM node:20-slim

WORKDIR /usr/src/app

# Install curl for healthcheck (consistent with other services)
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY package*.json ./

RUN npm install

COPY . .

RUN npm run build

EXPOSE 3010

HEALTHCHECK --interval=10s --timeout=5s --retries=5 --start-period=30s \
  CMD curl -f http://localhost:3010/health || exit 1

CMD [ "npm", "start" ]
