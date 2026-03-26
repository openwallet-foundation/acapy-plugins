# =============================================================================
# Playwright image with Chromium for E2E testing
# =============================================================================
FROM mcr.microsoft.com/playwright:v1.48.0-focal

WORKDIR /app

# Copy package files first (for layer caching)
COPY package.json ./

# Clear npm cache and reinstall with exact versions
RUN npm cache clean --force && npm install

# Playwright browsers are already installed in the base image

# Copy TypeScript config and source files
COPY tsconfig.json playwright.config.ts ./
COPY helpers/ ./helpers/
COPY tests/ ./tests/
COPY certs/ ./certs/

# Create test-results directory
RUN mkdir -p test-results

# Default command runs all tests with system Chromium
CMD ["npx", "playwright", "test", "--reporter=html,list"]
