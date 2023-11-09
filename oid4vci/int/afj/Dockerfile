# ---- Base Stage ----
FROM node:18 AS base

# Set the working directory
WORKDIR /usr/src/app

# Copy package.json and package-lock.json (if available)
COPY package*.json ./

# ---- Dependencies Stage ----
FROM base AS dependencies

# Install node modules, including 'devDependencies' for building the TypeScript source
RUN npm install

# Copy the rest of the application source code
COPY . .

# Build the TypeScript source
RUN npm run build

# ---- Release Stage ----
FROM node:18 AS release

# Set the working directory for the release stage
WORKDIR /usr/src/app

# Copy package.json and package-lock.json for the production installation
COPY package*.json ./

# Install production node_modules (skip 'devDependencies')
RUN npm ci --only=production

# Copy built node modules and build directory from the 'dependencies' stage
COPY --from=dependencies /usr/src/app/dist ./dist

# Your app binds to port 3000 so you'll use the EXPOSE instruction to have it mapped by the docker daemon
EXPOSE 3000

# Define the command to run your app using CMD which defines your runtime
CMD [ "node", "dist/app.js" ]
