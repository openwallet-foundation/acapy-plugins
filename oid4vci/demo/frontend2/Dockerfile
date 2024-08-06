# Use an official Node.js runtime as the base image
FROM node:18

# Set the working directory in the container
WORKDIR /app

# Copy package.json and package-lock.json to the working directory
COPY ./frontend2/package*.json ./

# Install project dependencies
RUN npm install

# Copy the entire project directory into the container
COPY ./frontend2/ .

# Expose a port that the app will run on
EXPOSE 3000

# Define the command to run your application
CMD ["npm", "start"]
