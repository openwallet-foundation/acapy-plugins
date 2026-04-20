FROM node:18
WORKDIR /app

# Install jq for JSON parsing in entrypoint.sh
RUN apt-get update && apt-get install -y jq && rm -rf /var/lib/apt/lists/*

COPY ./package*.json ./
RUN npm install
RUN npm install -g nodemon

COPY ./templates .
COPY ./index.js ./

COPY ./entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

EXPOSE 3000

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["npm", "start"]