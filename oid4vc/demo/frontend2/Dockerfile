FROM node:18
WORKDIR /app

COPY ./package*.json ./
RUN npm install

COPY ./templates .
COPY ./index.js ./

EXPOSE 3000

CMD ["npm", "start"]
