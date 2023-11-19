FROM node:18 AS base
WORKDIR /usr/src/app
RUN apt-get update && apt-get install ncat -y && apt-get clean

COPY package*.json ./
COPY aries-framework-javascript/ ./

RUN npm install

COPY . .

RUN npm run build

EXPOSE 3000

CMD [ "node", "dist/app.js" ]
