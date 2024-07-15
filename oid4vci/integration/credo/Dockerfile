FROM node:20 AS base
WORKDIR /usr/src/app
RUN apt-get update && apt-get install ncat -y && apt-get clean

COPY package*.json ./
RUN npm install
COPY . .

EXPOSE 3000

CMD [ "npm", "run", "watch" ]
