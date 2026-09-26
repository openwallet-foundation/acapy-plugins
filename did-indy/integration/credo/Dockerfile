FROM node:20 AS base
WORKDIR /usr/src/app
RUN apt-get update && apt-get install ncat -y && apt-get clean

COPY package*.json ./
COPY patches/ patches/
RUN npm ci
COPY . .

EXPOSE 3000

CMD [ "npm", "run", "watch" ]
