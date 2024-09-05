FROM node:18
WORKDIR /app

COPY ./package*.json ./
RUN npm install
RUN npm install -g nodemon

COPY ./templates .
COPY ./index.js ./

EXPOSE 3000

CMD ["nodemon", "npm", "start"]
