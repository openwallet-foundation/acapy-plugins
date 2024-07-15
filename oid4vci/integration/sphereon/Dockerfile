FROM oven/bun:slim AS base
WORKDIR /usr/src/app
RUN apt-get update && apt-get install ncat -y && apt-get clean

COPY bun.lockb package.json ./
RUN bun install
COPY . .

EXPOSE 3000

CMD [ "bun", "run", "index.ts"]
