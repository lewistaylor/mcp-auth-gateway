FROM node:22-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates curl python3 make g++ && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY server.mjs ./
COPY lib ./lib
COPY scripts ./scripts

RUN mkdir -p /app/data && chown -R node:node /app/data

COPY entrypoint.sh ./
RUN chmod +x entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["./entrypoint.sh"]
