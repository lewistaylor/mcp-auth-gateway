FROM node:22-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates curl python3 make g++ && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY server.mjs ./

RUN mkdir -p /app/data && chown -R node:node /app/data

USER node
EXPOSE 8000

CMD ["node", "server.mjs"]
