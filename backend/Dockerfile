# AETHER API Gateway (Node.js/Express) container image.
FROM node:20-alpine

WORKDIR /app

# Install dependencies first (layer caching). Only package manifests change rarely.
COPY package.json ./
RUN npm install --omit=dev

# App source.
COPY . .

# Entrypoint seeds the databases (idempotent upserts) then starts the server.
RUN chmod +x docker-entrypoint.sh

EXPOSE 4000

CMD ["./docker-entrypoint.sh"]
