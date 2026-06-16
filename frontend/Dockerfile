# AETHER Frontend (React/Vite) — multi-stage: build static assets, serve via nginx.

# ---- Build stage ----
FROM node:20-alpine AS build
WORKDIR /app

# VITE_API_BASE is baked into the bundle at BUILD time (Vite client env).
# It must be the URL the BROWSER uses to reach the gateway (host-published port),
# NOT the docker-internal hostname. Override at build with --build-arg.
ARG VITE_API_BASE=http://localhost:4000/api/v1
ARG VITE_POLL_INTERVAL_MS=2000
ENV VITE_API_BASE=$VITE_API_BASE
ENV VITE_POLL_INTERVAL_MS=$VITE_POLL_INTERVAL_MS

COPY package.json ./
RUN npm install
COPY . .
RUN npm run build

# ---- Serve stage ----
FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
