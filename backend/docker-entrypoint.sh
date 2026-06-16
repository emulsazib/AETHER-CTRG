#!/bin/sh
# Seed the databases (idempotent — safe on every boot), then launch the gateway.
# Seeding "fails soft": if a DB is briefly unavailable the seeder warns and skips,
# and the server's own connectors retry / fall back as needed.
set -e

echo "[entrypoint] seeding mock data..."
node src/seed/index.js || echo "[entrypoint] seeding skipped/failed — continuing."

echo "[entrypoint] starting API gateway..."
exec node src/server.js
