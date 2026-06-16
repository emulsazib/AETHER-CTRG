// Entrypoint: connect DBs (with graceful fallback), then start the HTTP server.
import { createApp } from './app.js';
import { config } from './config/env.js';
import { connectMongo } from './config/mongo.js';
import { connectNeo4j } from './config/neo4j.js';

async function start() {
  // Both connections fall back to in-memory stores on failure, so a failed
  // connection is a warning, not a fatal error.
  await Promise.all([connectMongo(), connectNeo4j()]);

  const app = createApp();
  app.listen(config.port, () => {
    console.log(`[gateway] AETHER API Gateway listening on http://localhost:${config.port}`);
    console.log(`[gateway] ML worker expected at ${config.mlWorkerUrl}`);
  });
}

start();
