// Neo4j connection manager with graceful in-memory fallback.
// connectNeo4j() verifies connectivity; on failure repositories use
// memoryGraphStore instead.
import neo4j from 'neo4j-driver';
import { config } from './env.js';

let driver = null;
let neo4jConnected = false;

export async function connectNeo4j() {
  try {
    driver = neo4j.driver(
      config.neo4jUri,
      neo4j.auth.basic(config.neo4jUser, config.neo4jPassword),
      { connectionTimeout: 3000 },
    );
    await driver.verifyConnectivity();
    neo4jConnected = true;
    console.log('[neo4j] connected:', config.neo4jUri);
  } catch (err) {
    neo4jConnected = false;
    driver = null;
    console.warn(
      `[neo4j] connection FAILED (${err.message}). ` +
        'Falling back to in-memory graph store — data will NOT persist.',
    );
  }
  return neo4jConnected;
}

export function isNeo4jConnected() {
  return neo4jConnected && driver !== null;
}

export function getDriver() {
  return driver;
}

export async function disconnectNeo4j() {
  if (driver) await driver.close();
}
