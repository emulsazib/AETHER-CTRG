// Centralized, typed access to environment variables. Importing this module
// loads .env once and exposes a frozen config object so the rest of the app
// never reads process.env directly (easier to audit / change later).
import dotenv from 'dotenv';

dotenv.config();

export const config = Object.freeze({
  port: parseInt(process.env.PORT || '4000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  corsOrigins: (process.env.CORS_ORIGINS || 'http://localhost:5173')
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean),

  mongoUri: process.env.MONGO_URI || 'mongodb://localhost:27017/aether',

  neo4jUri: process.env.NEO4J_URI || 'bolt://localhost:7687',
  neo4jUser: process.env.NEO4J_USER || 'neo4j',
  neo4jPassword: process.env.NEO4J_PASSWORD || 'neo4j',

  mlWorkerUrl: process.env.ML_WORKER_URL || 'http://localhost:8000',
  mlWorkerTimeoutMs: parseInt(process.env.ML_WORKER_TIMEOUT_MS || '15000', 10),

  alienvaultUrl: process.env.ALIENVAULT_OTX_URL || '',
  abuseipdbUrl: process.env.ABUSEIPDB_URL || '',
});
