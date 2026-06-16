// MongoDB connection manager with graceful in-memory fallback.
// connectMongo() attempts a real connection; on failure it logs a warning and
// leaves `mongoConnected` false so repositories switch to memoryJobStore.
import mongoose from 'mongoose';
import { config } from './env.js';

let mongoConnected = false;

export async function connectMongo() {
  try {
    await mongoose.connect(config.mongoUri, { serverSelectionTimeoutMS: 3000 });
    mongoConnected = true;
    console.log('[mongo] connected:', config.mongoUri.replace(/\/\/.*@/, '//***@'));
  } catch (err) {
    mongoConnected = false;
    console.warn(
      `[mongo] connection FAILED (${err.message}). ` +
        'Falling back to in-memory job store — data will NOT persist.',
    );
  }
  return mongoConnected;
}

export function isMongoConnected() {
  return mongoConnected && mongoose.connection.readyState === 1;
}

export async function disconnectMongo() {
  if (mongoConnected) await mongoose.disconnect();
}
