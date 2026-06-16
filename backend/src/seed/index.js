// Run all seeders (`npm run seed`). Safe to run without Docker — each seeder
// warns and skips if its database is unreachable.
import { disconnectMongo } from '../config/mongo.js';
import { disconnectNeo4j } from '../config/neo4j.js';
import { seedMongo } from './seedMongo.js';
import { seedNeo4j } from './seedNeo4j.js';

async function run() {
  console.log('[seed] starting AETHER mock-data seeding...');
  await seedMongo();
  await seedNeo4j();
  console.log('[seed] done.');
  await Promise.all([disconnectMongo(), disconnectNeo4j()]);
  process.exit(0);
}

run().catch((err) => {
  console.error('[seed] failed:', err);
  process.exit(1);
});
