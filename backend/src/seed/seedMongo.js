// Seed MongoDB AnalysisJobs from the shared jobSeed (mirrors mock datasets).
// No-op-with-warning if MongoDB is unreachable (the in-memory store self-seeds).
import { connectMongo, isMongoConnected, disconnectMongo } from '../config/mongo.js';
import { AnalysisJob } from '../models/AnalysisJob.js';
import { jobSeed } from './jobSeedData.js';

export async function seedMongo() {
  await connectMongo();
  if (!isMongoConnected()) {
    console.warn('[seed:mongo] MongoDB unreachable — skipping (memory store self-seeds).');
    return;
  }
  for (const job of jobSeed) {
    await AnalysisJob.updateOne({ job_id: job.job_id }, { $set: job }, { upsert: true });
  }
  console.log(`[seed:mongo] upserted ${jobSeed.length} AnalysisJobs.`);
}

// Allow running standalone: `node src/seed/seedMongo.js`
if (import.meta.url === `file://${process.argv[1]}`) {
  seedMongo().then(() => disconnectMongo());
}
