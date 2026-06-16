// In-memory fallback for AnalysisJobs + Feedback.
// Activated automatically when MongoDB is unreachable (see jobRepository.js).
// API surface intentionally mirrors what the repository needs so callers are
// agnostic to which backend is live. Data is process-local and NOT persisted.
import { jobSeed } from '../../seed/jobSeedData.js';

const jobs = new Map(); // job_id -> job document
const feedback = [];

// Pre-seed so the dashboard has content in no-Docker demos.
for (const j of jobSeed) {
  jobs.set(j.job_id, { ...j, createdAt: new Date(), updatedAt: new Date() });
}

export const memoryJobStore = {
  async create(doc) {
    const now = new Date();
    const record = { ...doc, createdAt: now, updatedAt: now };
    jobs.set(record.job_id, record);
    return record;
  },

  async findByJobId(jobId) {
    return jobs.get(jobId) || null;
  },

  async update(jobId, patch) {
    const existing = jobs.get(jobId);
    if (!existing) return null;
    const updated = { ...existing, ...patch, updatedAt: new Date() };
    jobs.set(jobId, updated);
    return updated;
  },

  async listRecent(limit = 20) {
    return [...jobs.values()]
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
      .slice(0, limit);
  },

  async createFeedback(doc) {
    const record = { ...doc, createdAt: new Date() };
    feedback.push(record);
    return record;
  },
};
