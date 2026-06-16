// Job/Feedback repository — single data-access surface for controllers.
// Transparently routes to MongoDB when connected, else the in-memory store.
// Controllers call ONLY these methods and never know which backend is live.
import { isMongoConnected } from '../config/mongo.js';
import { AnalysisJob, Feedback } from '../models/AnalysisJob.js';
import { memoryJobStore } from '../services/store/memoryJobStore.js';

export const jobRepository = {
  async create(doc) {
    if (isMongoConnected()) return (await AnalysisJob.create(doc)).toObject();
    return memoryJobStore.create(doc);
  },

  async findByJobId(jobId) {
    if (isMongoConnected()) return AnalysisJob.findOne({ job_id: jobId }).lean();
    return memoryJobStore.findByJobId(jobId);
  },

  async update(jobId, patch) {
    if (isMongoConnected()) {
      return AnalysisJob.findOneAndUpdate({ job_id: jobId }, patch, { new: true }).lean();
    }
    return memoryJobStore.update(jobId, patch);
  },

  async listRecent(limit = 20) {
    if (isMongoConnected()) {
      return AnalysisJob.find().sort({ createdAt: -1 }).limit(limit).lean();
    }
    return memoryJobStore.listRecent(limit);
  },

  async createFeedback(doc) {
    if (isMongoConnected()) return (await Feedback.create(doc)).toObject();
    return memoryJobStore.createFeedback(doc);
  },
};
