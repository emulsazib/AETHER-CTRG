// GET /api/v1/analysis/:id      — fetch a single job's status + results.
// GET /api/v1/analysis          — list recent ingestions (dashboard feed).
import { jobRepository } from '../repositories/jobRepository.js';

export async function getAnalysis(req, res, next) {
  try {
    const job = await jobRepository.findByJobId(req.params.id);
    if (!job) return res.status(404).json({ error: 'Job not found' });
    return res.json(job);
  } catch (err) {
    return next(err);
  }
}

export async function listAnalyses(req, res, next) {
  try {
    const limit = Math.min(parseInt(req.query.limit || '20', 10), 100);
    const jobs = await jobRepository.listRecent(limit);
    return res.json({ count: jobs.length, jobs });
  } catch (err) {
    return next(err);
  }
}
