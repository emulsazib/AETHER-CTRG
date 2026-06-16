// POST /api/v1/feedback — capture analyst corrections for the self-learning
// feedback loop (PRD §5.4).
//
// EXTENSION POINT: this is where a real system would enqueue the correction for
// model retraining / active-learning. For the MVP we simply persist it.
import { jobRepository } from '../repositories/jobRepository.js';

export async function submitFeedback(req, res, next) {
  try {
    const { job_id, correct_label, corrected_actor, notes, analyst } = req.body;
    if (!job_id) return res.status(400).json({ error: 'job_id is required' });

    const record = await jobRepository.createFeedback({
      job_id,
      analyst: analyst || 'anonymous',
      correct_label: correct_label || null,
      corrected_actor: corrected_actor || null,
      notes: notes || '',
    });

    // TODO(real): publish `record` to a retraining queue / active-learning store.
    return res.status(201).json({ status: 'recorded', feedback: record });
  } catch (err) {
    return next(err);
  }
}
