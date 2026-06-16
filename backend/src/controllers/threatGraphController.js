// GET /api/v1/threat-graph/:id — return the correlation subgraph (nodes/edges)
// anchored on a sample, actor, or job, shaped for react-force-graph.
import { graphRepository } from '../repositories/graphRepository.js';

export async function getThreatGraph(req, res, next) {
  try {
    const graph = await graphRepository.getThreatGraph(req.params.id);
    return res.json(graph);
  } catch (err) {
    return next(err);
  }
}
