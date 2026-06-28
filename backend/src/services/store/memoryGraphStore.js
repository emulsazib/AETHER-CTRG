// In-memory fallback for the threat-correlation graph.
// Activated when Neo4j is unreachable (see graphRepository.js). Self-seeds from
// the shared graphSeed so /threat-graph returns a meaningful subgraph.
import { graphSeed } from '../../seed/graphSeedData.js';
import { isIpv4, refang } from '../../utils/indicators.js';

const nodes = new Map(graphSeed.nodes.map((n) => [n.id, n]));
const edges = [...graphSeed.edges];

// Breadth-first collection of the subgraph reachable from a set of seed node ids.
function subgraphFrom(seedIds, depth = 2) {
  const included = new Set();
  let frontier = new Set(seedIds.filter((id) => nodes.has(id)));
  for (let d = 0; d <= depth; d += 1) {
    const next = new Set();
    for (const e of edges) {
      if (frontier.has(e.source) && !included.has(e.target)) next.add(e.target);
      if (frontier.has(e.target) && !included.has(e.source)) next.add(e.source);
    }
    frontier.forEach((id) => included.add(id));
    frontier = next;
  }
  const nodeList = [...included].map((id) => nodes.get(id)).filter(Boolean);
  const edgeList = edges.filter((e) => included.has(e.source) && included.has(e.target));
  return { nodes: nodeList, edges: edgeList };
}

export const memoryGraphStore = {
  // Return a subgraph anchored on a sample/actor matching `id`. Falls back to
  // the full graph when nothing matches (useful for the explorer overview).
  async getThreatGraph(id) {
    const direct = [...nodes.keys()].filter(
      (nid) => nid.includes(id) || nodes.get(nid).name === id,
    );
    if (direct.length > 0) return subgraphFrom(direct, 2);
    // Fallback: whole graph so the UI always has something to render.
    return { nodes: [...nodes.values()], edges: [...edges] };
  },

  // Upsert a freshly-analyzed sample and connect it to its IoCs/TTPs/actor.
  // Kept in lockstep with the Neo4j path (graphRepository.js): same refang, same
  // IP reputation props, same attribution stamp on the campaign edge.
  async upsertSampleGraph({
    jobId, fileName, fileType, iocs = [], ttps = [], actor,
    iocReputation = {}, attribution = null,
  }) {
    const sampleId = `sample:job:${jobId}`;
    nodes.set(sampleId, {
      id: sampleId,
      label: 'MalwareSample',
      name: fileName || jobId,
      props: { file_type: fileType, job_id: jobId },
    });
    if (actor) {
      const actorId = `actor:${actor.toLowerCase().replace(/\s+/g, '-')}`;
      if (!nodes.has(actorId)) nodes.set(actorId, { id: actorId, label: 'ThreatActor', name: actor, props: {} });
      edges.push({
        source: sampleId,
        target: actorId,
        type: 'BELONGS_TO_CAMPAIGN',
        props: { confidence: attribution?.confidence ?? null, source: attribution?.source || 'heuristic' },
      });
    }
    for (const ttp of ttps) {
      const ttpId = `ttp:${ttp}`;
      if (!nodes.has(ttpId)) nodes.set(ttpId, { id: ttpId, label: 'TTP', name: ttp, props: {} });
      edges.push({ source: sampleId, target: ttpId, type: 'USES_TTP', props: {} });
    }
    for (const raw of iocs) {
      const ip = refang(raw);
      if (!isIpv4(ip)) continue;
      const ipId = `ip:${ip}`;
      const rep = iocReputation[ip]?.abuseipdb || {};
      const props = {
        ...(nodes.get(ipId)?.props || {}),
        ...(rep.abuse_confidence != null ? { abuse_confidence: rep.abuse_confidence } : {}),
        ...(rep.country ? { country: rep.country } : {}),
        ...(rep.isp ? { isp: rep.isp } : {}),
      };
      nodes.set(ipId, { id: ipId, label: 'IP_Address', name: ip, props });
      edges.push({ source: sampleId, target: ipId, type: 'COMMUNICATES_WITH', props: {} });
    }
    return { sampleId };
  },
};
