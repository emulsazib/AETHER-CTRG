// Threat-graph repository — routes to Neo4j when connected, else memory store.
// Returns data shaped for react-force-graph: { nodes:[{id,label,name,props}],
// edges:[{source,target,type,props}] }.
import { getDriver, isNeo4jConnected } from '../config/neo4j.js';
import { memoryGraphStore } from '../services/store/memoryGraphStore.js';
import { isIpv4, refang } from '../utils/indicators.js';

// Map a Neo4j node/relationship result set into the frontend graph shape.
function mapNeoRecords(records) {
  const nodesById = new Map();
  const edges = [];
  for (const rec of records) {
    const n = rec.get('n');
    const m = rec.has('m') ? rec.get('m') : null;
    const r = rec.has('r') ? rec.get('r') : null;
    for (const node of [n, m]) {
      if (!node) continue;
      const id = node.properties.id || node.elementId;
      if (!nodesById.has(id)) {
        nodesById.set(id, {
          id,
          label: node.labels?.[0] || 'Node',
          name: node.properties.name || id,
          props: node.properties,
        });
      }
    }
    if (r && n && m) {
      edges.push({
        source: n.properties.id || n.elementId,
        target: m.properties.id || m.elementId,
        type: r.type,
        props: r.properties,
      });
    }
  }
  return { nodes: [...nodesById.values()], edges };
}

export const graphRepository = {
  async getThreatGraph(id) {
    if (!isNeo4jConnected()) return memoryGraphStore.getThreatGraph(id);

    const session = getDriver().session();
    try {
      // Match the anchor node by id or name, then expand 1-2 hops.
      const result = await session.run(
        `MATCH (n)-[r]-(m)
         WHERE n.id = $id OR n.name = $id OR n.id CONTAINS $id
         RETURN n, r, m LIMIT 200`,
        { id },
      );
      const mapped = mapNeoRecords(result.records);
      if (mapped.nodes.length > 0) return mapped;

      // Fallback: return a sample of the whole graph so the UI isn't empty.
      const all = await session.run('MATCH (n)-[r]-(m) RETURN n, r, m LIMIT 200');
      return mapNeoRecords(all.records);
    } finally {
      await session.close();
    }
  },

  async upsertSampleGraph(payload) {
    if (!isNeo4jConnected()) return memoryGraphStore.upsertSampleGraph(payload);

    const {
      jobId, fileName, fileType, iocs = [], ttps = [], actor,
      iocReputation = {}, attribution = null,
    } = payload;
    const sampleId = `sample:job:${jobId}`;
    const session = getDriver().session();
    try {
      await session.run(
        `MERGE (s:MalwareSample {id: $sampleId})
         SET s.name = $fileName, s.file_type = $fileType, s.job_id = $jobId`,
        { sampleId, fileName, fileType, jobId },
      );
      if (actor) {
        // Stamp the campaign edge with OSINT attribution confidence/source when present.
        await session.run(
          `MERGE (a:ThreatActor {name: $actor})
           WITH a MATCH (s:MalwareSample {id: $sampleId})
           MERGE (s)-[rel:BELONGS_TO_CAMPAIGN]->(a)
           SET rel.confidence = $confidence, rel.source = $source`,
          {
            actor,
            sampleId,
            confidence: attribution?.confidence ?? null,
            source: attribution?.source || 'heuristic',
          },
        );
      }
      for (const ttp of ttps) {
        await session.run(
          `MERGE (t:TTP {id: $ttpId}) SET t.name = $ttp
           WITH t MATCH (s:MalwareSample {id: $sampleId})
           MERGE (s)-[:USES_TTP]->(t)`,
          { ttpId: `ttp:${ttp}`, ttp, sampleId },
        );
      }
      for (const raw of iocs) {
        const ip = refang(raw);
        if (!isIpv4(ip)) continue;
        // Reputation keyed by the refanged indicator (from the worker's OSINT).
        const rep = iocReputation[ip]?.abuseipdb || {};
        await session.run(
          `MERGE (ip:IP_Address {id: $ipId})
             SET ip.name = $ip,
                 ip.abuse_confidence = coalesce($abuse, ip.abuse_confidence),
                 ip.country = coalesce($country, ip.country),
                 ip.isp = coalesce($isp, ip.isp)
           WITH ip MATCH (s:MalwareSample {id: $sampleId})
           MERGE (s)-[:COMMUNICATES_WITH]->(ip)`,
          {
            ipId: `ip:${ip}`,
            ip,
            abuse: rep.abuse_confidence ?? null,
            country: rep.country ?? null,
            isp: rep.isp ?? null,
            sampleId,
          },
        );
      }
      return { sampleId };
    } finally {
      await session.close();
    }
  },
};
