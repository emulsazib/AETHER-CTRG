// Threat Actor Graph Explorer — renders the Neo4j correlation graph with
// react-force-graph-2d. Node color encodes type (sample/actor/ttp/ip/tactic).
// Data fetching lives in useThreatGraph(); this component only renders.
import { useState } from 'react';
import { useParams } from 'react-router-dom';
import ForceGraph2D from 'react-force-graph-2d';
import { useThreatGraph } from '../../hooks/useThreatGraph.js';

// 'all' is a sentinel: backend returns the full graph when no node matches it.
const DEFAULT_ANCHOR = 'all';

const COLORS = {
  ThreatActor: '#ff5d6c',
  MalwareSample: '#4cc9f0',
  TTP: '#7b61ff',
  IP_Address: '#ffb703',
  MITRE_Tactic: '#2ecc71',
};

export default function ThreatGraph() {
  const { anchorId } = useParams();
  const [query, setQuery] = useState(anchorId || DEFAULT_ANCHOR);
  const [active, setActive] = useState(anchorId || DEFAULT_ANCHOR);
  const { graph, loading, error } = useThreatGraph(active);

  // react-force-graph wants { nodes, links } with link.source/target ids.
  const graphData = {
    nodes: graph.nodes.map((n) => ({ ...n })),
    links: graph.edges.map((e) => ({ source: e.source, target: e.target, type: e.type })),
  };

  return (
    <div>
      <h1 className="page-title">Threat Actor Graph Explorer</h1>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="row">
          <input
            className="mono"
            style={{ flex: 1, padding: 10, background: 'var(--panel-2)', border: '1px solid var(--border)', borderRadius: 8, color: 'var(--text)' }}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Anchor node id/name (e.g. APT29, sample:f00dcafe, all)"
          />
          <button className="btn" onClick={() => setActive(query)}>Explore</button>
        </div>
        <div className="row" style={{ marginTop: 10 }}>
          {Object.entries(COLORS).map(([label, color]) => (
            <span key={label} className="muted" style={{ fontSize: 12 }}>
              <span style={{ display: 'inline-block', width: 10, height: 10, background: color, borderRadius: 3, marginRight: 5 }} />
              {label}
            </span>
          ))}
        </div>
      </div>

      {loading && <p className="muted">Loading graph…</p>}
      {error && <p style={{ color: 'var(--danger)' }}>Error: {error}</p>}

      <div className="card" style={{ height: 560, padding: 0, overflow: 'hidden' }}>
        {graphData.nodes.length === 0 ? (
          <p className="muted" style={{ padding: 20 }}>No nodes for this anchor.</p>
        ) : (
          <ForceGraph2D
            graphData={graphData}
            backgroundColor="#0b0f17"
            nodeRelSize={6}
            nodeColor={(n) => COLORS[n.label] || '#8da2bd'}
            nodeLabel={(n) => `${n.label}: ${n.name}`}
            linkColor={() => '#314257'}
            linkDirectionalArrowLength={4}
            linkDirectionalArrowRelPos={1}
            linkLabel={(l) => l.type}
            nodeCanvasObjectMode={() => 'after'}
            nodeCanvasObject={(node, ctx, globalScale) => {
              const label = node.name;
              const fontSize = 11 / globalScale;
              ctx.font = `${fontSize}px Inter, sans-serif`;
              ctx.fillStyle = '#e6edf6';
              ctx.textAlign = 'center';
              ctx.fillText(label, node.x, node.y + 10);
            }}
          />
        )}
      </div>
    </div>
  );
}
