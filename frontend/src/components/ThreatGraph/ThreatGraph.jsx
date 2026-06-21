// Threat Actor Graph Explorer — renders the Neo4j correlation graph with
// react-force-graph-2d. Node color encodes type (sample/actor/ttp/ip/tactic).
// Data fetching lives in useThreatGraph(); this component only renders.
import { useState } from 'react';
import { useParams } from 'react-router-dom';
import ForceGraph2D from 'react-force-graph-2d';
import { useThreatGraph } from '../../hooks/useThreatGraph.js';
import { IconGraph, IconCrosshair } from '../common/Icons.jsx';

const DEFAULT_ANCHOR = 'all';

const COLORS = {
  ThreatActor: '#ff3b5c',
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

  const graphData = {
    nodes: graph.nodes.map((n) => ({ ...n })),
    links: graph.edges.map((e) => ({ source: e.source, target: e.target, type: e.type })),
  };

  const counts = graph.nodes.reduce((m, n) => { m[n.label] = (m[n.label] || 0) + 1; return m; }, {});

  return (
    <div>
      <div className="page-head">
        <div>
          <h1 className="page-title"><span className="accenticon"><IconGraph size={22} /></span>Threat Correlation Graph</h1>
          <p className="page-sub">STIX2-style relationships across samples, actors, TTPs &amp; infrastructure</p>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="row">
          <span className="ci" style={{ color: 'var(--accent)' }}><IconCrosshair size={18} /></span>
          <input
            className="input mono"
            style={{ flex: 1 }}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && setActive(query)}
            placeholder="Anchor node (e.g. APT29, sample:f00dcafe, all)"
          />
          <button className="btn" onClick={() => setActive(query)}><IconGraph size={16} />Explore</button>
        </div>
        <div className="row" style={{ marginTop: 14 }}>
          {Object.entries(COLORS).map(([label, color]) => (
            <span key={label} className="chip-legend">
              <span className="sw" style={{ background: color }} />
              {label.replace('_', ' ')} {counts[label] ? <span className="muted-2">· {counts[label]}</span> : null}
            </span>
          ))}
        </div>
      </div>

      {loading && <p className="muted"><span className="scanline">▮</span> Loading graph…</p>}
      {error && <div className="banner crit">{error}</div>}

      <div className="card glow" style={{ height: 580, padding: 0, overflow: 'hidden' }}>
        {graphData.nodes.length === 0 ? (
          <div className="empty" style={{ paddingTop: 220 }}><span className="eico"><IconGraph size={34} /></span><div>No nodes for this anchor.</div></div>
        ) : (
          <ForceGraph2D
            graphData={graphData}
            backgroundColor="#070b12"
            nodeRelSize={6}
            nodeColor={(n) => COLORS[n.label] || '#8094b0'}
            nodeLabel={(n) => `${n.label}: ${n.name}`}
            linkColor={() => '#243349'}
            linkWidth={1}
            linkDirectionalArrowLength={4}
            linkDirectionalArrowRelPos={1}
            linkDirectionalParticles={1}
            linkDirectionalParticleWidth={1.6}
            linkDirectionalParticleColor={() => '#4cc9f0'}
            linkLabel={(l) => l.type}
            nodeCanvasObjectMode={() => 'after'}
            nodeCanvasObject={(node, ctx, globalScale) => {
              const label = node.name;
              const fontSize = 11 / globalScale;
              ctx.font = `${fontSize}px Inter, sans-serif`;
              ctx.fillStyle = '#cdd9ea';
              ctx.textAlign = 'center';
              ctx.fillText(label, node.x, node.y + 11);
            }}
          />
        )}
      </div>
    </div>
  );
}
