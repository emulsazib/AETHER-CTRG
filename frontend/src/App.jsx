// App shell: SOC top status bar + icon sidebar + routed views. Live system
// health (gateway/mongo/neo4j/worker) is polled in the header so analysts can
// see the platform state at a glance.
import { useEffect, useState } from 'react';
import { NavLink, Navigate, Route, Routes } from 'react-router-dom';
import Dashboard from './components/Dashboard/Dashboard.jsx';
import Ingestion from './components/Ingestion/Ingestion.jsx';
import AnalysisResults from './components/AnalysisResults/AnalysisResults.jsx';
import ThreatGraph from './components/ThreatGraph/ThreatGraph.jsx';
import { useHealth } from './hooks/useHealth.js';
import {
  IconShield, IconGrid, IconUpload, IconScan, IconGraph, IconClock,
} from './components/common/Icons.jsx';

function StatusPill({ label, state }) {
  const cls = state === 'up' ? 'up' : state === 'warn' ? 'warnp' : 'down';
  return <span className={`pill ${cls}`}><span className="dot" />{label}</span>;
}

function TopBar() {
  const { health, online } = useHealth();
  const [now, setNow] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  const workerUp = health?.ml_worker?.status === 'ok';
  const mongoUp = health?.mongo === 'connected';
  const neoUp = health?.neo4j === 'connected';

  return (
    <header className="topbar">
      <div className="brand">
        <span className="logo"><IconShield size={22} /></span>
        AE<span>THER</span>
      </div>
      <div className="tagline">AI THREAT ANALYSIS &amp; ATTRIBUTION</div>
      <div className="spring" />
      <div className="status-strip">
        <StatusPill label="GATEWAY" state={online ? 'up' : 'down'} />
        <StatusPill label="AI-WORKER" state={workerUp ? 'up' : online ? 'warn' : 'down'} />
        <StatusPill label="MONGO" state={mongoUp ? 'up' : online ? 'warn' : 'down'} />
        <StatusPill label="NEO4J" state={neoUp ? 'up' : online ? 'warn' : 'down'} />
        <span className="clock"><IconClock size={13} />{now.toLocaleTimeString([], { hour12: false })} UTC{(() => { const o = -now.getTimezoneOffset() / 60; return (o >= 0 ? '+' : '') + o; })()}</span>
      </div>
    </header>
  );
}

const NAV = [
  { to: '/', end: true, label: 'Overview', Icon: IconGrid, section: 'Operations' },
  { to: '/ingest', label: 'Ingestion', Icon: IconUpload },
  { to: '/analysis', label: 'Analysis & XAI', Icon: IconScan, section: 'Intelligence' },
  { to: '/graph', label: 'Threat Graph', Icon: IconGraph },
];

export default function App() {
  return (
    <div className="app-shell">
      <TopBar />

      <aside className="sidebar">
        {NAV.map(({ to, end, label, Icon, section }) => (
          <span key={to} style={{ display: 'contents' }}>
            {section && <div className="nav-section">{section}</div>}
            <NavLink to={to} end={end} className="nav-link">
              <span className="nico"><Icon size={18} /></span>{label}
            </NavLink>
          </span>
        ))}
        <div className="sidebar-foot">
          AETHER v1.0 · SOC Console<br />
          <span className="muted-2">Research / education use only</span>
        </div>
      </aside>

      <main className="main">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/ingest" element={<Ingestion />} />
          <Route path="/analysis" element={<AnalysisResults />} />
          <Route path="/analysis/:jobId" element={<AnalysisResults />} />
          <Route path="/graph" element={<ThreatGraph />} />
          <Route path="/graph/:anchorId" element={<ThreatGraph />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}
