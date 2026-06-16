// App shell: sidebar nav + routed views. Each view is a self-contained feature
// component that pulls data through hooks (never fetches inline).
import { NavLink, Navigate, Route, Routes } from 'react-router-dom';
import Dashboard from './components/Dashboard/Dashboard.jsx';
import Ingestion from './components/Ingestion/Ingestion.jsx';
import AnalysisResults from './components/AnalysisResults/AnalysisResults.jsx';
import ThreatGraph from './components/ThreatGraph/ThreatGraph.jsx';

export default function App() {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">AE<span>THER</span></div>
        <NavLink to="/" end className="nav-link">Dashboard</NavLink>
        <NavLink to="/ingest" className="nav-link">Data Ingestion</NavLink>
        <NavLink to="/analysis" className="nav-link">Analysis &amp; XAI</NavLink>
        <NavLink to="/graph" className="nav-link">Threat Graph</NavLink>
      </aside>

      <main className="main">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/ingest" element={<Ingestion />} />
          {/* Optional :jobId deep-link, e.g. /analysis/<job_id> */}
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
