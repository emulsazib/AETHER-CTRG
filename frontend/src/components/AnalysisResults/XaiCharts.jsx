// Renders the XAI JSON payload as charts:
//   - SHAP: diverging bar chart of per-feature contributions (force-plot proxy)
//   - LIME: horizontal bar chart of local feature importances
// Pure presentational component — receives the payload, fetches nothing.
import {
  Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts';

export default function XaiCharts({ xai }) {
  if (!xai) return <p className="muted">No XAI payload yet.</p>;

  const shap = (xai.shap?.features || []).map((f) => ({
    feature: f.feature,
    contribution: f.contribution,
  }));
  const lime = (xai.lime?.features || []).map((f) => ({
    feature: f.feature,
    importance: f.importance,
  }));

  return (
    <div className="grid cols-2">
      <div className="card">
        <h3>SHAP Feature Contributions</h3>
        <p className="muted" style={{ marginTop: -6 }}>
          prediction: <strong>{xai.prediction}</strong> ({xai.predicted_label}) · base{' '}
          {xai.shap?.base_value}
        </p>
        <ResponsiveContainer width="100%" height={260}>
          <BarChart data={shap} layout="vertical" margin={{ left: 30 }}>
            <XAxis type="number" stroke="#8da2bd" fontSize={11} />
            <YAxis type="category" dataKey="feature" width={140} stroke="#8da2bd" fontSize={11} />
            <Tooltip cursor={{ fill: '#1b2433' }} contentStyle={{ background: '#131a26', border: '1px solid #233047' }} />
            <Bar dataKey="contribution">
              {shap.map((d) => (
                <Cell key={d.feature} fill={d.contribution >= 0 ? '#ff5d6c' : '#2ecc71'} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
        <p className="muted" style={{ fontSize: 11 }}>
          Red pushes toward <em>malicious</em>, green toward <em>benign</em>.
        </p>
      </div>

      <div className="card">
        <h3>LIME Local Importance</h3>
        <ResponsiveContainer width="100%" height={260}>
          <BarChart data={lime} layout="vertical" margin={{ left: 30 }}>
            <XAxis type="number" stroke="#8da2bd" fontSize={11} />
            <YAxis type="category" dataKey="feature" width={140} stroke="#8da2bd" fontSize={11} />
            <Tooltip cursor={{ fill: '#1b2433' }} contentStyle={{ background: '#131a26', border: '1px solid #233047' }} />
            <Bar dataKey="importance" fill="#4cc9f0" />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
