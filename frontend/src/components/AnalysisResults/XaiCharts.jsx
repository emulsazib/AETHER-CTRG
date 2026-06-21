// Renders the XAI payload as charts:
//   - SHAP: diverging bar chart of per-feature contributions (force-plot proxy)
//   - LIME: horizontal bar chart of local feature importances
// Pure presentational component — receives the payload, fetches nothing.
import {
  Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts';

const TIP = { background: '#0e141f', border: '1px solid #2c3d57', borderRadius: 8 };

export default function XaiCharts({ xai }) {
  if (!xai) return <p className="muted">No XAI payload yet.</p>;

  const shap = (xai.shap?.features || []).map((f) => ({ feature: f.feature, contribution: f.contribution }));
  const lime = (xai.lime?.features || []).map((f) => ({ feature: f.feature, importance: f.importance }));

  return (
    <div className="grid cols-2">
      <div className="card">
        <div className="card-head"><h3>SHAP Feature Contributions</h3>
          <span className="right muted-2" style={{ fontSize: 11 }}>base {xai.shap?.base_value}</span></div>
        <ResponsiveContainer width="100%" height={280}>
          <BarChart data={shap} layout="vertical" margin={{ left: 30 }}>
            <XAxis type="number" stroke="#5c6e8a" fontSize={11} tickLine={false} axisLine={false} />
            <YAxis type="category" dataKey="feature" width={150} stroke="#8094b0" fontSize={11} tickLine={false} axisLine={false} />
            <Tooltip cursor={{ fill: 'rgba(76,201,240,.06)' }} contentStyle={TIP} />
            <Bar dataKey="contribution" radius={[0, 4, 4, 0]}>
              {shap.map((d) => <Cell key={d.feature} fill={d.contribution >= 0 ? '#ff3b5c' : '#2ecc71'} />)}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
        <p className="muted-2" style={{ fontSize: 11 }}>Red pushes toward <em style={{ color: 'var(--critical)' }}>malicious</em>, green toward <em style={{ color: 'var(--benign)' }}>benign</em>.</p>
      </div>

      <div className="card">
        <div className="card-head"><h3>LIME Local Importance</h3></div>
        <ResponsiveContainer width="100%" height={280}>
          <BarChart data={lime} layout="vertical" margin={{ left: 30 }}>
            <XAxis type="number" stroke="#5c6e8a" fontSize={11} tickLine={false} axisLine={false} />
            <YAxis type="category" dataKey="feature" width={150} stroke="#8094b0" fontSize={11} tickLine={false} axisLine={false} />
            <Tooltip cursor={{ fill: 'rgba(76,201,240,.06)' }} contentStyle={TIP} />
            <Bar dataKey="importance" fill="#4cc9f0" radius={[0, 4, 4, 0]} />
          </BarChart>
        </ResponsiveContainer>
        <p className="muted-2" style={{ fontSize: 11 }}>Top locally-influential features for this prediction.</p>
      </div>
    </div>
  );
}
