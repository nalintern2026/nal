import { useEffect, useState } from 'react';
import { getAlerts, updateAlert } from '../services/api';
import { SectionHeading } from '../components/Primitives';

export default function Alerts() {
    const [alerts, setAlerts] = useState([]);
    const [status, setStatus] = useState('');
    const [risk, setRisk] = useState('');

    const load = async () => {
        const res = await getAlerts({ status: status || undefined, risk_level: risk || undefined, limit: 200 });
        setAlerts(res.data.alerts || []);
    };

    useEffect(() => { load(); }, [status, risk]);

    return (
        <div className="space-y-4">
            <SectionHeading title="Alerts" subtitle="Actionable security alerts from detections" />
            <div className="flex gap-2">
                <select value={status} onChange={(e) => setStatus(e.target.value)} className="bg-surface border border-white/10 rounded px-2 py-1">
                    <option value="">All Status</option><option>OPEN</option><option>ACKNOWLEDGED</option><option>RESOLVED</option>
                </select>
                <select value={risk} onChange={(e) => setRisk(e.target.value)} className="bg-surface border border-white/10 rounded px-2 py-1">
                    <option value="">All Risk</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option>
                </select>
            </div>
            <div className="overflow-x-auto">
                <table className="w-full data-table">
                    <thead><tr><th>ID</th><th>Priority</th><th>Risk</th><th>Classification</th><th>Status</th><th>Occurrences</th><th>Last Seen</th><th>Correlation</th><th>Reason</th><th>Action</th></tr></thead>
                    <tbody>
                        {alerts.map((a) => (
                            <tr key={a.id}>
                                <td>{a.id}</td><td>{a.priority}</td><td>{a.risk_level}</td><td>{a.classification}</td><td>{a.status}</td><td>{a.occurrence_count || 1}</td><td>{a.last_seen || a.created_at}</td><td>{a.correlation_id || '—'}</td><td>{a.reason}</td>
                                <td>
                                    {a.status !== 'RESOLVED' && (
                                        <button className="px-3 py-1 border border-primary text-primary rounded" onClick={async () => { await updateAlert(a.id, 'RESOLVED'); await load(); }}>
                                            Resolve
                                        </button>
                                    )}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
