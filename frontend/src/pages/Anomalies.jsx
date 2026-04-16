import { useState, useEffect } from 'react';
import { getAnomalies } from '../services/api';
import { SectionHeading, TogglePills } from '../components/Primitives';
import {
    AlertTriangle,
    TrendingUp,
    Zap,
    Eye,
    Filter,
    Search,
    ChevronLeft,
    ChevronRight,
} from 'lucide-react';
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement } from 'chart.js';
import { Bar, Doughnut } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement);

/* Chart palette: distinct from background #222831 / #393E46 - no grays */
const chartColors = ['#00ADB5', '#3B82F6', '#22C55E', '#F59E0B', '#EF4444', '#A855F7', '#EC4899'];

export default function Anomalies() {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [monitorView, setMonitorView] = useState(''); // '' = combined, 'passive', 'active'
    const [filters, setFilters] = useState({
        classification: '',
        risk_level: '',
        src_ip: '',
        protocol: '',
    });
    const [page, setPage] = useState(1);

    const fetchAnomalies = async () => {
        setLoading(true);
        setError(null);
        try {
            const params = { page, per_page: 20 };
            if (filters.classification?.trim()) params.classification = filters.classification.trim();
            if (filters.risk_level?.trim()) params.risk_level = filters.risk_level.trim();
            if (filters.src_ip?.trim()) params.src_ip = filters.src_ip.trim();
            if (filters.protocol?.trim()) params.protocol = filters.protocol.trim();
            if (monitorView) params.monitor_type = monitorView;
            const { data: d } = await getAnomalies(params);
            setData(d);
        } catch (err) {
            console.error('Failed to fetch anomalies:', err);
            setError(err.response?.data?.detail || err.message || 'Failed to load anomaly data.');
            setData(null);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchAnomalies();
    }, [page, filters, monitorView]);

    if (loading) {
        return (
            <div className="flex items-center justify-center h-96">
                <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
            </div>
        );
    }

    if (!data && !loading) {
        return (
            <div className="flex flex-col items-center justify-center h-96">
                <AlertTriangle size={48} className="text-danger mb-4" />
                <p className="text-text-muted mb-4">{error || 'Failed to load anomaly data. Start the backend or retry.'}</p>
                <button
                    onClick={fetchAnomalies}
                    className="px-4 py-2.5 rounded-[10px] border border-primary text-primary text-body font-medium hover:bg-primary/10 transition-colors"
                >
                    Retry
                </button>
            </div>
        );
    }

    if (!data) return null;

    return (
        <div className="space-y-8">
            {/* Header + Monitor Toggle */}
            <div className="flex items-center justify-between gap-4 flex-wrap">
                <SectionHeading
                    title="Anomaly Detection"
                    subtitle={`${data.total_anomalies} threats${monitorView === 'active' ? ' (active monitoring)' : monitorView === 'passive' ? ' (passive / uploads)' : ' (combined)'}`}
                />
                <div className="flex items-center gap-2">
                    <span className="text-small font-medium text-text-muted uppercase tracking-wider">View</span>
                    <TogglePills
                        value={monitorView}
                        onChange={(value) => { setMonitorView(value); setPage(1); }}
                        options={[
                            { value: '', label: 'Combined' },
                            { value: 'active', label: 'Active' },
                            { value: 'passive', label: 'Passive' },
                        ]}
                    />
                </div>
            </div>

            {/* KPIs */}
            <h2 className="section-header">Threat Summary</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="glass-card p-6 border-danger/20 animate-slide-up">
                    <div className="flex items-center gap-3">
                        <div className="p-2 rounded-xl bg-danger/10">
                            <AlertTriangle size={18} className="text-danger" />
                        </div>
                        <div>
                            <p className="text-small text-text-muted">Total Anomalies</p>
                            <p className="text-2xl font-bold text-text-primary">{data.total_anomalies}</p>
                        </div>
                    </div>
                </div>
                <div className="glass-card p-6 border-warning/20 animate-slide-up">
                    <div className="flex items-center gap-3">
                        <div className="p-2 rounded-xl bg-warning/10">
                            <Zap size={18} className="text-warning" />
                        </div>
                        <div>
                            <p className="text-small text-text-muted">High Severity (≥0.8)</p>
                            <p className="text-2xl font-bold text-text-primary">
                                {(data.score_distribution['0.9-1.0'] || 0) + (data.score_distribution['0.8-0.9'] || 0)}
                            </p>
                        </div>
                    </div>
                </div>
                <div className="glass-card p-6 border-[#A855F7]/20 animate-slide-up">
                    <div className="flex items-center gap-3">
                        <div className="p-2 rounded-xl bg-[#A855F7]/10">
                            <TrendingUp size={18} className="text-[#A855F7]" />
                        </div>
                        <div>
                            <p className="text-small text-text-muted">Attack Types</p>
                            <p className="text-2xl font-bold text-text-primary">
                                {Object.keys(data.attack_breakdown || {}).length}
                            </p>
                        </div>
                    </div>
                </div>
            </div>

            {/* Charts */}
            <h2 className="section-header">
                Score & Attack Breakdown
                <span className="ml-2 text-small font-normal text-text-muted">
                    {!monitorView && '(combined)'}
                    {monitorView === 'active' && '(active)'}
                    {monitorView === 'passive' && '(passive)'}
                </span>
            </h2>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* Score Distribution */}
                <div className="glass-card p-6">
                    <h3 className="text-h2 font-semibold text-text-primary mb-4 flex items-center gap-2">
                        <TrendingUp size={14} className="text-primary" />
                        Anomaly Score Distribution
                    </h3>
                    <div className="h-64">
                        <Bar
                            data={{
                                labels: Object.keys(data.score_distribution),
                                datasets: [{
                                    label: 'Count',
                                    data: Object.values(data.score_distribution),
                                    backgroundColor: chartColors.map(c => c + '99'),
                                    borderColor: chartColors,
                                    borderWidth: 1,
                                    borderRadius: 6,
                                }],
                            }}
                            options={{
                                responsive: true,
                                maintainAspectRatio: false,
                                scales: {
                                    x: { grid: { color: 'rgba(255,255,255,0.06)' }, ticks: { color: '#B0B5BA', font: { size: 13 } } },
                                    y: { grid: { color: 'rgba(255,255,255,0.06)' }, ticks: { color: '#B0B5BA', font: { size: 13 } } },
                                },
                                plugins: { legend: { display: false } },
                            }}
                        />
                    </div>
                </div>

                {/* Attack Breakdown */}
                <div className="glass-card p-6">
                    <h3 className="text-h2 font-semibold text-text-primary mb-4 flex items-center gap-2">
                        <Zap size={14} className="text-danger" />
                        Attack Type Breakdown
                    </h3>
                    <div className="h-64 flex items-center justify-center">
                        <Doughnut
                            data={{
                                labels: Object.keys(data.attack_breakdown || {}),
                                datasets: [{
                                    data: Object.values(data.attack_breakdown || {}),
                                    backgroundColor: chartColors,
                                    borderWidth: 0,
                                    spacing: 2,
                                    borderRadius: 4,
                                }],
                            }}
                            options={{
                                responsive: true,
                                maintainAspectRatio: false,
                                cutout: '60%',
                                plugins: {
                                    legend: {
                                        position: 'right',
                                        labels: { color: '#B0B5BA', font: { size: 13 }, padding: 8, usePointStyle: true, pointStyleWidth: 8 },
                                    },
                                },
                            }}
                        />
                    </div>
                </div>
            </div>

            {/* Top Anomalies Table */}
            <h2 className="section-header">Top Threats</h2>
            <div className="glass-card p-6">
                <h3 className="text-h2 font-semibold text-text-primary mb-4 flex items-center gap-2">
                    <Eye size={14} className="text-danger" />
                    Top Threats (Highest Score)
                </h3>
                <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-4">
                    <div className="relative">
                        <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
                        <input
                            type="text"
                            placeholder="Source IP..."
                            value={filters.src_ip}
                            onChange={(e) => { setFilters((p) => ({ ...p, src_ip: e.target.value })); setPage(1); }}
                            className="w-full pl-9 pr-3 py-2 rounded-xl bg-background border border-white/10 text-body text-text-primary placeholder-text-muted focus:outline-none focus:border-primary/50 transition-colors"
                        />
                    </div>
                    <select
                        value={filters.classification}
                        onChange={(e) => { setFilters((p) => ({ ...p, classification: e.target.value })); setPage(1); }}
                        className="px-3 py-2 rounded-xl bg-background border border-white/10 text-body text-text-primary focus:outline-none focus:border-primary/50 appearance-none cursor-pointer"
                    >
                        <option value="">All Threat Types</option>
                        {Object.keys(data.attack_breakdown || {}).map((c) => (
                            <option key={c} value={c}>{c}</option>
                        ))}
                    </select>
                    <select
                        value={filters.risk_level}
                        onChange={(e) => { setFilters((p) => ({ ...p, risk_level: e.target.value })); setPage(1); }}
                        className="px-3 py-2 rounded-xl bg-background border border-white/10 text-body text-text-primary focus:outline-none focus:border-primary/50 appearance-none cursor-pointer"
                    >
                        <option value="">All Risk Levels</option>
                        {['Critical', 'High', 'Medium', 'Low'].map((r) => (
                            <option key={r} value={r}>{r}</option>
                        ))}
                    </select>
                    <input
                        type="text"
                        placeholder="Protocol..."
                        value={filters.protocol}
                        onChange={(e) => { setFilters((p) => ({ ...p, protocol: e.target.value })); setPage(1); }}
                        className="px-3 py-2 rounded-xl bg-background border border-white/10 text-body text-text-primary placeholder-text-muted focus:outline-none focus:border-primary/50"
                    />
                    <button
                        onClick={() => { setFilters({ classification: '', risk_level: '', src_ip: '', protocol: '' }); setPage(1); }}
                        className="px-4 py-2 rounded-[10px] border border-white/10 text-body text-text-muted hover:text-text-primary hover:border-primary/50 transition-colors flex items-center justify-center gap-2"
                    >
                        <Filter size={12} />
                        Clear
                    </button>
                </div>
                <div className="overflow-x-auto">
                    <table className="w-full data-table">
                        <thead>
                            <tr>
                                <th>Source</th>
                                <th>#</th>
                                <th>Source IP</th>
                                <th>Dest IP</th>
                                <th>Protocol</th>
                                <th>Classification</th>
                                <th>Threat Type</th>
                                <th>CVE</th>
                                <th>Anomaly Score</th>
                                <th>Confidence</th>
                                <th>Risk Level</th>
                            </tr>
                        </thead>
                        <tbody>
                            {(data.top_anomalies || []).length === 0 ? (
                                <tr>
                                    <td colSpan={11} className="text-center py-8 text-text-muted text-body">
                                        No threats in current data for selected filters.
                                    </td>
                                </tr>
                            ) : (data.top_anomalies || []).map((a, i) => (
                                <tr key={a.id}>
                                    <td>
                                        <span className={`px-2 py-0.5 rounded-md text-small font-medium ${(a.monitor_type || 'passive') === 'active' ? 'bg-primary/20 text-primary border border-primary/30' : 'bg-surface text-text-muted border border-white/10'}`}>
                                            {(a.monitor_type || 'passive') === 'active' ? 'Active' : 'Passive'}
                                        </span>
                                    </td>
                                    <td className="font-mono text-primary text-small">#{i + 1}</td>
                                    <td className="cell-ip">{a.src_ip}</td>
                                    <td className="cell-ip">{a.dst_ip}</td>
                                    <td>
                                        <span className="px-2 py-0.5 rounded-md bg-surface text-small font-mono text-primary border border-white/10">
                                            {a.protocol}
                                        </span>
                                    </td>
                                    <td className="text-small font-semibold text-danger" title={a.classification_reason || ''}>{a.classification}</td>
                                    <td className="text-small text-amber-200">{a.threat_type || '—'}</td>
                                    <td className="text-small font-mono text-primary">{a.cve_refs ? String(a.cve_refs).replace(/,/g, ', ') : '—'}</td>
                                    <td>
                                        <div className="flex items-center gap-2">
                                            <div className="h-2 w-16 rounded-full bg-background overflow-hidden">
                                                <div
                                                    className={`h-full rounded-full ${a.anomaly_score >= 0.9 ? 'bg-danger' : a.anomaly_score >= 0.8 ? 'bg-warning' : 'bg-warning/70'}`}
                                                    style={{ width: `${a.anomaly_score * 100}%` }}
                                                />
                                            </div>
                                            <span className="text-small font-mono text-danger">{a.anomaly_score.toFixed(3)}</span>
                                        </div>
                                    </td>
                                    <td className="text-small text-text-muted">{(((a.confidence ?? 0) * 100)).toFixed(0)}%</td>
                                    <td>
                                        <span className={`px-2 py-0.5 rounded-md text-small font-medium badge-${(a.risk_level || 'low').toLowerCase()}`} title={a.classification_reason || ''}>
                                            {a.risk_level}
                                        </span>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
                {(data.total_pages || 1) > 1 && (
                    <div className="flex items-center justify-between px-1 pt-4">
                        <p className="text-small text-text-muted">
                            Page {data.page || 1} / {data.total_pages || 1}
                        </p>
                        <div className="flex items-center gap-2">
                            <button
                                onClick={() => setPage(Math.max(1, (data.page || 1) - 1))}
                                disabled={(data.page || 1) <= 1}
                                className="p-2 rounded-[10px] border border-white/10 text-text-muted hover:text-text-primary hover:border-primary/50 disabled:opacity-30 transition-colors"
                            >
                                <ChevronLeft size={14} />
                            </button>
                            <button
                                onClick={() => setPage(Math.min(data.total_pages || 1, (data.page || 1) + 1))}
                                disabled={(data.page || 1) >= (data.total_pages || 1)}
                                className="p-2 rounded-[10px] border border-white/10 text-text-muted hover:text-text-primary hover:border-primary/50 disabled:opacity-30 transition-colors"
                            >
                                <ChevronRight size={14} />
                            </button>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}
