import { useState, useEffect, useCallback } from 'react';
import { getTrafficFlows, getTrafficTrends } from '../services/api';
import { SectionHeading, TogglePills } from '../components/Primitives';
import {
    Network,
    Search,
    ChevronLeft,
    ChevronRight,
    Filter,
} from 'lucide-react';
import { Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend } from 'chart.js';
import { Line } from 'react-chartjs-2';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend);

const PROTOCOL_MAP = {
    '1': 'ICMP',
    '6': 'TCP',
    '17': 'UDP',
    '47': 'GRE',
    '50': 'ESP',
    '51': 'AH',
    '89': 'OSPF',
    '132': 'SCTP',
};

// Protocol filter – backend matches both name (TCP) and number (6) in DB
const PROTOCOL_FILTER_OPTIONS = [
    { value: '', label: 'All Protocols' },
    { value: 'TCP', label: 'TCP (6)' },
    { value: 'UDP', label: 'UDP (17)' },
    { value: 'ICMP', label: 'ICMP (1)' },
    { value: 'GRE', label: 'GRE (47)' },
    { value: 'ESP', label: 'ESP (50)' },
    { value: 'AH', label: 'AH (51)' },
    { value: 'OSPF', label: 'OSPF (89)' },
    { value: 'SCTP', label: 'SCTP (132)' },
];

// Classification filter – one option per distinct label (backend matches case-insensitive)
const CLASSIFICATION_OPTIONS = [
    { value: '', label: 'All Classifications' },
    { value: 'BENIGN', label: 'Benign (Safe)' },
    { value: 'DDoS', label: 'DDoS' },
    { value: 'Bot', label: 'Bot' },
    { value: 'Anomaly', label: 'Anomaly' },
    { value: 'PortScan', label: 'PortScan' },
    { value: 'Brute Force', label: 'Brute Force' },
    { value: 'BruteForce', label: 'BruteForce' },
    { value: 'Web Attack', label: 'Web Attack' },
    { value: 'Infiltration', label: 'Infiltration' },
    { value: 'Heartbleed', label: 'Heartbleed' },
    { value: 'DoS', label: 'DoS' },
];

export default function TrafficAnalysis() {
    const [flows, setFlows] = useState([]);
    const [total, setTotal] = useState(0);
    const [page, setPage] = useState(1);
    const [totalPages, setTotalPages] = useState(1);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [trendData, setTrendData] = useState([]);
    const [monitorView, setMonitorView] = useState(''); // '' = combined, 'passive', 'active'
    const [filters, setFilters] = useState({
        classification: '',
        risk_level: '',
        src_ip: '',
        protocol: '',
    });

    const fetchFlows = useCallback(async ({ silent = false } = {}) => {
        if (!silent) {
            setLoading(true);
        }
        setError(null);
        try {
            const params = { page, per_page: 15 };
            if (filters.classification?.trim()) params.classification = filters.classification.trim();
            if (filters.risk_level?.trim()) params.risk_level = filters.risk_level.trim();
            if (filters.src_ip?.trim()) params.src_ip = filters.src_ip.trim();
            if (filters.protocol?.trim()) params.protocol = filters.protocol.trim();
            if (monitorView) params.monitor_type = monitorView;

            const [flowsRes, trendsRes] = await Promise.all([
                getTrafficFlows(params),
                getTrafficTrends({ ...params, points: 96 }),
            ]);
            setFlows(flowsRes.data.flows || []);
            setTotal(flowsRes.data.total ?? 0);
            setTotalPages(Math.max(1, flowsRes.data.total_pages ?? 1));
            setTrendData(trendsRes.data.points || []);
        } catch (err) {
            console.error('Failed to fetch flows:', err);
            setError(err.response?.data?.detail || 'Cannot reach backend. Start the API to see traffic data.');
        } finally {
            if (!silent) {
                setLoading(false);
            }
        }
    }, [page, filters, monitorView]);

    useEffect(() => {
        fetchFlows();
    }, [fetchFlows]);

    useEffect(() => {
        const interval = setInterval(() => {
            fetchFlows({ silent: true });
        }, 5000);
        return () => clearInterval(interval);
    }, [fetchFlows]);

    const handleFilterChange = (key, value) => {
        setFilters((prev) => ({ ...prev, [key]: value }));
        setPage(1);
    };

    const clearFilters = () => {
        setFilters({ classification: '', risk_level: '', src_ip: '', protocol: '' });
        setPage(1);
    };

    const hasActiveFilters = filters.classification || filters.risk_level || filters.src_ip || filters.protocol;

    const formatProtocol = (value) => {
        if (value == null) return '—';
        const code = String(value).trim();
        const name = PROTOCOL_MAP[code];
        return name ? `${name} (${code})` : code;
    };

    const trendLabels = trendData.map((p) => {
        const raw = String(p?.hour || '').trim();
        if (!raw) return '';

        // Backend stores UTC timestamps; hour buckets are substr(timestamp,1,16) e.g. "2026-03-18T10:01"
        // Append Z so Date() interprets as UTC, then toLocaleString converts to local
        let normalized = raw.replace(' ', 'T');
        if (!normalized.endsWith('Z')) normalized += ':00Z';
        let dt = new Date(normalized);
        if (Number.isNaN(dt.getTime())) dt = new Date(raw);
        if (Number.isNaN(dt.getTime())) return raw;

        return dt.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    });

    return (
        <div className="space-y-8">
            {/* Header + Monitor Toggle */}
            <div className="flex items-center justify-between gap-4 flex-wrap">
                <SectionHeading
                    title="Traffic Analysis"
                    subtitle={`${total.toLocaleString()} flows${monitorView === 'active' ? ' (active monitoring)' : monitorView === 'passive' ? ' (passive / uploads)' : ' (combined)'}`}
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

            {/* Filters */}
            <h2 className="section-header">Filters</h2>
            <div className="glass-card p-6">
                <div className="flex items-center justify-between gap-2 mb-3">
                    <div className="flex items-center gap-2">
                        <Filter size={14} className="text-primary" />
                        <span className="text-small font-semibold text-text-primary uppercase tracking-wider">Filters</span>
                        {hasActiveFilters && (
                            <span className="text-small px-2 py-0.5 rounded-full bg-primary/15 text-primary">
                                Active
                            </span>
                        )}
                    </div>
                    {hasActiveFilters && (
                        <button
                            onClick={clearFilters}
                            className="text-small text-text-muted hover:text-primary transition-colors"
                        >
                            Clear all
                        </button>
                    )}
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-3">
                    <div className="relative">
                        <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
                        <input
                            type="text"
                            placeholder="Source IP"
                            value={filters.src_ip}
                            onChange={(e) => handleFilterChange('src_ip', e.target.value)}
                            className="w-full pl-9 pr-3 py-2 rounded-xl bg-background border border-white/10 text-body text-text-primary placeholder-text-muted focus:outline-none focus:border-primary/50 transition-colors"
                        />
                    </div>
                    <select
                        value={filters.classification}
                        onChange={(e) => handleFilterChange('classification', e.target.value)}
                        className="px-3 py-2 rounded-xl bg-background border border-white/10 text-body text-text-primary focus:outline-none focus:border-primary/50 appearance-none cursor-pointer"
                    >
                        {CLASSIFICATION_OPTIONS.map((c) => (
                            <option key={c.value || 'all'} value={c.value}>{c.label}</option>
                        ))}
                    </select>
                    <select
                        value={filters.risk_level}
                        onChange={(e) => handleFilterChange('risk_level', e.target.value)}
                        className="px-3 py-2 rounded-xl bg-background border border-white/10 text-body text-text-primary focus:outline-none focus:border-primary/50 appearance-none cursor-pointer"
                    >
                        <option value="">All Risk Levels</option>
                        {['Critical', 'High', 'Medium', 'Low'].map((r) => (
                            <option key={r} value={r}>{r}</option>
                        ))}
                    </select>
                    <select
                        value={filters.protocol}
                        onChange={(e) => handleFilterChange('protocol', e.target.value)}
                        className="px-3 py-2 rounded-xl bg-background border border-white/10 text-body text-text-primary focus:outline-none focus:border-primary/50 appearance-none cursor-pointer"
                    >
                        {PROTOCOL_FILTER_OPTIONS.map((p) => (
                            <option key={p.value || 'all'} value={p.value}>{p.label}</option>
                        ))}
                    </select>
                    <button
                        onClick={clearFilters}
                        className="px-4 py-2 rounded-[10px] border border-white/10 text-body text-text-muted hover:text-text-primary hover:border-primary/50 transition-colors"
                    >
                        Clear
                    </button>
                </div>
            </div>

            {/* Flow Trend Charts */}
            <h2 className="section-header">
                Flow Trends
                <span className="ml-2 text-small font-normal text-text-muted">
                    {!monitorView && '(combined)'}
                    {monitorView === 'active' && '(active monitoring)'}
                    {monitorView === 'passive' && '(passive / uploads)'}
                </span>
            </h2>
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                <div className="glass-card p-6">
                    <h3 className="text-h2 font-semibold text-text-primary mb-3">Flow Volume & Threat Mix (Time Buckets)</h3>
                    <div className="h-72">
                        <Line
                            data={{
                                labels: trendLabels,
                                datasets: [
                                    {
                                        label: 'Total Flows',
                                        data: trendData.map((p) => p.total_flows || 0),
                                        borderColor: '#00ADB5',
                                        backgroundColor: 'rgba(0, 173, 181, 0.12)',
                                        pointRadius: trendData.length <= 1 ? 3 : 1,
                                        borderWidth: 2,
                                        tension: 0.25,
                                    },
                                    {
                                        label: 'Threat Flows',
                                        data: trendData.map((p) => p.threat_flows || 0),
                                        borderColor: '#EF4444',
                                        backgroundColor: 'rgba(239, 68, 68, 0.12)',
                                        pointRadius: trendData.length <= 1 ? 3 : 1,
                                        borderWidth: 2,
                                        tension: 0.25,
                                    },
                                    {
                                        label: 'Benign Flows',
                                        data: trendData.map((p) => p.benign_flows || 0),
                                        borderColor: '#22C55E',
                                        backgroundColor: 'rgba(34, 197, 94, 0.12)',
                                        pointRadius: trendData.length <= 1 ? 3 : 1,
                                        borderWidth: 2,
                                        tension: 0.25,
                                    },
                                ],
                            }}
                            options={{
                                responsive: true,
                                maintainAspectRatio: false,
                                interaction: { mode: 'index', intersect: false },
                                scales: {
                                    x: { grid: { color: 'rgba(255,255,255,0.06)' }, ticks: { color: '#B0B5BA', maxTicksLimit: 8, font: { size: 13 } } },
                                    y: { grid: { color: 'rgba(255,255,255,0.06)' }, ticks: { color: '#B0B5BA', font: { size: 13 } } },
                                },
                                plugins: {
                                    legend: { labels: { color: '#B0B5BA', font: { size: 13 }, usePointStyle: true, pointStyleWidth: 8 } },
                                },
                            }}
                        />
                    </div>
                </div>

                <div className="glass-card p-6">
                    <h3 className="text-h2 font-semibold text-text-primary mb-3">Average Risk, Confidence & Threat Rate</h3>
                    <div className="h-72">
                        <Line
                            data={{
                                labels: trendLabels,
                                datasets: [
                                    {
                                        label: 'Avg Risk %',
                                        data: trendData.map((p) => Math.round((p.avg_risk_score || 0) * 100)),
                                        borderColor: '#F59E0B',
                                        backgroundColor: 'rgba(245, 158, 11, 0.12)',
                                        pointRadius: trendData.length <= 1 ? 3 : 1,
                                        borderWidth: 2,
                                        tension: 0.25,
                                    },
                                    {
                                        label: 'Avg Confidence %',
                                        data: trendData.map((p) => Math.round((p.avg_confidence || 0) * 100)),
                                        borderColor: '#A855F7',
                                        backgroundColor: 'rgba(168, 85, 247, 0.12)',
                                        pointRadius: trendData.length <= 1 ? 3 : 1,
                                        borderWidth: 2,
                                        tension: 0.25,
                                    },
                                    {
                                        label: 'Threat Rate %',
                                        data: trendData.map((p) => p.threat_rate || 0),
                                        borderColor: '#EF4444',
                                        backgroundColor: 'rgba(239, 68, 68, 0.12)',
                                        pointRadius: trendData.length <= 1 ? 3 : 1,
                                        borderWidth: 2,
                                        tension: 0.25,
                                    },
                                ],
                            }}
                            options={{
                                responsive: true,
                                maintainAspectRatio: false,
                                interaction: { mode: 'index', intersect: false },
                                scales: {
                                    x: { grid: { color: 'rgba(255,255,255,0.06)' }, ticks: { color: '#B0B5BA', maxTicksLimit: 8, font: { size: 13 } } },
                                    y: {
                                        min: 0,
                                        max: 100,
                                        grid: { color: 'rgba(255,255,255,0.06)' },
                                        ticks: { color: '#B0B5BA', font: { size: 13 }, callback: (v) => `${v}%` },
                                    },
                                },
                                plugins: {
                                    legend: { labels: { color: '#B0B5BA', font: { size: 13 }, usePointStyle: true, pointStyleWidth: 8 } },
                                },
                            }}
                        />
                    </div>
                </div>
            </div>

            {/* Error */}
            {error && (
                <div className="glass-card p-4 border-danger/30 bg-danger/10 flex items-center justify-between">
                    <p className="text-body text-red-300">{error}</p>
                    <button
                        onClick={() => { setError(null); fetchFlows(); }}
                        className="px-4 py-2 rounded-[10px] border border-danger text-danger text-small font-medium hover:bg-danger/10 transition-colors"
                    >
                        Retry
                    </button>
                </div>
            )}

            {/* Table */}
            <h2 className="section-header">Flow Records</h2>
            <div className="glass-card overflow-hidden">
                {loading ? (
                    <div className="flex items-center justify-center h-64">
                        <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                    </div>
                ) : flows.length === 0 && !error ? (
                    <div className="flex flex-col items-center justify-center h-64 text-text-muted">
                        <Network size={40} className="mb-3 opacity-50" />
                        <p className="text-body">No flows to show</p>
                        <p className="text-small mt-1">Start the backend and load data, or upload a capture.</p>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full data-table">
                            <thead>
                                <tr>
                                    <th className="text-left">Source</th>
                                    <th className="text-left">Time</th>
                                    <th className="text-left">Source IP</th>
                                    <th className="text-left">Dest IP</th>
                                    <th className="text-left">Port</th>
                                    <th className="text-left">Protocol</th>
                                    <th className="text-left">Duration</th>
                                    <th className="text-left">B/s</th>
                                    <th className="text-left">Classification</th>
                                    <th className="text-left">Anomaly</th>
                                    <th className="text-left">Risk</th>
                                </tr>
                            </thead>
                            <tbody>
                                {flows.map((flow) => (
                                    <tr key={flow.id}>
                                        <td>
                                            <span className={`px-2 py-0.5 rounded-md text-small font-medium ${(flow.monitor_type || 'passive') === 'active' ? 'bg-primary/20 text-primary border border-primary/30' : 'bg-surface text-text-muted border border-white/10'}`}>
                                                {(flow.monitor_type || 'passive') === 'active' ? 'Active' : 'Passive'}
                                            </span>
                                        </td>
                                        <td className="text-small text-text-muted whitespace-nowrap">
                                            {flow.timestamp ? new Date(flow.timestamp).toLocaleTimeString() : '—'}
                                        </td>
                                        <td className="cell-ip">{flow.src_ip ?? '—'}</td>
                                        <td className="cell-ip">{flow.dst_ip ?? '—'}</td>
                                        <td className="font-mono text-small text-text-muted">{flow.dst_port ?? '—'}</td>
                                        <td>
                                            <span className="px-2 py-0.5 rounded-md bg-surface text-small font-mono text-primary border border-white/10">
                                                {formatProtocol(flow.protocol)}
                                            </span>
                                        </td>
                                        <td className="text-small text-text-muted">{flow.duration != null ? `${Number(flow.duration).toFixed(1)}s` : '—'}</td>
                                        <td className="text-small text-text-muted font-mono">
                                            {flow.flow_bytes_per_sec != null ? (Number(flow.flow_bytes_per_sec) / 1000).toFixed(1) + 'K' : '—'}
                                        </td>
                                        <td title={flow.classification_reason || ''}>
                                            <span className={`text-small font-semibold ${String(flow.classification || '').toLowerCase() === 'benign' ? 'text-success' : 'text-danger'}`}>
                                                {flow.classification || '—'}
                                            </span>
                                        </td>
                                        <td>
                                            <span className={`text-small font-mono ${(Number(flow.anomaly_score) || 0) > 0.7 ? 'text-danger' : (Number(flow.anomaly_score) || 0) > 0.4 ? 'text-warning' : 'text-success'}`}>
                                                {(Number(flow.anomaly_score) || 0).toFixed(2)}
                                            </span>
                                        </td>
                                        <td>
                                            <span className={`px-2 py-0.5 rounded-md text-small font-medium badge-${(flow.risk_level || 'low').toLowerCase()}`}>
                                                {flow.risk_level ?? '—'}
                                            </span>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}

                {/* Pagination */}
                {flows.length > 0 && (
                <div className="flex items-center justify-between px-6 py-3 border-t border-white/10">
                    <p className="text-small text-text-muted">
                        Showing {((page - 1) * 15) + 1}–{Math.min(page * 15, total)} of {total}
                    </p>
                    <div className="flex items-center gap-2">
                        <button
                            onClick={() => setPage(Math.max(1, page - 1))}
                            disabled={page === 1}
                            className="p-2 rounded-[10px] border border-white/10 text-text-muted hover:text-text-primary hover:border-primary/50 disabled:opacity-30 transition-colors"
                        >
                            <ChevronLeft size={14} />
                        </button>
                        <span className="text-small text-text-primary font-medium px-2">
                            {page} / {totalPages}
                        </span>
                        <button
                            onClick={() => setPage(Math.min(totalPages, page + 1))}
                            disabled={page === totalPages}
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
