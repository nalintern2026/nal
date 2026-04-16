import { useState, useEffect, useCallback, useRef } from 'react';
import { getDashboardStats, getAlerts } from '../services/api';
import { SectionHeading, TogglePills } from '../components/Primitives';
import {
    Activity,
    AlertTriangle,
    Shield,
    Zap,
    TrendingUp,
    Globe,
    ArrowUpRight,
    ArrowDownRight,
} from 'lucide-react';
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement, PointElement, LineElement, Filler } from 'chart.js';
import { Doughnut, Bar, Line } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement, PointElement, LineElement, Filler);

/* Chart palette: distinct from background #222831 / #393E46 - no grays */
const chartColors = ['#00ADB5', '#3B82F6', '#22C55E', '#F59E0B', '#EF4444', '#A855F7', '#EC4899'];

/** Label for passive timeline: full upload timestamp (local). */
function formatUploadTimestamp(hour) {
    const raw = String(hour || '').trim();
    if (!raw) return '';
    let s = raw;
    if (s.includes('T') && !s.endsWith('Z') && !/[+-]\d{2}:?\d{2}$/.test(s)) {
        s = s.endsWith('Z') ? s : `${s}Z`;
    }
    const d = new Date(s);
    if (Number.isNaN(d.getTime())) return raw.length > 22 ? `${raw.slice(0, 10)} ${raw.slice(11, 19)}` : raw;
    return d.toLocaleString([], { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function formatActiveMinuteLabel(hour) {
    const raw = String(hour || '').trim();
    if (!raw) return '';
    let dt = new Date(raw.includes('T') ? `${raw.slice(0, 16)}:00Z` : raw);
    if (Number.isNaN(dt.getTime())) dt = new Date(raw);
    if (Number.isNaN(dt.getTime())) return raw;
    return dt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function timelineLabels(timeline, mode) {
    const arr = timeline || [];
    if (mode === 'passive') return arr.map((t) => formatUploadTimestamp(t.hour));
    return arr.map((t) => formatActiveMinuteLabel(t.hour));
}

const EMPTY_STATS = {
    total_flows: 0,
    total_anomalies: 0,
    anomaly_rate: 0,
    avg_risk_score: 0,
    attack_distribution: {},
    risk_distribution: { Critical: 0, High: 0, Medium: 0, Low: 0 },
    timeline: [],
    protocols: {},
};

export default function Dashboard() {
    /** Separate caches so passive/active never overwrite each other (fixes flicker on toggle). */
    const [statsByMode, setStatsByMode] = useState({ passive: null, active: null });
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [refreshing, setRefreshing] = useState(false);
    const [lastFetchByMode, setLastFetchByMode] = useState({ passive: null, active: null });
    const [monitorView, setMonitorView] = useState('passive'); // 'passive' | 'active'
    const [alertSummary, setAlertSummary] = useState({ total: 0, critical: 0 });
    const [activeModel] = useState('—');

    const genPassive = useRef(0);
    const genActive = useRef(0);

    const fetchStatsFor = useCallback(async (mode) => {
        const genRef = mode === 'passive' ? genPassive : genActive;
        const myGen = ++genRef.current;
        try {
            const response = await getDashboardStats(mode);
            if (myGen !== genRef.current) return;
            setStatsByMode((prev) => ({ ...prev, [mode]: response.data }));
            const t = new Date().toLocaleTimeString();
            setLastFetchByMode((prev) => ({ ...prev, [mode]: t }));
            setError(null);
        } catch (err) {
            if (myGen !== genRef.current) return;
            setError(err.response?.data?.detail || err.message || 'Failed to fetch data');
        }
    }, []);

    // Initial load + periodic refresh: update BOTH caches (toggle only switches which cache is shown)
    useEffect(() => {
        let cancelled = false;
        (async () => {
            await Promise.all([fetchStatsFor('passive'), fetchStatsFor('active')]);
            try {
                const alertsRes = await getAlerts({ limit: 200 });
                const alerts = alertsRes.data.alerts || [];
                setAlertSummary({ total: alerts.length, critical: alerts.filter((a) => a.priority === 'CRITICAL').length });
            } catch {
                setAlertSummary({ total: 0, critical: 0 });
            }
            if (!cancelled) setLoading(false);
        })();
        return () => { cancelled = true; };
    }, [fetchStatsFor]);

    useEffect(() => {
        const interval = setInterval(() => {
            fetchStatsFor('passive');
            fetchStatsFor('active');
        }, 5000);
        return () => clearInterval(interval);
    }, [fetchStatsFor]);

    // If user switches tab before that mode's first successful fetch, load it now (fixes blank passive).
    useEffect(() => {
        if (statsByMode[monitorView] == null) {
            fetchStatsFor(monitorView);
        }
    }, [monitorView, statsByMode, fetchStatsFor]);

    const handleManualRefresh = async () => {
        setRefreshing(true);
        await Promise.all([fetchStatsFor('passive'), fetchStatsFor('active')]);
        setRefreshing(false);
    };

    if (loading && !statsByMode.passive && !statsByMode.active) {
        return <LoadingSkeleton />;
    }

    const statsData = statsByMode[monitorView] || EMPTY_STATS;
    const lastFetch = lastFetchByMode[monitorView];

    const riskPercent = Math.round((statsData.avg_risk_score || 0) * 100);

    return (
        <div className="space-y-8">
            {/* Toggle: Passive / Active */}
            <div className="flex items-center justify-between gap-4 flex-wrap">
                <div className="flex items-center gap-2">
                    <span className="text-small font-medium text-text-muted uppercase tracking-wider">View</span>
                    <TogglePills
                        value={monitorView}
                        onChange={setMonitorView}
                        options={[
                            { value: 'passive', label: 'Passive' },
                            { value: 'active', label: 'Active' },
                        ]}
                    />
                    <span className="text-small text-text-muted">
                        {monitorView === 'passive' ? 'File uploads' : 'Live monitoring'}
                    </span>
                </div>
                <div className="flex items-center gap-3">
                    <p className="text-small text-text-muted">
                        {monitorView === 'active' && (
                            <span className="text-primary font-medium">Live • </span>
                        )}
                        Last updated: {lastFetch ?? '—'} | Total Flows: {statsData.total_flows}
                    </p>
                    <button
                        onClick={handleManualRefresh}
                        disabled={refreshing}
                        className="px-4 py-2.5 rounded-[10px] border border-primary text-primary text-body font-medium hover:bg-primary/10 transition-colors disabled:opacity-50"
                    >
                        {refreshing ? 'Refreshing...' : 'Refresh'}
                    </button>
                </div>
            </div>

            {/* Header */}
            <SectionHeading
                title="Network Dashboard"
                subtitle="Real-time and uploaded traffic intelligence in one view"
            />

            {error && (
                <div className="glass-card p-4 border-danger/30 bg-danger/10">
                    <p className="text-danger text-body">{error}</p>
                </div>
            )}

            {statsData.total_flows === 0 && !error && (
                <div className="glass-card p-8 text-center border-warning/30 bg-warning/10">
                    <p className="text-warning mb-2">No data yet</p>
                    <p className="text-body text-text-muted">
                        {monitorView === 'passive'
                            ? 'Upload a network file on the Upload page to see analysis results here.'
                            : 'Start Active Monitoring (use Default/lo), then use the app to generate traffic. Backend must run with sudo.'}
                    </p>
                </div>
            )}

            {/* KPI Cards */}
            <h2 className="section-header">Network Overview</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <KPICard
                    title="Total Flows"
                    value={statsData.total_flows.toLocaleString()}
                    icon={Activity}
                    color="cyan"
                    trend={monitorView === 'active' ? 'Live stream' : 'Uploaded'}
                    trendUp={true}
                />
                <KPICard
                    title="Anomalies Detected"
                    value={statsData.total_anomalies.toLocaleString()}
                    icon={AlertTriangle}
                    color="red"
                    trend={`${statsData.anomaly_rate}%`}
                    trendUp={false}
                    subtitle="Anomaly Rate"
                />
                <KPICard
                    title="Avg Risk Score"
                    value={riskPercent + '%'}
                    icon={Shield}
                    color="purple"
                    trend={riskPercent > 50 ? 'High' : 'Normal'}
                    trendUp={riskPercent > 50}
                />
                <KPICard
                    title="Active Protocols"
                    value={Object.keys(statsData.protocols || {}).length}
                    icon={Globe}
                    color="green"
                    trend="Live"
                    trendUp={true}
                />
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="glass-card p-4">Alerts: <span className="font-semibold">{alertSummary.total}</span> (Critical: {alertSummary.critical})</div>
                <div className="glass-card p-4">Active Model Version: <span className="font-semibold">{activeModel}</span></div>
            </div>

            {/* Charts Row */}
            <h2 className="section-header">Traffic Analysis</h2>
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                {/* Attack Distribution Doughnut */}
                <div className="glass-card p-6">
                    <h3 className="text-h2 font-semibold text-text-primary mb-4 flex items-center gap-2">
                        <Zap size={14} className="text-primary" />
                        Attack Distribution
                    </h3>
                    <div className="h-56 flex items-center justify-center">
                        <Doughnut
                            data={{
                                labels: Object.keys(statsData.attack_distribution || {}),
                                datasets: [{
                                    data: Object.values(statsData.attack_distribution || {}),
                                    backgroundColor: chartColors,
                                    borderWidth: 0,
                                    spacing: 2,
                                    borderRadius: 4,
                                }],
                            }}
                            options={{
                                responsive: true,
                                maintainAspectRatio: false,
                                cutout: '65%',
                                interaction: { mode: 'nearest', intersect: true },
                                plugins: {
                                    legend: {
                                        position: 'right',
                                        labels: { color: '#B0B5BA', font: { size: 13, family: 'Inter' }, padding: 8, usePointStyle: true, pointStyleWidth: 8 },
                                    },
                                    tooltip: {
                                        enabled: true,
                                        backgroundColor: 'rgba(34, 40, 49, 0.95)',
                                        titleColor: '#EEEEEE',
                                        bodyColor: '#B0B5BA',
                                        borderColor: 'rgba(0, 173, 181, 0.3)',
                                        borderWidth: 1,
                                        cornerRadius: 8,
                                        padding: 12,
                                        titleFont: { size: 13, weight: 'bold', family: 'Inter' },
                                        bodyFont: { size: 12, family: 'Inter' },
                                        callbacks: {
                                            label: (ctx) => {
                                                const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
                                                const pct = total > 0 ? ((ctx.parsed / total) * 100).toFixed(1) : 0;
                                                return ` ${ctx.label}: ${ctx.parsed.toLocaleString()} (${pct}%)`;
                                            },
                                        },
                                    },
                                },
                            }}
                        />
                    </div>
                </div>

                {/* Passive + Active: line charts (upload time vs last 1h minute buckets). */}
                <div className="glass-card p-6 lg:col-span-2">
                    <h3 className="text-h2 font-semibold text-text-primary mb-4 flex items-center gap-2">
                        <TrendingUp size={14} className="text-primary" />
                        Traffic Timeline
                    </h3>
                    <div className="h-64 min-h-[240px] relative">
                        {statsByMode[monitorView] == null ? (
                            <div className="h-full flex items-center justify-center text-body text-text-muted">
                                Loading chart…
                            </div>
                        ) : (statsData.timeline || []).length === 0 ? (
                            <div className="h-full flex items-center justify-center text-body text-text-muted px-4 text-center">
                                {monitorView === 'passive'
                                    ? 'No upload history yet. Run an analysis from the Upload page — each upload appears here by timestamp.'
                                    : 'No flow data in the last hour for active monitoring. Generate traffic or widen capture.'}
                            </div>
                        ) : monitorView === 'passive' ? (
                            <Line
                                key={`tl-passive-${(statsData.timeline || []).length}`}
                                data={{
                                    labels: timelineLabels(statsData.timeline, 'passive'),
                                    datasets: [
                                        {
                                            label: 'Total Flows',
                                            data: (statsData.timeline || []).map((t) => Number(t.total) || 0),
                                            borderColor: '#00ADB5',
                                            backgroundColor: 'rgba(0, 173, 181, 0.12)',
                                            fill: true,
                                            tension: 0.4,
                                            pointRadius: 3,
                                            pointHoverRadius: 7,
                                            pointBackgroundColor: '#00ADB5',
                                            pointBorderColor: '#222831',
                                            pointBorderWidth: 2,
                                            borderWidth: 2,
                                        },
                                        {
                                            label: 'Anomalies',
                                            data: (statsData.timeline || []).map((t) => Number(t.anomalies) || 0),
                                            borderColor: '#EF4444',
                                            backgroundColor: 'rgba(239, 68, 68, 0.12)',
                                            fill: true,
                                            tension: 0.4,
                                            pointRadius: 3,
                                            pointHoverRadius: 7,
                                            pointBackgroundColor: '#EF4444',
                                            pointBorderColor: '#222831',
                                            pointBorderWidth: 2,
                                            borderWidth: 2,
                                        },
                                    ],
                                }}
                                options={{
                                    responsive: true,
                                    maintainAspectRatio: false,
                                    animation: { duration: 0 },
                                    interaction: { mode: 'index', intersect: false },
                                    hover: { mode: 'index', intersect: false },
                                    scales: {
                                        x: {
                                            grid: { color: 'rgba(255,255,255,0.06)' },
                                            ticks: {
                                                color: '#B0B5BA',
                                                font: { size: 10 },
                                                maxRotation: 55,
                                                minRotation: 35,
                                                autoSkip: true,
                                                maxTicksLimit: 16,
                                            },
                                        },
                                        y: {
                                            beginAtZero: true,
                                            grid: { color: 'rgba(255,255,255,0.06)' },
                                            ticks: { color: '#B0B5BA', font: { size: 13 } },
                                        },
                                    },
                                    plugins: {
                                        legend: { labels: { color: '#B0B5BA', font: { size: 13 }, usePointStyle: true, pointStyleWidth: 8 } },
                                        tooltip: {
                                            callbacks: {
                                                title: (items) => (items[0] ? `Uploaded: ${items[0].label}` : ''),
                                                label: (ctx) => {
                                                    const v = ctx.parsed?.y ?? ctx.raw ?? 0;
                                                    return ` ${ctx.dataset.label}: ${Number(v).toLocaleString()} flows`;
                                                },
                                            },
                                        },
                                    },
                                }}
                            />
                        ) : (
                            <Line
                                key={`tl-active-${(statsData.timeline || []).length}`}
                                data={{
                                    labels: (statsData.timeline || []).map((t) => {
                                        const raw = String(t.hour || '').trim();
                                        if (!raw) return '';
                                        let dt = new Date(raw.includes('T') ? raw + ':00Z' : raw);
                                        if (Number.isNaN(dt.getTime())) dt = new Date(raw);
                                        if (Number.isNaN(dt.getTime())) return raw;
                                        return dt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                                    }),
                                    datasets: [
                                        {
                                            label: 'Total Flows',
                                            data: (statsData.timeline || []).map((t) => Number(t.total) || 0),
                                            borderColor: '#00ADB5',
                                            backgroundColor: 'rgba(0, 173, 181, 0.12)',
                                            fill: true,
                                            tension: 0.4,
                                            pointRadius: 3,
                                            pointHoverRadius: 7,
                                            pointBackgroundColor: '#00ADB5',
                                            pointBorderColor: '#222831',
                                            pointBorderWidth: 2,
                                            borderWidth: 2,
                                        },
                                        {
                                            label: 'Anomalies',
                                            data: (statsData.timeline || []).map((t) => Number(t.anomalies) || 0),
                                            borderColor: '#EF4444',
                                            backgroundColor: 'rgba(239, 68, 68, 0.12)',
                                            fill: true,
                                            tension: 0.4,
                                            pointRadius: 3,
                                            pointHoverRadius: 7,
                                            pointBackgroundColor: '#EF4444',
                                            pointBorderColor: '#222831',
                                            pointBorderWidth: 2,
                                            borderWidth: 2,
                                        },
                                    ],
                                }}
                                options={{
                                    responsive: true,
                                    maintainAspectRatio: false,
                                    animation: { duration: 0 },
                                    interaction: { mode: 'index', intersect: false },
                                    hover: { mode: 'index', intersect: false },
                                    scales: {
                                        x: { grid: { color: 'rgba(255,255,255,0.06)' }, ticks: { color: '#B0B5BA', font: { size: 13 } } },
                                        y: { grid: { color: 'rgba(255,255,255,0.06)' }, ticks: { color: '#B0B5BA', font: { size: 13 } }, beginAtZero: true },
                                    },
                                    plugins: {
                                        legend: { labels: { color: '#B0B5BA', font: { size: 13 }, usePointStyle: true, pointStyleWidth: 8 } },
                                        tooltip: {
                                            callbacks: {
                                                title: (items) => (items[0] ? `Time: ${items[0].label}` : ''),
                                                label: (ctx) => {
                                                    const v = ctx.parsed?.y ?? ctx.raw ?? 0;
                                                    return ` ${ctx.dataset.label}: ${Number(v).toLocaleString()} flows`;
                                                },
                                            },
                                        },
                                    },
                                }}
                            />
                        )}
                    </div>
                </div>
            </div>

            {/* Bottom Row */}
            <h2 className="section-header">Risk & Protocols</h2>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* Risk Distribution */}
                <div className="glass-card p-6">
                    <h3 className="text-h2 font-semibold text-text-primary mb-4 flex items-center gap-2">
                        <Shield size={14} className="text-primary" />
                        Risk Distribution
                    </h3>
                    <div className="space-y-3 mt-2">
                        {Object.entries(statsData.risk_distribution || {}).map(([level, count]) => {
                            const total = statsData.total_flows || 1;
                            const pct = Math.round((count / total) * 100);
                            const colorMap = {
                                Critical: { bg: 'bg-danger', text: 'text-red-400' },
                                High: { bg: 'bg-warning', text: 'text-amber-400' },
                                Medium: { bg: 'bg-[#A855F7]', text: 'text-purple-400' },
                                Low: { bg: 'bg-success', text: 'text-green-400' },
                            };
                            const c = colorMap[level] || { bg: 'bg-[#A855F7]', text: 'text-[#A855F7]' };
                            return (
                                <div key={level}>
                                    <div className="flex justify-between text-small mb-1">
                                        <span className={`font-medium ${c.text}`}>{level}</span>
                                        <span className="text-text-muted">{count} ({pct}%)</span>
                                    </div>
                                    <div className="h-2 rounded-full bg-background overflow-hidden">
                                        <div
                                            className={`h-full rounded-full ${c.bg} transition-all duration-500`}
                                            style={{ width: `${pct}%` }}
                                        />
                                    </div>
                                </div>
                            );
                        })}
                    </div>

                    {/* Risk Score Gauge */}
                    <div className="mt-6 flex items-center justify-center">
                        <div className="relative w-32 h-32">
                            <svg viewBox="0 0 100 100" className="transform -rotate-90">
                                <circle cx="50" cy="50" r="40" fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="8" />
                                <circle
                                    cx="50" cy="50" r="40" fill="none"
                                    stroke={riskPercent > 70 ? '#EF4444' : riskPercent > 40 ? '#F59E0B' : '#22C55E'}
                                    strokeWidth="8"
                                    strokeLinecap="round"
                                    strokeDasharray={`${riskPercent * 2.51} 251`}
                                    className="transition-all duration-500"
                                />
                            </svg>
                            <div className="absolute inset-0 flex flex-col items-center justify-center">
                                <span className="text-2xl font-bold text-text-primary">{riskPercent}</span>
                                <span className="text-small text-text-muted">Risk Score</span>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Protocol Distribution Bar */}
                <div className="glass-card p-6">
                    <h3 className="text-h2 font-semibold text-text-primary mb-4 flex items-center gap-2">
                        <Globe size={14} className="text-success" />
                        Protocol Distribution
                    </h3>
                    <div className="h-72">
                        <Bar
                            data={{
                                labels: Object.keys(statsData.protocols || {}),
                                datasets: [{
                                    label: 'Flows',
                                    data: Object.values(statsData.protocols || {}),
                                    backgroundColor: chartColors.map(c => c + '99'),
                                    borderColor: chartColors,
                                    borderWidth: 1,
                                    borderRadius: 6,
                                }],
                            }}
                            options={{
                                responsive: true,
                                maintainAspectRatio: false,
                                indexAxis: 'y',
                                interaction: { mode: 'nearest', intersect: true },
                                scales: {
                                    x: { grid: { color: 'rgba(255,255,255,0.06)' }, ticks: { color: '#B0B5BA', font: { size: 13 } }, beginAtZero: true },
                                    y: { grid: { display: false }, ticks: { color: '#EEEEEE', font: { size: 13, family: 'JetBrains Mono' } } },
                                },
                                plugins: {
                                    legend: { display: false },
                                    tooltip: {
                                        enabled: true,
                                        backgroundColor: 'rgba(34, 40, 49, 0.95)',
                                        titleColor: '#EEEEEE',
                                        bodyColor: '#B0B5BA',
                                        borderColor: 'rgba(0, 173, 181, 0.3)',
                                        borderWidth: 1,
                                        cornerRadius: 8,
                                        padding: 12,
                                        titleFont: { size: 13, weight: 'bold', family: 'Inter' },
                                        bodyFont: { size: 12, family: 'Inter' },
                                        callbacks: {
                                            title: (items) => items[0] ? `Protocol: ${items[0].label}` : '',
                                            label: (ctx) => ` Flows: ${ctx.parsed.x.toLocaleString()}`,
                                        },
                                    },
                                },
                            }}
                        />
                    </div>
                </div>
            </div>

            {/* Top Source IPs Table */}
            <h2 className="section-header">Top Source IPs</h2>
            <div className="glass-card p-6">
                <h3 className="text-h2 font-semibold text-text-primary mb-4 flex items-center gap-2">
                    <Globe size={14} className="text-primary" />
                    Top Source IPs
                </h3>
                <div className="overflow-x-auto">
                    <table className="w-full data-table">
                        <thead>
                            <tr>
                                <th>Rank</th>
                                <th>IP Address</th>
                                <th>Flow Count</th>
                                <th>Traffic Share</th>
                            </tr>
                        </thead>
                        <tbody>
                            {(statsData.top_sources || []).map((ip, i) => (
                                <tr key={ip.ip}>
                                    <td className="font-mono text-primary">#{i + 1}</td>
                                    <td className="cell-ip">{ip.ip}</td>
                                    <td>{ip.count}</td>
                                    <td>
                                        <div className="flex items-center gap-2">
                                            <div className="h-1.5 rounded-full bg-background w-20 overflow-hidden">
                                                <div
                                                    className="h-full rounded-full bg-primary"
                                                    style={{ width: `${Math.round((ip.count / Math.max(1, statsData.total_flows || 0)) * 100)}%` }}
                                                />
                                            </div>
                                            <span className="text-small text-text-muted">
                                                {Math.round((ip.count / Math.max(1, statsData.total_flows || 0)) * 100)}%
                                            </span>
                                        </div>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
}

function KPICard({ title, value, icon: Icon, color, trend, trendUp, subtitle }) {
    const colorMap = {
        cyan: { icon: 'text-primary', border: 'border-primary/20' },
        red: { icon: 'text-danger', border: 'border-danger/20' },
        purple: { icon: 'text-[#A855F7]', border: 'border-[#A855F7]/20' },
        green: { icon: 'text-success', border: 'border-success/20' },
    };
    const c = colorMap[color] || { icon: 'text-primary', border: 'border-white/10' };

    return (
        <div className={`glass-card p-6 border ${c.border} animate-slide-up`}>
            <div className="flex items-start justify-between">
                <div>
                    <p className="text-small text-text-muted font-medium mb-1">{title}</p>
                    <p className="text-2xl font-bold text-text-primary">{value}</p>
                </div>
                <div className={`p-2 rounded-xl bg-background/80 ${c.icon}`}>
                    <Icon size={18} />
                </div>
            </div>
            <div className="flex items-center gap-1 mt-2">
                {trendUp ? (
                    <ArrowUpRight size={12} className="text-success" />
                ) : (
                    <ArrowDownRight size={12} className="text-danger" />
                )}
                <span className={`text-small font-medium ${trendUp ? 'text-success' : 'text-danger'}`}>{trend}</span>
                {subtitle && <span className="text-small text-text-muted ml-1">{subtitle}</span>}
            </div>
        </div>
    );
}

function LoadingSkeleton() {
    return (
        <div className="space-y-8 animate-pulse">
            <div className="grid grid-cols-4 gap-4">
                {[...Array(4)].map((_, i) => (
                    <div key={i} className="glass-card h-28 rounded-xl" />
                ))}
            </div>
            <div className="grid grid-cols-3 gap-4">
                <div className="glass-card h-72 rounded-xl" />
                <div className="glass-card h-72 rounded-xl col-span-2" />
            </div>
        </div>
    );
}

function ErrorState({ onRetry }) {
    return (
        <div className="flex flex-col items-center justify-center h-96">
            <AlertTriangle size={48} className="text-danger mb-4" />
            <h3 className="text-h2 font-semibold text-text-primary mb-2">Failed to Load Dashboard</h3>
            <p className="text-body text-text-muted mb-4">Start the backend API to see live stats, or retry if it just came online.</p>
            {onRetry && (
                <button
                    onClick={onRetry}
                    className="px-4 py-2.5 rounded-[10px] bg-primary text-white text-body font-medium hover:opacity-90 transition-opacity"
                >
                    Retry
                </button>
            )}
        </div>
    );
}
