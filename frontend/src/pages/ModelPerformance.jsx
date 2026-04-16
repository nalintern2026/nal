import { useState, useEffect } from 'react';
import { getModelMetrics } from '../services/api';
import { SectionHeading } from '../components/Primitives';
import {
    BarChart3,
    Target,
    Crosshair,
    Layers,
    Clock,
    Database,
    GitBranch,
    CheckCircle2,
    XCircle,
    Shield,
    Activity,
    TreeDeciduous,
} from 'lucide-react';
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement } from 'chart.js';
import { Bar, Doughnut } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement);

const severityColors = {
    Critical: { bg: '#EF444499', border: '#EF4444' },
    High: { bg: '#F59E0B99', border: '#F59E0B' },
    Medium: { bg: '#8B5CF699', border: '#8B5CF6' },
    Low: { bg: '#22C55E99', border: '#22C55E' },
};

export default function ModelPerformance() {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);

    const fetchModelMetrics = async () => {
        setLoading(true);
        try {
            const { data: d } = await getModelMetrics();
            setData(d);
        } catch (err) {
            console.error('Failed to fetch model metrics:', err);
            setData(null);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchModelMetrics();
    }, []);

    if (loading) {
        return (
            <div className="flex items-center justify-center h-96">
                <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
            </div>
        );
    }

    if (!data) {
        return (
            <div className="flex flex-col items-center justify-center h-96">
                <BarChart3 size={48} className="text-danger mb-4" />
                <p className="text-text-muted mb-4">Failed to load model metrics. Start the backend or retry.</p>
                <button
                    onClick={fetchModelMetrics}
                    className="px-4 py-2.5 rounded-[10px] border border-primary text-primary text-body font-medium hover:bg-primary/10 transition-colors"
                >
                    Retry
                </button>
            </div>
        );
    }

    const rf = data.models?.random_forest;
    const ifModel = data.models?.isolation_forest;
    const info = data.training_info || {};
    const live = data.live_metrics || {};
    const modelStatus = data.model_status || {};
    const totalFlows = live.total_flows || 0;
    const totalAnomalies = live.total_anomalies || 0;
    const normalFlows = Math.max(0, totalFlows - totalAnomalies);
    const riskDist = live.risk_distribution || {};

    const perClass = rf?.per_class || {};
    const classes = rf?.classes || [];
    const cm = rf?.confusion_matrix || [];

    return (
        <div className="space-y-8">
            {/* Header */}
            <SectionHeading
                title="Model Performance"
                subtitle="Training evaluation metrics and live runtime performance"
            />

            {/* ── Model Pipeline Status ── */}
            <h2 className="section-header">Pipeline Status</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <StatusCard
                    label="Random Forest"
                    subtitle="Supervised classifier"
                    loaded={modelStatus.supervised_loaded}
                    icon={TreeDeciduous}
                    details={rf ? `${classes.length} classes · ${(rf.accuracy * 100).toFixed(1)}% accuracy` : null}
                />
                <StatusCard
                    label="Isolation Forest"
                    subtitle="Anomaly detector"
                    loaded={modelStatus.unsupervised_loaded}
                    icon={Shield}
                    details={ifModel ? `${ifModel.n_estimators} trees · ${ifModel.contamination} contamination` : null}
                />
                <StatusCard
                    label="Feature Scaler"
                    subtitle="StandardScaler"
                    loaded={modelStatus.scaler_loaded}
                    icon={Activity}
                    details={info.feature_count ? `${info.feature_count} features` : null}
                />
            </div>

            {/* ── RF Training Metrics (only when RF is trained) ── */}
            {rf && (
                <>
                    <h2 className="section-header">Random Forest — Training Metrics</h2>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                        <MetricCard label="Accuracy" value={rf.accuracy} color="cyan" icon={Target} />
                        <MetricCard label="Precision" value={rf.precision} color="purple" icon={Crosshair} subtitle="macro avg" />
                        <MetricCard label="Recall" value={rf.recall} color="green" icon={Layers} subtitle="macro avg" />
                        <MetricCard label="F1-Score" value={rf.f1_score} color="pink" icon={GitBranch} subtitle="macro avg" />
                    </div>

                    {/* Per-Class Performance Table */}
                    {Object.keys(perClass).length > 0 && (
                        <>
                            <h2 className="section-header">Per-Class Performance</h2>
                            <div className="glass-card overflow-hidden">
                                <div className="overflow-x-auto">
                                    <table className="w-full data-table">
                                        <thead>
                                            <tr>
                                                <th>Class</th>
                                                <th className="text-right">Precision</th>
                                                <th className="text-right">Recall</th>
                                                <th className="text-right">F1-Score</th>
                                                <th className="text-right">Support</th>
                                                <th className="w-48">Performance</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {classes.map((cls) => {
                                                const m = perClass[cls];
                                                if (!m) return null;
                                                const f1Pct = Math.round(m.f1_score * 100);
                                                const barColor = f1Pct >= 95 ? '#22C55E' : f1Pct >= 85 ? '#00ADB5' : f1Pct >= 70 ? '#F59E0B' : '#EF4444';
                                                return (
                                                    <tr key={cls}>
                                                        <td className="font-semibold text-text-primary text-body">{cls}</td>
                                                        <td className="text-right font-mono text-body text-text-primary">{(m.precision * 100).toFixed(1)}%</td>
                                                        <td className="text-right font-mono text-body text-text-primary">{(m.recall * 100).toFixed(1)}%</td>
                                                        <td className="text-right font-mono text-body font-semibold text-text-primary">{(m.f1_score * 100).toFixed(1)}%</td>
                                                        <td className="text-right font-mono text-small text-text-muted">{m.support.toLocaleString()}</td>
                                                        <td>
                                                            <div className="flex items-center gap-2">
                                                                <div className="flex-1 h-2 rounded-full bg-background overflow-hidden">
                                                                    <div
                                                                        className="h-full rounded-full transition-all duration-500"
                                                                        style={{ width: `${f1Pct}%`, backgroundColor: barColor }}
                                                                    />
                                                                </div>
                                                                <span className="text-small font-mono text-text-muted w-10 text-right">{f1Pct}%</span>
                                                            </div>
                                                        </td>
                                                    </tr>
                                                );
                                            })}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </>
                    )}

                    {/* Confusion Matrix */}
                    {cm.length > 0 && (
                        <>
                            <h2 className="section-header">Confusion Matrix</h2>
                            <div className="glass-card p-6">
                                <div className="overflow-x-auto">
                                    <table className="w-full">
                                        <thead>
                                            <tr>
                                                <th className="text-small text-text-muted p-2 text-left">Actual ↓ / Predicted →</th>
                                                {classes.map((c) => (
                                                    <th key={c} className="text-small text-text-muted p-2 text-center font-medium whitespace-nowrap">
                                                        {c}
                                                    </th>
                                                ))}
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {cm.map((row, i) => {
                                                const rowMax = Math.max(...row);
                                                return (
                                                    <tr key={i}>
                                                        <td className="text-small text-text-muted p-2 font-medium whitespace-nowrap">{classes[i]}</td>
                                                        {row.map((val, j) => {
                                                            const intensity = rowMax > 0 ? val / rowMax : 0;
                                                            const isDiag = i === j;
                                                            return (
                                                                <td key={j} className="p-1.5 text-center">
                                                                    <div
                                                                        className={`rounded-lg p-2 text-small font-mono font-semibold ${isDiag ? 'text-text-primary' : 'text-text-muted'}`}
                                                                        style={{
                                                                            background: isDiag
                                                                                ? `rgba(0, 173, 181, ${0.15 + intensity * 0.35})`
                                                                                : val > 0 ? `rgba(239, 68, 68, ${Math.min(intensity * 0.3, 0.3)})` : 'transparent',
                                                                            border: isDiag ? '1px solid rgba(0, 173, 181, 0.25)' : '1px solid transparent',
                                                                        }}
                                                                    >
                                                                        {val.toLocaleString()}
                                                                    </div>
                                                                </td>
                                                            );
                                                        })}
                                                    </tr>
                                                );
                                            })}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </>
                    )}

                    {/* Training Info */}
                    <h2 className="section-header">Training Information</h2>
                    <div className="glass-card p-6">
                        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
                            {[
                                { label: 'Dataset', value: info.dataset || '—', icon: Database },
                                { label: 'Total Samples', value: (info.total_samples ?? 0).toLocaleString(), icon: Layers },
                                { label: 'Training Split', value: (info.training_samples ?? 0).toLocaleString(), icon: GitBranch },
                                { label: 'Test Split', value: (info.test_samples ?? 0).toLocaleString(), icon: Target },
                                { label: 'Features', value: info.feature_count ?? '—', icon: Crosshair },
                                { label: 'Last Trained', value: info.last_trained ? new Date(info.last_trained).toLocaleDateString() : '—', icon: Clock },
                            ].map((item) => (
                                <div key={item.label} className="p-4 rounded-xl bg-background/60 border border-white/10">
                                    <div className="flex items-center gap-2 mb-1">
                                        <item.icon size={12} className="text-text-muted" />
                                        <p className="text-small text-text-muted">{item.label}</p>
                                    </div>
                                    <p className="text-body font-semibold text-text-primary font-mono truncate" title={String(item.value)}>{item.value}</p>
                                </div>
                            ))}
                        </div>
                    </div>
                </>
            )}

            {/* ── Runtime Metrics (always shown when flows exist) ── */}
            {totalFlows > 0 && (
                <>
                    <h2 className="section-header">Live Runtime Metrics</h2>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                        <div className="glass-card p-6">
                            <p className="text-small text-text-muted">Total Flows Analyzed</p>
                            <p className="text-2xl font-bold text-text-primary">{totalFlows.toLocaleString()}</p>
                        </div>
                        <div className="glass-card p-6">
                            <p className="text-small text-text-muted">Anomalies Detected</p>
                            <p className="text-2xl font-bold text-danger">{totalAnomalies.toLocaleString()}</p>
                        </div>
                        <div className="glass-card p-6">
                            <p className="text-small text-text-muted">Anomaly Rate</p>
                            <p className="text-2xl font-bold text-warning">{(live.anomaly_rate || 0).toFixed(2)}%</p>
                        </div>
                        <div className="glass-card p-6">
                            <p className="text-small text-text-muted">Avg Confidence</p>
                            <p className="text-2xl font-bold text-primary">{Math.round((live.avg_confidence || 0) * 100)}%</p>
                        </div>
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                        <div className="glass-card p-6">
                            <h3 className="text-h2 font-semibold text-text-primary mb-4">Traffic Health</h3>
                            <div className="h-72 flex items-center justify-center">
                                <Doughnut
                                    data={{
                                        labels: ['Normal', 'Anomalies'],
                                        datasets: [{
                                            data: [normalFlows, totalAnomalies],
                                            backgroundColor: ['#22C55E99', '#EF444499'],
                                            borderColor: ['#22C55E', '#EF4444'],
                                            borderWidth: 1,
                                            spacing: 2,
                                            borderRadius: 4,
                                        }],
                                    }}
                                    options={{
                                        responsive: true,
                                        maintainAspectRatio: false,
                                        cutout: '62%',
                                        plugins: {
                                            legend: {
                                                position: 'right',
                                                labels: { color: '#B0B5BA', font: { size: 13 }, usePointStyle: true, pointStyleWidth: 8 },
                                            },
                                        },
                                    }}
                                />
                            </div>
                        </div>

                        <div className="glass-card p-6">
                            <h3 className="text-h2 font-semibold text-text-primary mb-4">Risk Distribution</h3>
                            <div className="h-72">
                                <Bar
                                    data={{
                                        labels: ['Low', 'Medium', 'High', 'Critical'],
                                        datasets: [{
                                            label: 'Flows',
                                            data: [
                                                riskDist.Low || 0,
                                                riskDist.Medium || 0,
                                                riskDist.High || 0,
                                                riskDist.Critical || 0,
                                            ],
                                            backgroundColor: [severityColors.Low.bg, severityColors.Medium.bg, severityColors.High.bg, severityColors.Critical.bg],
                                            borderColor: [severityColors.Low.border, severityColors.Medium.border, severityColors.High.border, severityColors.Critical.border],
                                            borderWidth: 1,
                                            borderRadius: 6,
                                        }],
                                    }}
                                    options={{
                                        responsive: true,
                                        maintainAspectRatio: false,
                                        scales: {
                                            x: { grid: { display: false }, ticks: { color: '#B0B5BA', font: { size: 13 } } },
                                            y: { grid: { color: 'rgba(255,255,255,0.06)' }, ticks: { color: '#B0B5BA', font: { size: 13 } } },
                                        },
                                        plugins: { legend: { display: false } },
                                    }}
                                />
                            </div>
                        </div>
                    </div>
                </>
            )}

            {/* Fallback: no models and no flows */}
            {!rf && totalFlows === 0 && (
                <div className="glass-card p-10 text-center rounded-xl border border-white/10">
                    <div className="inline-flex p-4 rounded-xl bg-primary/10 border border-primary/20 mb-4">
                        <BarChart3 size={48} className="text-primary" />
                    </div>
                    <h3 className="text-h2 font-semibold text-text-primary mb-2">No data yet</h3>
                    <p className="text-body text-text-muted max-w-md mx-auto">
                        Train the ML models and upload network traffic to see performance metrics here.
                    </p>
                </div>
            )}
        </div>
    );
}

function MetricCard({ label, value, color, icon: Icon, subtitle }) {
    const pct = Math.round(value * 100);
    const colorMap = {
        cyan: { text: 'text-primary', border: 'border-primary/20', bar: 'bg-primary' },
        purple: { text: 'text-[#A855F7]', border: 'border-[#A855F7]/20', bar: 'bg-[#A855F7]' },
        green: { text: 'text-success', border: 'border-success/20', bar: 'bg-success' },
        pink: { text: 'text-[#EC4899]', border: 'border-[#EC4899]/20', bar: 'bg-[#EC4899]' },
    };
    const c = colorMap[color] || colorMap.cyan;

    return (
        <div className={`glass-card p-6 border ${c.border}`}>
            <div className="flex items-center gap-2 mb-1">
                <Icon size={14} className={c.text} />
                <span className="text-small text-text-muted font-medium">{label}</span>
            </div>
            {subtitle && <p className="text-small text-text-muted mb-1">{subtitle}</p>}
            <p className={`text-2xl font-bold ${c.text} mb-2`}>{(value * 100).toFixed(1)}%</p>
            <div className="h-1.5 rounded-full bg-background overflow-hidden">
                <div className={`h-full rounded-full ${c.bar} transition-all duration-500`} style={{ width: `${pct}%` }} />
            </div>
        </div>
    );
}

function StatusCard({ label, subtitle, loaded, icon: Icon, details }) {
    return (
        <div className={`glass-card p-6 border ${loaded ? 'border-success/20' : 'border-danger/20'}`}>
            <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-3">
                    <div className={`p-2.5 rounded-xl ${loaded ? 'bg-success/10 border border-success/20' : 'bg-danger/10 border border-danger/20'}`}>
                        <Icon size={18} className={loaded ? 'text-success' : 'text-danger'} />
                    </div>
                    <div>
                        <p className="text-body font-semibold text-text-primary">{label}</p>
                        <p className="text-small text-text-muted">{subtitle}</p>
                    </div>
                </div>
                {loaded
                    ? <CheckCircle2 size={18} className="text-success" />
                    : <XCircle size={18} className="text-danger" />
                }
            </div>
            {details && (
                <p className="text-small text-text-muted font-mono pl-12">{details}</p>
            )}
            {!loaded && (
                <p className="text-small text-danger/80 pl-12">Not loaded — run training pipeline</p>
            )}
        </div>
    );
}
