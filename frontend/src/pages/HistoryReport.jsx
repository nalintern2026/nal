import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { getHistoryReport, getUploadFlows } from '../services/api';
import { SectionHeading } from '../components/Primitives';
import {
    ArrowLeft,
    FileText,
    CheckCircle2,
    AlertTriangle,
    Shield,
    FileUp,
    Loader2,
} from 'lucide-react';

export default function HistoryReport() {
    const { id } = useParams();
    const navigate = useNavigate();
    const [report, setReport] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [reportFlows, setReportFlows] = useState([]);
    const [flowsPage, setFlowsPage] = useState(1);
    const [hasMoreFlows, setHasMoreFlows] = useState(false);
    const [loadingMoreFlows, setLoadingMoreFlows] = useState(false);
    const [anomalyRowsVisible, setAnomalyRowsVisible] = useState(10);
    const [riskRowsVisible, setRiskRowsVisible] = useState(10);
    const [reportFilter, setReportFilter] = useState({ type: '', value: '' });

    useEffect(() => {
        if (id) loadReport();
    }, [id]);

    const loadReport = async () => {
        setLoading(true);
        setError(null);
        setReport(null);
        setReportFlows([]);
        setAnomalyRowsVisible(10);
        setRiskRowsVisible(10);
        setReportFilter({ type: '', value: '' });
        try {
            const { data } = await getHistoryReport(id);
            setReport(data);
            const flows = data.flows || data.sample_flows || [];
            setReportFlows(flows);
            setHasMoreFlows((data.total_flows || 0) > flows.length);
            setFlowsPage(Math.floor(flows.length / 200) + 1);
        } catch (err) {
            setError(err.response?.data?.detail || 'Failed to load report.');
        } finally {
            setLoading(false);
        }
    };

    const loadMoreFlows = async (pageToLoad = 1, replace = false) => {
        if (!id) return;
        setLoadingMoreFlows(true);
        try {
            const { data } = await getUploadFlows(id, { page: pageToLoad, per_page: 200 });
            const flows = data.flows || [];
            setReportFlows((prev) => {
                if (replace) return flows;
                const existing = new Set(prev.map((f) => f.id));
                const incoming = flows.filter((f) => !existing.has(f.id));
                return [...prev, ...incoming];
            });
            setFlowsPage((data.page || pageToLoad) + 1);
            setHasMoreFlows(Boolean(data.has_more));
        } catch {
            setError('Failed to load flows.');
        } finally {
            setLoadingMoreFlows(false);
        }
    };

    const formatSize = (bytes) => {
        if (bytes == null || bytes === undefined) return '—';
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    };

    const renderReportRows = (rows = []) => {
        if (!rows.length) {
            return <p className="text-small text-text-muted">No detailed rows found for this section.</p>;
        }
        return (
            <div className="overflow-x-auto">
                <table className="w-full data-table">
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Threat</th>
                            <th>CVE</th>
                            <th>Source IP</th>
                            <th>Dest IP</th>
                            <th>Protocol</th>
                            <th>Anomaly</th>
                            <th>Risk</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows.map((row) => (
                            <tr key={`${row.id}-${row.classification || row.src_ip}`}>
                                <td className="text-small text-text-primary" title={row.classification_reason || ''}>{row.classification || '—'}</td>
                                <td className="text-small text-amber-200">{row.threat_type || '—'}</td>
                                <td className="text-small font-mono text-primary">{row.cve_refs ? String(row.cve_refs).replace(/,/g, ', ') : '—'}</td>
                                <td className="cell-ip">{row.src_ip || '—'}</td>
                                <td className="cell-ip">{row.dst_ip || '—'}</td>
                                <td className="text-small text-primary">{row.protocol || '—'}</td>
                                <td className="text-small text-warning">{Math.round((row.anomaly_score || 0) * 100)}%</td>
                                <td title={row.classification_reason || ''}>
                                    <span className={`px-2 py-0.5 rounded-md text-small font-medium badge-${(row.risk_level || 'low').toLowerCase()}`}>
                                        {row.risk_level || 'Low'} ({Math.round((row.risk_score || 0) * 100)}%)
                                    </span>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        );
    };

    const anomalyRows = [...reportFlows]
        .filter((row) => row?.is_anomaly || String(row?.classification || '').toUpperCase() !== 'BENIGN')
        .sort((a, b) => (b?.anomaly_score || 0) - (a?.anomaly_score || 0));

    const riskRows = [...reportFlows].sort((a, b) => (b?.risk_score || 0) - (a?.risk_score || 0));

    const filteredAnomalyRows = anomalyRows.filter((row) => {
        if (!reportFilter.type || !reportFilter.value) return true;
        if (reportFilter.type === 'risk') return String(row?.risk_level || '').toLowerCase() === String(reportFilter.value).toLowerCase();
        if (reportFilter.type === 'classification') return String(row?.classification || '').toLowerCase() === String(reportFilter.value).toLowerCase();
        return true;
    });

    const filteredRiskRows = riskRows.filter((row) => {
        if (!reportFilter.type || !reportFilter.value) return true;
        if (reportFilter.type === 'risk') return String(row?.risk_level || '').toLowerCase() === String(reportFilter.value).toLowerCase();
        if (reportFilter.type === 'classification') return String(row?.classification || '').toLowerCase() === String(reportFilter.value).toLowerCase();
        return true;
    });

    const filteredReportFlows = reportFlows.filter((row) => {
        if (!reportFilter.type || !reportFilter.value) return true;
        if (reportFilter.type === 'risk') return String(row?.risk_level || '').toLowerCase() === String(reportFilter.value).toLowerCase();
        if (reportFilter.type === 'classification') return String(row?.classification || '').toLowerCase() === String(reportFilter.value).toLowerCase();
        return true;
    });

    if (loading) {
        return (
            <div className="flex flex-col items-center justify-center min-h-[300px] gap-4">
                <Loader2 size={32} className="animate-spin text-primary" />
                <p className="text-body text-text-muted">Loading report...</p>
            </div>
        );
    }

    if (error || !report) {
        return (
            <div className="max-w-2xl mx-auto space-y-4">
                <button
                    type="button"
                    onClick={() => navigate('/history')}
                    className="flex items-center gap-2 text-body text-primary hover:opacity-90"
                >
                    <ArrowLeft size={16} />
                    Back to History
                </button>
                <div className="glass-card p-6 border-danger/30 bg-danger/10">
                    <p className="text-red-300">{error || 'Report not found.'}</p>
                </div>
            </div>
        );
    }

    return (
        <div className="max-w-4xl mx-auto space-y-8">
            <div className="flex items-center justify-between">
                <button
                    type="button"
                    onClick={() => navigate('/history')}
                    className="flex items-center gap-2 px-4 py-2 rounded-[10px] border border-white/10 text-text-primary hover:border-primary/50 hover:text-primary transition-colors"
                >
                    <ArrowLeft size={16} />
                    Back to History
                </button>
                <div className="max-w-md truncate">
                    <SectionHeading title={report.filename || 'Report'} subtitle="Historical analysis report details" />
                </div>
            </div>

            <h2 className="section-header">Report Summary</h2>
            <div className="glass-card p-6 border-success/20">
                <div className="flex items-center gap-3 mb-4">
                    <CheckCircle2 size={20} className="text-success" />
                    <h3 className="text-h2 font-semibold text-text-primary">Analysis Report</h3>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5">
                    <ReportKPI label="Total Flows" value={report.total_flows ?? 0} icon={FileText} />
                    <ReportKPI label="Anomalies" value={report.anomaly_count ?? 0} icon={AlertTriangle} />
                    <ReportKPI label="Avg Risk" value={`${Math.round((report.avg_risk_score ?? 0) * 100)}%`} icon={Shield} />
                    <ReportKPI label="File Size" value={formatSize(report.file_size)} icon={FileUp} />
                </div>

                <h4 className="text-small font-semibold text-text-muted uppercase tracking-wider mb-3">Attack Distribution</h4>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mb-5">
                    {Object.entries(report.attack_distribution || {}).map(([type, count]) => (
                        <button
                            key={type}
                            type="button"
                            onClick={() => setReportFilter(reportFilter.type === 'classification' && reportFilter.value === type ? { type: '', value: '' } : { type: 'classification', value: type })}
                            className={`p-3 rounded-xl bg-background/60 border text-left transition-colors hover:border-primary/50 ${reportFilter.type === 'classification' && reportFilter.value === type ? 'border-primary' : 'border-white/10'}`}
                        >
                            <p className="text-small text-text-muted mb-1">{type}</p>
                            <p className="text-lg font-bold text-text-primary">{count}</p>
                        </button>
                    ))}
                </div>

                <h4 className="text-small font-semibold text-text-muted uppercase tracking-wider mb-3">Risk Breakdown</h4>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mb-5">
                    {Object.entries(report.report_details?.risk_breakdown || report.risk_distribution || {}).map(([level, count]) => (
                        <button
                            key={level}
                            type="button"
                            onClick={() => setReportFilter(reportFilter.type === 'risk' && reportFilter.value === level ? { type: '', value: '' } : { type: 'risk', value: level })}
                            className={`p-2 rounded-lg bg-background/60 border text-left transition-colors ${reportFilter.type === 'risk' && reportFilter.value === level ? 'border-primary' : 'border-white/10'} hover:border-primary/50`}
                        >
                            <p className="text-small text-text-muted">{level}</p>
                            <p className="text-body font-semibold text-text-primary">{count}</p>
                        </button>
                    ))}
                </div>

                <h4 className="text-small font-semibold text-text-muted uppercase tracking-wider mb-3">Top Anomalies</h4>
                {renderReportRows(filteredAnomalyRows.slice(0, anomalyRowsVisible))}
                {(anomalyRowsVisible < filteredAnomalyRows.length || hasMoreFlows) && (
                    <div className="mt-3 flex justify-end">
                        <button
                            type="button"
                            onClick={async () => {
                                if (anomalyRowsVisible < anomalyRows.length) {
                                    setAnomalyRowsVisible((p) => p + 10);
                                } else if (hasMoreFlows && id) {
                                    await loadMoreFlows(flowsPage, false);
                                    setAnomalyRowsVisible((p) => p + 10);
                                }
                            }}
                            disabled={loadingMoreFlows}
                            className="px-4 py-2 rounded-[10px] border border-primary text-primary text-small font-semibold hover:bg-primary/10 disabled:opacity-60"
                        >
                            {loadingMoreFlows ? 'Loading...' : 'View More'}
                        </button>
                    </div>
                )}

                <h4 className="text-small font-semibold text-text-muted uppercase tracking-wider mb-3 mt-6">Top Risk Flows</h4>
                {renderReportRows(filteredRiskRows.slice(0, riskRowsVisible))}
                {(riskRowsVisible < filteredRiskRows.length || hasMoreFlows) && (
                    <div className="mt-3 flex justify-end">
                        <button
                            type="button"
                            onClick={async () => {
                                if (riskRowsVisible < riskRows.length) {
                                    setRiskRowsVisible((p) => p + 10);
                                } else if (hasMoreFlows && id) {
                                    await loadMoreFlows(flowsPage, false);
                                    setRiskRowsVisible((p) => p + 10);
                                }
                            }}
                            disabled={loadingMoreFlows}
                            className="px-4 py-2 rounded-[10px] border border-primary text-primary text-small font-semibold hover:bg-primary/10 disabled:opacity-60"
                        >
                            {loadingMoreFlows ? 'Loading...' : 'View More'}
                        </button>
                    </div>
                )}

                {reportFlows.length > 0 && (
                    <>
                        <div className="flex items-center justify-between mb-3 mt-6">
                            <h4 className="text-small font-semibold text-text-muted uppercase tracking-wider">
                                All Flows ({filteredReportFlows.length}/{report.total_flows || 0})
                            </h4>
                            <div className="flex items-center gap-2">
                                {reportFilter.type && (
                                    <button
                                        type="button"
                                        onClick={() => setReportFilter({ type: '', value: '' })}
                                        className="px-3 py-2 rounded-[10px] border border-white/15 text-text-primary text-small hover:border-primary/50"
                                    >
                                        Clear Filter
                                    </button>
                                )}
                                {hasMoreFlows && (
                                    <button
                                        type="button"
                                        onClick={() => loadMoreFlows(flowsPage, false)}
                                        disabled={loadingMoreFlows}
                                        className="px-4 py-2 rounded-[10px] border border-primary text-primary text-small font-semibold hover:bg-primary/10 disabled:opacity-60"
                                    >
                                        {loadingMoreFlows ? 'Loading...' : 'View More'}
                                    </button>
                                )}
                            </div>
                        </div>
                        <div className="overflow-x-auto max-h-96 overflow-y-auto">
                            <table className="w-full data-table">
                                <thead>
                                    <tr>
                                        <th>Source IP</th>
                                        <th>Dest IP</th>
                                        <th>Protocol</th>
                                        <th>Classification</th>
                                        <th>Risk</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {filteredReportFlows.map((flow) => (
                                        <tr key={flow.id}>
                                            <td className="cell-ip">{flow.src_ip}</td>
                                            <td className="cell-ip">{flow.dst_ip}</td>
                                            <td>
                                                <span className="px-2 py-0.5 rounded-md bg-surface text-small font-mono text-primary border border-white/10">
                                                    {flow.protocol}
                                                </span>
                                            </td>
                                            <td>
                                                <span className={`text-small font-medium ${String(flow.classification || '').toUpperCase() === 'BENIGN' ? 'text-success' : 'text-danger'}`}>
                                                    {flow.classification}
                                                </span>
                                            </td>
                                            <td>
                                                <span className={`px-2 py-0.5 rounded-md text-small font-medium badge-${(flow.risk_level || 'low').toLowerCase()}`}>
                                                    {flow.risk_level || 'Low'}
                                                </span>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </>
                )}
            </div>
        </div>
    );
}

function ReportKPI({ label, value, icon: Icon }) {
    return (
        <div className="p-3 rounded-xl bg-background/60 border border-white/10 text-center">
            <Icon size={16} className="mx-auto text-primary mb-1" />
            <p className="text-lg font-bold text-text-primary">{value}</p>
            <p className="text-small text-text-muted uppercase tracking-wider">{label}</p>
        </div>
    );
}
