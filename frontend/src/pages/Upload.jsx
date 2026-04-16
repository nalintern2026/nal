import { useState, useCallback } from 'react';
import { uploadFile, getUploadJob, getUploadFlows, setUploadInProgress } from '../services/api';
import { SectionHeading } from '../components/Primitives';
import {
    Upload as UploadIcon,
    FileUp,
    CheckCircle2,
    XCircle,
    Loader2,
    FileText,
    AlertTriangle,
    Shield,
    ChevronDown,
    ChevronUp,
} from 'lucide-react';
export default function Upload() {
    const [file, setFile] = useState(null);
    const [dragOver, setDragOver] = useState(false);
    const [uploading, setUploading] = useState(false);
    const [result, setResult] = useState(null);
    const [error, setError] = useState(null);
    const [expandedSection, setExpandedSection] = useState(null);
    const [fileFlows, setFileFlows] = useState([]);
    const [flowsPage, setFlowsPage] = useState(1);
    const [hasMoreFlows, setHasMoreFlows] = useState(false);
    const [loadingMoreFlows, setLoadingMoreFlows] = useState(false);
    const [anomalyRowsVisible, setAnomalyRowsVisible] = useState(10);
    const [riskRowsVisible, setRiskRowsVisible] = useState(10);
    const [uploadFilter, setUploadFilter] = useState({ type: '', value: '' });
    const [jobStatus, setJobStatus] = useState(null);

    const handleDrop = useCallback((e) => {
        e.preventDefault();
        setDragOver(false);
        const droppedFile = e.dataTransfer.files[0];
        if (droppedFile) {
            setFile(droppedFile);
            setResult(null);
            setError(null);
            setExpandedSection(null);
            setFileFlows([]);
            setFlowsPage(1);
            setHasMoreFlows(false);
            setAnomalyRowsVisible(10);
            setRiskRowsVisible(10);
            setUploadFilter({ type: '', value: '' });
        }
    }, []);

    const handleFileSelect = (e) => {
        const selectedFile = e.target.files[0];
        if (selectedFile) {
            setFile(selectedFile);
            setResult(null);
            setError(null);
            setExpandedSection(null);
            setFileFlows([]);
            setFlowsPage(1);
            setHasMoreFlows(false);
            setAnomalyRowsVisible(10);
            setRiskRowsVisible(10);
            setUploadFilter({ type: '', value: '' });
        }
    };

    const loadMoreFlows = async (analysisId, pageToLoad = 1, replace = false) => {
        if (!analysisId) return;
        setLoadingMoreFlows(true);
        try {
            const { data } = await getUploadFlows(analysisId, { page: pageToLoad, per_page: 200 });
            setFileFlows((prev) => {
                if (replace) return data.flows || [];
                const existing = new Set(prev.map((f) => f.id));
                const incoming = (data.flows || []).filter((f) => !existing.has(f.id));
                return [...prev, ...incoming];
            });
            setFlowsPage((data.page || pageToLoad) + 1);
            setHasMoreFlows(Boolean(data.has_more));
        } catch {
            setError('Failed to load full flow list for this upload.');
        } finally {
            setLoadingMoreFlows(false);
        }
    };

    const handleUpload = async () => {
        if (!file) return;
        setUploading(true);
        setError(null);
        setJobStatus('QUEUED');
        setUploadInProgress(true);

        try {
            const { data } = await uploadFile(file);
            // Backward-compatible: some backend variants return completed analysis payload directly.
            if (!data?.job_id && data?.id) {
                setJobStatus('COMPLETED');
                setResult(data || {});
                setExpandedSection(null);
                setFileFlows(data?.sample_flows || []);
                setFlowsPage(1);
                setHasMoreFlows((data?.total_flows || 0) > (data?.sample_flows || []).length);
                setAnomalyRowsVisible(10);
                setRiskRowsVisible(10);
                setUploadFilter({ type: '', value: '' });
                await loadMoreFlows(data?.id, 1, true);
                return;
            }
            if (!data?.job_id) throw new Error('Backend response missing upload job id');
            let job = null;
            const start = Date.now();
            while (Date.now() - start < 10 * 60 * 1000) {
                const res = await getUploadJob(data.job_id);
                job = res.data;
                setJobStatus(job?.status || 'PROCESSING');
                if (job?.status === 'COMPLETED' || job?.status === 'FAILED') break;
                await new Promise((r) => setTimeout(r, 1500));
            }
            if (!job || job.status !== 'COMPLETED') {
                throw new Error(job?.error || 'Upload processing timed out');
            }
            setResult(job.result_summary || {});
            setExpandedSection(null);
            setFileFlows(job.result_summary?.sample_flows || []);
            setFlowsPage(1);
            setHasMoreFlows((job.result_summary?.total_flows || 0) > (job.result_summary?.sample_flows || []).length);
            setAnomalyRowsVisible(10);
            setRiskRowsVisible(10);
            setUploadFilter({ type: '', value: '' });
            await loadMoreFlows(job.result_summary?.id, 1, true);
        } catch (err) {
            setError(err?.friendlyMessage || err?.message || err.response?.data?.detail || 'Upload failed. Make sure the backend is running.');
        } finally {
            setUploading(false);
            setUploadInProgress(false);
        }
    };

    const formatSize = (bytes) => {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    };

    const renderRows = (rows = []) => {
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
                                    <span className={`px-2 py-0.5 rounded-md text-xs font-medium badge-${(row.risk_level || 'low').toLowerCase()}`}>
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

    const anomalyRows = [...fileFlows]
        .filter((row) => row?.is_anomaly || String(row?.classification || '').toUpperCase() !== 'BENIGN')
        .sort((a, b) => (b?.anomaly_score || 0) - (a?.anomaly_score || 0));

    const riskRows = [...fileFlows]
        .sort((a, b) => (b?.risk_score || 0) - (a?.risk_score || 0));

    const filteredFileFlows = fileFlows.filter((row) => {
        if (!uploadFilter.type || !uploadFilter.value) return true;
        if (uploadFilter.type === 'risk') {
            return String(row?.risk_level || '').toLowerCase() === String(uploadFilter.value).toLowerCase();
        }
        if (uploadFilter.type === 'classification') {
            return String(row?.classification || '').toLowerCase() === String(uploadFilter.value).toLowerCase();
        }
        return true;
    });

    const filteredAnomalyRows = anomalyRows.filter((row) => {
        if (!uploadFilter.type || !uploadFilter.value) return true;
        if (uploadFilter.type === 'risk') {
            return String(row?.risk_level || '').toLowerCase() === String(uploadFilter.value).toLowerCase();
        }
        if (uploadFilter.type === 'classification') {
            return String(row?.classification || '').toLowerCase() === String(uploadFilter.value).toLowerCase();
        }
        return true;
    });

    const filteredRiskRows = riskRows.filter((row) => {
        if (!uploadFilter.type || !uploadFilter.value) return true;
        if (uploadFilter.type === 'risk') {
            return String(row?.risk_level || '').toLowerCase() === String(uploadFilter.value).toLowerCase();
        }
        if (uploadFilter.type === 'classification') {
            return String(row?.classification || '').toLowerCase() === String(uploadFilter.value).toLowerCase();
        }
        return true;
    });

    const handleViewMoreAnomalies = async () => {
        if (anomalyRowsVisible < anomalyRows.length) {
            setAnomalyRowsVisible((prev) => prev + 10);
            return;
        }
        if (hasMoreFlows && result?.id) {
            await loadMoreFlows(result.id, flowsPage, false);
            setAnomalyRowsVisible((prev) => prev + 10);
        }
    };

    const handleViewMoreRisk = async () => {
        if (riskRowsVisible < riskRows.length) {
            setRiskRowsVisible((prev) => prev + 10);
            return;
        }
        if (hasMoreFlows && result?.id) {
            await loadMoreFlows(result.id, flowsPage, false);
            setRiskRowsVisible((prev) => prev + 10);
        }
    };

    return (
        <div className="max-w-4xl mx-auto space-y-8">
            {/* Header */}
            <SectionHeading
                title="Upload Network Capture"
                subtitle="Upload PCAP, PCAPNG, or CSV flow files for ML-powered traffic analysis"
            />

            {/* Drop Zone */}
            <div
                onDrop={handleDrop}
                onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                onDragLeave={() => setDragOver(false)}
                className={`drop-zone rounded-xl p-12 text-center cursor-pointer ${dragOver ? 'drag-over' : ''}`}
                onClick={() => document.getElementById('file-input').click()}
            >
                <input
                    id="file-input"
                    type="file"
                    accept=".pcap,.pcapng,.csv"
                    onChange={handleFileSelect}
                    className="hidden"
                />
                <div className="flex flex-col items-center">
                    <div className="w-16 h-16 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center mb-4">
                        <FileUp size={28} className="text-primary" />
                    </div>
                    <p className="text-body font-semibold text-text-primary mb-1">
                        {dragOver ? 'Drop your file here' : 'Drag & drop your file here'}
                    </p>
                    <p className="text-body text-text-muted mb-4">or click to browse</p>
                    <div className="flex gap-2">
                        {['.pcap', '.pcapng', '.csv'].map((ext) => (
                            <span key={ext} className="px-3 py-1 rounded-lg bg-surface text-small font-mono text-primary border border-white/10">
                                {ext}
                            </span>
                        ))}
                    </div>
                </div>
            </div>

            {/* Selected File */}
            {file && (
                <div className="glass-card p-6 animate-slide-up">
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                            <div className="p-2 rounded-xl bg-primary/10">
                                <FileText size={20} className="text-primary" />
                            </div>
                            <div>
                                <p className="text-body font-medium text-text-primary">{file.name}</p>
                                <p className="text-small text-text-muted">{formatSize(file.size)}</p>
                            </div>
                        </div>
                        <div className="flex items-center gap-3">
                            <button
                                onClick={() => {
                                    setFile(null);
                                    setResult(null);
                                    setError(null);
                                    setExpandedSection(null);
                                    setFileFlows([]);
                                    setFlowsPage(1);
                                    setHasMoreFlows(false);
                                    setAnomalyRowsVisible(10);
                                    setRiskRowsVisible(10);
                                    setUploadFilter({ type: '', value: '' });
                                }}
                                className="text-small text-text-muted hover:text-danger transition-colors"
                            >
                                Remove
                            </button>
                            <button
                                onClick={handleUpload}
                                disabled={uploading}
                                className="px-5 py-2.5 rounded-[10px] bg-primary text-white text-body font-semibold hover:opacity-90 transition-opacity disabled:opacity-50 flex items-center gap-2"
                            >
                                {uploading ? (
                                    <>
                                        <Loader2 size={14} className="animate-spin" />
                                        Processing...
                                    </>
                                ) : (
                                    <>
                                        <UploadIcon size={14} />
                                        Analyze
                                    </>
                                )}
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Error */}
            {error && (
                <div className="glass-card p-4 border-danger/30 bg-danger/10 animate-slide-up">
                    <div className="flex items-center gap-3">
                        <XCircle size={20} className="text-danger" />
                        <p className="text-body text-red-300">{error}</p>
                    </div>
                </div>
            )}
            {uploading && (
                <div className="glass-card p-4 border-primary/30 bg-primary/10 animate-slide-up">
                    <p className="text-body text-text-primary">Job status: <span className="font-semibold">{jobStatus || 'PROCESSING'}</span></p>
                </div>
            )}

            {/* Results */}
            {result && (
                <div className="space-y-4 animate-slide-up">
                    <h2 className="section-header">Analysis Results</h2>
                    <div className="glass-card p-6 border-success/20">
                        <div className="flex items-center gap-3 mb-4">
                            <CheckCircle2 size={20} className="text-success" />
                            <h3 className="text-h2 font-semibold text-text-primary">Analysis Complete</h3>
                        </div>

                        {/* Result KPIs */}
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5">
                            <ResultKPI
                                label="Total Flows"
                                value={result.total_flows ?? 0}
                                icon={FileText}
                                isActive={expandedSection === 'total_flows'}
                                onClick={() => setExpandedSection(expandedSection === 'total_flows' ? null : 'total_flows')}
                            />
                            <ResultKPI
                                label="Anomalies"
                                value={result.anomaly_count ?? 0}
                                icon={AlertTriangle}
                                isActive={expandedSection === 'anomalies'}
                                onClick={() => setExpandedSection(expandedSection === 'anomalies' ? null : 'anomalies')}
                            />
                            <ResultKPI
                                label="Avg Risk"
                                value={`${Math.round((result.avg_risk_score ?? 0) * 100)}%`}
                                icon={Shield}
                                isActive={expandedSection === 'avg_risk'}
                                onClick={() => setExpandedSection(expandedSection === 'avg_risk' ? null : 'avg_risk')}
                            />
                            {result.file_size != null && <ResultKPI label="File Size" value={formatSize(result.file_size)} icon={FileUp} />}
                        </div>

                        {expandedSection === 'total_flows' && (
                            <div className="mb-5 p-4 rounded-xl bg-background/60 border border-white/10">
                                <h4 className="text-small font-semibold text-text-primary uppercase tracking-wider mb-3">Protocol Distribution</h4>
                                <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                                    {Object.entries(result.report_details?.protocol_distribution || {}).map(([name, count]) => (
                                        <div key={name} className="p-2 rounded-lg bg-surface border border-white/10">
                                            <p className="text-small text-text-muted">{name}</p>
                                            <p className="text-body font-semibold text-text-primary">{count}</p>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {expandedSection === 'anomalies' && (
                            <div className="mb-5 p-4 rounded-xl bg-background/60 border border-white/10">
                                <h4 className="text-small font-semibold text-text-primary uppercase tracking-wider mb-3">Anomaly Types</h4>
                                <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mb-4">
                                    {Object.entries(result.report_details?.anomaly_breakdown || {}).map(([name, count]) => (
                                        <button
                                            key={name}
                                            type="button"
                                            onClick={() => setUploadFilter({ type: 'classification', value: name })}
                                            className={`p-2 rounded-lg bg-surface border text-left transition-colors ${uploadFilter.type === 'classification' && uploadFilter.value === name ? 'border-primary' : 'border-white/10 hover:border-primary/50'}`}
                                        >
                                            <p className="text-small text-text-muted">{name}</p>
                                            <p className="text-body font-semibold text-text-primary">{count}</p>
                                        </button>
                                    ))}
                                </div>
                                {renderRows(filteredAnomalyRows.slice(0, anomalyRowsVisible))}
                                {(anomalyRowsVisible < filteredAnomalyRows.length || hasMoreFlows) && (
                                    <div className="mt-3 flex justify-end">
                                        <button
                                            type="button"
                                            onClick={handleViewMoreAnomalies}
                                            disabled={loadingMoreFlows}
                                            className="px-4 py-2 rounded-[10px] border border-primary text-primary text-small font-semibold hover:bg-primary/10 disabled:opacity-60"
                                        >
                                            {loadingMoreFlows ? 'Loading...' : 'View More'}
                                        </button>
                                    </div>
                                )}
                            </div>
                        )}

                        {expandedSection === 'avg_risk' && (
                            <div className="mb-5 p-4 rounded-xl bg-background/60 border border-white/10">
                                <h4 className="text-small font-semibold text-text-primary uppercase tracking-wider mb-3">Risk Breakdown</h4>
                                <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mb-4">
                                    {Object.entries(result.report_details?.risk_breakdown || {}).map(([level, count]) => (
                                        <button
                                            key={level}
                                            type="button"
                                            onClick={() => setUploadFilter({ type: 'risk', value: level })}
                                            className={`p-2 rounded-lg bg-surface border text-left transition-colors ${uploadFilter.type === 'risk' && uploadFilter.value === level ? 'border-primary' : 'border-white/10 hover:border-primary/50'}`}
                                        >
                                            <p className="text-small text-text-muted">{level}</p>
                                            <p className="text-body font-semibold text-text-primary">{count}</p>
                                        </button>
                                    ))}
                                </div>
                                {renderRows(filteredRiskRows.slice(0, riskRowsVisible))}
                                {(riskRowsVisible < filteredRiskRows.length || hasMoreFlows) && (
                                    <div className="mt-3 flex justify-end">
                                        <button
                                            type="button"
                                            onClick={handleViewMoreRisk}
                                            disabled={loadingMoreFlows}
                                            className="px-4 py-2 rounded-[10px] border border-primary text-primary text-small font-semibold hover:bg-primary/10 disabled:opacity-60"
                                        >
                                            {loadingMoreFlows ? 'Loading...' : 'View More'}
                                        </button>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* Attack Breakdown */}
                        <h4 className="text-small font-semibold text-text-muted uppercase tracking-wider mb-3">Attack Distribution</h4>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mb-5">
                            {Object.entries(result.attack_distribution || {}).map(([type, count]) => (
                                <button
                                    key={type}
                                    type="button"
                                    onClick={() => setExpandedSection(expandedSection === `attack:${type}` ? null : `attack:${type}`)}
                                    className={`p-3 rounded-xl bg-background/60 border text-left transition-colors hover:border-primary/50 ${expandedSection === `attack:${type}` ? 'border-primary' : 'border-white/10'}`}
                                >
                                    <p className="text-small text-text-muted mb-1">{type}</p>
                                    <p className="text-lg font-bold text-text-primary">{count}</p>
                                </button>
                            ))}
                        </div>

                        {expandedSection?.startsWith('attack:') && (
                            <div className="mb-5 p-4 rounded-xl bg-background/60 border border-white/10">
                                <h4 className="text-small font-semibold text-text-primary uppercase tracking-wider mb-3">
                                    {expandedSection.replace('attack:', '')} Sample Flows
                                </h4>
                                {renderRows(result.report_details?.attack_flow_samples?.[expandedSection.replace('attack:', '')] || [])}
                            </div>
                        )}

                        {/* All Flows (paged) */}
                        {fileFlows.length > 0 && (
                            <>
                                <div className="flex items-center justify-between mb-3">
                                    <h4 className="text-small font-semibold text-text-muted uppercase tracking-wider">
                                        All Flows From This File ({filteredFileFlows.length}/{result.total_flows || 0})
                                    </h4>
                                    <div className="flex items-center gap-2">
                                        {uploadFilter.type && (
                                            <button
                                                type="button"
                                                onClick={() => setUploadFilter({ type: '', value: '' })}
                                                className="px-3 py-2 rounded-[10px] border border-white/15 text-text-primary text-small hover:border-primary/50"
                                            >
                                                Clear Small Filter
                                            </button>
                                        )}
                                        {hasMoreFlows && (
                                            <button
                                                type="button"
                                                onClick={() => loadMoreFlows(result.id, flowsPage, false)}
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
                                            {filteredFileFlows.map((flow) => (
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
                                {loadingMoreFlows && (
                                    <p className="text-small text-text-muted mt-2">Loading more rows...</p>
                                )}
                            </>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}

function ResultKPI({ label, value, icon: Icon, isActive = false, onClick }) {
    const clickable = typeof onClick === 'function';

    return (
        <button
            type="button"
            onClick={onClick}
            className={`p-3 rounded-xl bg-background/60 border text-center w-full transition-colors ${isActive ? 'border-primary' : 'border-white/10'} ${clickable ? 'hover:border-primary/50' : ''}`}
            disabled={!clickable}
        >
            <Icon size={16} className="mx-auto text-primary mb-1" />
            <p className="text-lg font-bold text-text-primary">{value}</p>
            <p className="text-small text-text-muted uppercase tracking-wider flex items-center justify-center gap-1">
                {label}
                {clickable && (isActive ? <ChevronUp size={12} /> : <ChevronDown size={12} />)}
            </p>
        </button>
    );
}
