import { useEffect, useState } from 'react';
import { getOsintFlows } from '../services/api';
import { SectionHeading, TogglePills } from '../components/Primitives';
import {
    ShieldCheck,
    Search,
    ChevronLeft,
    ChevronRight,
    ChevronDown,
    ChevronUp,
    Bug,
    ExternalLink,
    Shield,
    AlertTriangle,
    Activity,
    Globe,
} from 'lucide-react';

const verdictColors = {
    'Verified Threat': { text: 'text-red-400', bg: 'bg-red-500/15', border: 'border-red-500/30' },
    'Suspicious': { text: 'text-orange-400', bg: 'bg-orange-500/15', border: 'border-orange-500/30' },
    'Unconfirmed Threat': { text: 'text-yellow-400', bg: 'bg-yellow-500/15', border: 'border-yellow-500/30' },
    'Likely False Positive': { text: 'text-green-400', bg: 'bg-green-500/15', border: 'border-green-500/30' },
    'OSINT Unavailable': { text: 'text-slate-400', bg: 'bg-slate-500/15', border: 'border-slate-500/30' },
    'OSINT Skipped': { text: 'text-slate-400', bg: 'bg-slate-500/15', border: 'border-slate-500/30' },
};

const riskColors = {
    Critical: 'text-red-400',
    High: 'text-orange-400',
    Medium: 'text-purple-400',
    Low: 'text-green-400',
};

function parseCveRefs(raw) {
    if (!raw) return [];
    return String(raw).split(',').map((s) => s.trim()).filter(Boolean);
}

export default function OSINTValidation() {
    const [flows, setFlows] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [page, setPage] = useState(1);
    const [totalPages, setTotalPages] = useState(1);
    const [total, setTotal] = useState(0);
    const [monitorView, setMonitorView] = useState('');
    const [srcIp, setSrcIp] = useState('');
    const [debouncedSrcIp, setDebouncedSrcIp] = useState('');
    const [expandedRows, setExpandedRows] = useState({});

    const toggleRow = (id) => {
        setExpandedRows((p) => ({ ...p, [id]: !p[id] }));
    };

    const fetchFlows = async () => {
        setLoading(true);
        setError(null);
        try {
            const params = { page, per_page: 20 };
            if (monitorView) params.monitor_type = monitorView;
            if (debouncedSrcIp.trim()) params.src_ip = debouncedSrcIp.trim();
            const { data } = await getOsintFlows(params);
            setFlows(data.flows || []);
            setTotal(data.total ?? 0);
            setTotalPages(Math.max(1, data.total_pages ?? 1));
        } catch (e) {
            setError(e.response?.data?.detail || 'Failed to load OSINT-validated flows.');
            setFlows([]);
            setTotal(0);
            setTotalPages(1);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        const t = setTimeout(() => {
            setDebouncedSrcIp(srcIp);
        }, 350);
        return () => clearTimeout(t);
    }, [srcIp]);

    useEffect(() => {
        setPage(1);
    }, [debouncedSrcIp, monitorView]);

    useEffect(() => {
        fetchFlows();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [page, monitorView, debouncedSrcIp]);

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between gap-4 flex-wrap">
                <SectionHeading
                    title="OSINT Validation"
                    subtitle={`${total.toLocaleString()} enriched flows${monitorView === 'active' ? ' (active monitoring)' : monitorView === 'passive' ? ' (passive / uploads)' : ' (combined)'}`}
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

            <div className="glass-card p-4 flex items-center gap-3">
                <div className="relative flex-1">
                    <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
                    <input
                        type="text"
                        placeholder="Filter by source IP…"
                        value={srcIp}
                        onChange={(e) => setSrcIp(e.target.value)}
                        className="w-full pl-9 pr-3 py-2 rounded-xl bg-background border border-white/10 text-body text-text-primary placeholder-text-muted focus:outline-none focus:border-primary/50 transition-colors"
                    />
                </div>
                <button
                    type="button"
                    onClick={() => { setSrcIp(''); setPage(1); }}
                    className="px-4 py-2 rounded-[10px] border border-white/10 text-body text-text-muted hover:text-text-primary hover:border-primary/50 transition-colors"
                >
                    Clear
                </button>
            </div>

            {error && (
                <div className="glass-card p-4 border-danger/30 bg-danger/10">
                    <p className="text-body text-red-300">{error}</p>
                </div>
            )}

            <div className="glass-card overflow-hidden">
                {loading ? (
                    <div className="flex items-center justify-center h-64">
                        <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                    </div>
                ) : flows.length === 0 ? (
                    <div className="p-10 text-center text-text-muted">
                        No OSINT-enriched flows yet. Generate traffic or upload a file that triggers anomalies with public IPs.
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full data-table">
                            <thead>
                                <tr>
                                    <th className="w-8"></th>
                                    <th>Source</th>
                                    <th>Time</th>
                                    <th>Source IP</th>
                                    <th>Dest IP</th>
                                    <th>OSINT IP</th>
                                    <th>AbuseIPDB</th>
                                    <th>VirusTotal</th>
                                    <th>Feeds</th>
                                    <th>Final</th>
                                    <th>Verdict</th>
                                    <th>Anomaly</th>
                                    <th>Classification</th>
                                </tr>
                            </thead>
                            <tbody>
                                {flows.map((f) => {
                                    const isExpanded = expandedRows[f.id];
                                    const cves = parseCveRefs(f.cve_refs);
                                    const vc = verdictColors[f.final_verdict] || verdictColors['OSINT Unavailable'];
                                    const rc = riskColors[f.risk_level] || 'text-text-muted';
                                    return (
                                        <tr key={f.id} className="group cursor-pointer" onClick={() => toggleRow(f.id)}>
                                            <td className="text-center px-2">
                                                {isExpanded
                                                    ? <ChevronUp size={14} className="text-primary inline-block" />
                                                    : <ChevronDown size={14} className="text-text-muted group-hover:text-primary inline-block transition-colors" />
                                                }
                                            </td>
                                            <td>
                                                <span className={`px-2 py-0.5 rounded-md text-small font-medium ${(f.monitor_type || 'passive') === 'active' ? 'bg-primary/20 text-primary border border-primary/30' : 'bg-surface text-text-muted border border-white/10'}`}>
                                                    {(f.monitor_type || 'passive') === 'active' ? 'Active' : 'Passive'}
                                                </span>
                                            </td>
                                            <td className="text-small text-text-muted whitespace-nowrap">
                                                {f.timestamp ? new Date(f.timestamp).toLocaleString() : '—'}
                                            </td>
                                            <td className="cell-ip">{f.src_ip || '—'}</td>
                                            <td className="cell-ip">{f.dst_ip || '—'}</td>
                                            <td className="cell-ip">{f.osint_ip || '—'}</td>
                                            <td className="text-small font-mono text-text-muted">
                                                {f.abuse_score == null ? '—' : `${Number(f.abuse_score).toFixed(0)}/100`}
                                            </td>
                                            <td className="text-small font-mono text-text-muted">
                                                {f.vt_score == null ? '—' : `${Number(f.vt_score).toFixed(0)}/100`}
                                            </td>
                                            <td className="text-small font-mono">
                                                {f.feed_score > 0
                                                    ? <span className="text-red-400 font-semibold">{Number(f.feed_score).toFixed(0)}/100</span>
                                                    : <span className="text-text-muted">Clean</span>
                                                }
                                            </td>
                                            <td className="text-small font-mono text-primary">
                                                {f.final_score == null ? '—' : Number(f.final_score).toFixed(1)}
                                            </td>
                                            <td>
                                                <span className={`px-2 py-0.5 rounded-md text-small font-medium ${vc.bg} ${vc.text} border ${vc.border}`}>
                                                    {f.final_verdict || '—'}
                                                </span>
                                            </td>
                                            <td className="text-small font-mono text-danger">
                                                {(Number(f.anomaly_score) || 0).toFixed(2)}
                                            </td>
                                            <td className="text-small font-semibold text-text-primary">
                                                {f.classification || '—'}
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>

                        {/* Expanded detail panels rendered outside the table for proper layout */}
                        {flows.map((f) => {
                            if (!expandedRows[f.id]) return null;
                            const cves = parseCveRefs(f.cve_refs);
                            const vc = verdictColors[f.final_verdict] || verdictColors['OSINT Unavailable'];
                            const rc = riskColors[f.risk_level] || 'text-text-muted';
                            return (
                                <div key={`detail-${f.id}`} className="mx-4 mb-4 p-5 rounded-xl bg-background/60 border border-white/10 animate-fade-in space-y-4">
                                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                                        {/* Classification & Threat Info */}
                                        <div className="space-y-3">
                                            <h4 className="text-small font-semibold text-text-muted uppercase tracking-wider flex items-center gap-2">
                                                <Shield size={14} className="text-primary" />
                                                Threat Classification
                                            </h4>
                                            <div className="space-y-2">
                                                <div className="flex items-center gap-2">
                                                    <span className="text-small text-text-muted">Classification:</span>
                                                    <span className="text-body font-semibold text-text-primary">{f.classification || '—'}</span>
                                                </div>
                                                <div className="flex items-center gap-2">
                                                    <span className="text-small text-text-muted">Threat Type:</span>
                                                    <span className="text-body font-medium text-text-primary">{f.threat_type || '—'}</span>
                                                </div>
                                                <div className="flex items-center gap-2">
                                                    <span className="text-small text-text-muted">Risk Level:</span>
                                                    <span className={`text-body font-semibold ${rc}`}>{f.risk_level || '—'}</span>
                                                </div>
                                                <div className="flex items-center gap-2">
                                                    <span className="text-small text-text-muted">Risk Score:</span>
                                                    <span className="text-body font-mono text-text-primary">{f.risk_score != null ? Number(f.risk_score).toFixed(3) : '—'}</span>
                                                </div>
                                                <div className="flex items-center gap-2">
                                                    <span className="text-small text-text-muted">Confidence:</span>
                                                    <span className="text-body font-mono text-text-primary">{f.confidence != null ? `${(Number(f.confidence) * 100).toFixed(1)}%` : '—'}</span>
                                                </div>
                                            </div>
                                            {f.classification_reason && (
                                                <div className="p-3 rounded-lg bg-surface border border-white/10">
                                                    <p className="text-small text-text-muted mb-1 font-medium">Reason</p>
                                                    <p className="text-small text-text-primary leading-relaxed">{f.classification_reason}</p>
                                                </div>
                                            )}
                                        </div>

                                        {/* CVE References */}
                                        <div className="space-y-3">
                                            <h4 className="text-small font-semibold text-text-muted uppercase tracking-wider flex items-center gap-2">
                                                <Bug size={14} className="text-danger" />
                                                CVE References
                                            </h4>
                                            {cves.length > 0 ? (
                                                <div className="space-y-2">
                                                    {cves.map((cve) => (
                                                        <div key={cve} className="flex items-center justify-between p-2.5 rounded-lg bg-surface border border-white/10 hover:border-primary/30 transition-colors">
                                                            <div className="flex items-center gap-2">
                                                                <AlertTriangle size={14} className="text-warning shrink-0" />
                                                                <span className="text-body font-mono font-semibold text-text-primary">{cve}</span>
                                                            </div>
                                                            <a
                                                                href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                                                                target="_blank"
                                                                rel="noopener noreferrer"
                                                                onClick={(e) => e.stopPropagation()}
                                                                className="flex items-center gap-1 text-small text-primary hover:opacity-80 transition-opacity"
                                                            >
                                                                <ExternalLink size={12} />
                                                                NVD
                                                            </a>
                                                        </div>
                                                    ))}
                                                </div>
                                            ) : (
                                                <div className="p-3 rounded-lg bg-surface border border-white/10">
                                                    <p className="text-small text-text-muted">No CVE references — behavioral/pattern-based detection.</p>
                                                </div>
                                            )}
                                        </div>

                                        {/* OSINT Details & Flow Metadata */}
                                        <div className="space-y-3">
                                            <h4 className="text-small font-semibold text-text-muted uppercase tracking-wider flex items-center gap-2">
                                                <Globe size={14} className="text-primary" />
                                                OSINT & Flow Details
                                            </h4>
                                            <div className="space-y-2">
                                                <div className="flex items-center justify-between">
                                                    <span className="text-small text-text-muted">AbuseIPDB</span>
                                                    <span className="text-body font-mono text-text-primary">
                                                        {f.abuse_ok ? (f.abuse_score != null ? `${Number(f.abuse_score).toFixed(0)}/100` : 'OK') : (f.osint_error || 'Unavailable')}
                                                    </span>
                                                </div>
                                                <div className="flex items-center justify-between">
                                                    <span className="text-small text-text-muted">VirusTotal</span>
                                                    <span className="text-body font-mono text-text-primary">
                                                        {f.vt_ok ? (f.vt_score != null ? `${Number(f.vt_score).toFixed(1)}/100` : 'OK') : 'Unavailable'}
                                                    </span>
                                                </div>
                                                <div className="flex items-center justify-between">
                                                    <span className="text-small text-text-muted">Threat Feeds</span>
                                                    {f.feed_score > 0 ? (
                                                        <span className="text-body font-mono font-semibold text-red-400">
                                                            {Number(f.feed_score).toFixed(0)}/100
                                                        </span>
                                                    ) : (
                                                        <span className="text-body font-mono text-green-400">Clean</span>
                                                    )}
                                                </div>
                                                {f.feed_sources && (
                                                    <div className="flex items-start justify-between">
                                                        <span className="text-small text-text-muted">Matched Feeds</span>
                                                        <span className="text-small font-medium text-red-300 text-right max-w-[60%]">
                                                            {f.feed_sources}
                                                        </span>
                                                    </div>
                                                )}
                                                <div className="flex items-center justify-between pt-1 border-t border-white/10">
                                                    <span className="text-small text-text-muted">Final Score</span>
                                                    <span className="text-body font-mono font-semibold text-primary">
                                                        {f.final_score != null ? Number(f.final_score).toFixed(1) : '—'}
                                                    </span>
                                                </div>
                                                <div className="flex items-center justify-between">
                                                    <span className="text-small text-text-muted">Verdict</span>
                                                    <span className={`text-body font-semibold ${(verdictColors[f.final_verdict] || {}).text || 'text-text-primary'}`}>
                                                        {f.final_verdict || '—'}
                                                    </span>
                                                </div>
                                            </div>
                                            <div className="pt-2 border-t border-white/10 space-y-1.5">
                                                <p className="text-small text-text-muted font-medium flex items-center gap-1.5">
                                                    <Activity size={12} />
                                                    Flow Metadata
                                                </p>
                                                <div className="grid grid-cols-2 gap-x-4 gap-y-1">
                                                    <span className="text-small text-text-muted">Protocol</span>
                                                    <span className="text-small font-mono text-text-primary">{f.protocol || '—'}</span>
                                                    <span className="text-small text-text-muted">Src Port</span>
                                                    <span className="text-small font-mono text-text-primary">{f.src_port ?? '—'}</span>
                                                    <span className="text-small text-text-muted">Dst Port</span>
                                                    <span className="text-small font-mono text-text-primary">{f.dst_port ?? '—'}</span>
                                                    <span className="text-small text-text-muted">Duration</span>
                                                    <span className="text-small font-mono text-text-primary">{f.duration != null ? `${Number(f.duration).toLocaleString()} µs` : '—'}</span>
                                                    <span className="text-small text-text-muted">Bytes/s</span>
                                                    <span className="text-small font-mono text-text-primary">{f.flow_bytes_per_sec != null ? Number(f.flow_bytes_per_sec).toLocaleString(undefined, { maximumFractionDigits: 0 }) : '—'}</span>
                                                    <span className="text-small text-text-muted">Pkts/s</span>
                                                    <span className="text-small font-mono text-text-primary">{f.flow_packets_per_sec != null ? Number(f.flow_packets_per_sec).toLocaleString(undefined, { maximumFractionDigits: 0 }) : '—'}</span>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                )}

                {flows.length > 0 && (
                    <div className="flex items-center justify-between px-6 py-3 border-t border-white/10">
                        <p className="text-small text-text-muted">
                            Page {page} / {totalPages}
                        </p>
                        <div className="flex items-center gap-2">
                            <button
                                onClick={() => setPage(Math.max(1, page - 1))}
                                disabled={page === 1}
                                className="p-2 rounded-[10px] border border-white/10 text-text-muted hover:text-text-primary hover:border-primary/50 disabled:opacity-30 transition-colors"
                            >
                                <ChevronLeft size={14} />
                            </button>
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

