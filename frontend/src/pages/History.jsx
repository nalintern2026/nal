import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getHistory } from '../services/api';
import { SectionHeading, TogglePills } from '../components/Primitives';
import {
    History as HistoryIcon,
    FileText,
    ChevronRight,
    AlertTriangle,
    Loader2,
    Clock,
    HardDrive,
} from 'lucide-react';

export default function History() {
    const [analyses, setAnalyses] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [monitorView, setMonitorView] = useState(''); // '' = combined, 'passive', 'active'
    const navigate = useNavigate();

    useEffect(() => {
        loadHistory();
    }, [monitorView]);

    const loadHistory = async () => {
        setLoading(true);
        setError(null);
        try {
            const { data } = await getHistory(100, monitorView || undefined);
            setAnalyses(data.analyses || []);
        } catch (err) {
            setError(err.response?.data?.detail || 'Failed to load history.');
        } finally {
            setLoading(false);
        }
    };

    const formatSize = (bytes) => {
        if (bytes == null || bytes === undefined) return '—';
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    };

    const formatDate = (iso) => {
        if (!iso) return '—';
        try {
            const d = new Date(iso);
            return d.toLocaleString();
        } catch {
            return iso;
        }
    };

    if (loading) {
        return (
            <div className="flex items-center justify-center min-h-[300px]">
                <Loader2 size={32} className="animate-spin text-primary" />
            </div>
        );
    }

    return (
        <div className="max-w-4xl mx-auto space-y-8">
            <div className="flex items-center justify-between gap-4 flex-wrap mb-8">
                <SectionHeading
                    title="Analysis History"
                    subtitle={`View past analyses. Click any report to open full details.${monitorView === 'active' ? ' Showing: Active monitoring sessions.' : monitorView === 'passive' ? ' Showing: Passive (upload) analyses.' : ' Showing: All analyses (combined).'}`}
                />
                <div className="flex items-center gap-2">
                    <span className="text-small font-medium text-text-muted uppercase tracking-wider">View</span>
                    <TogglePills
                        value={monitorView}
                        onChange={setMonitorView}
                        options={[
                            { value: '', label: 'Combined' },
                            { value: 'active', label: 'Active' },
                            { value: 'passive', label: 'Passive' },
                        ]}
                    />
                </div>
            </div>

            {error && (
                <div className="glass-card p-4 border-danger/30 bg-danger/10">
                    <div className="flex items-center gap-3">
                        <AlertTriangle size={20} className="text-danger" />
                        <p className="text-body text-red-300">{error}</p>
                    </div>
                </div>
            )}

            {analyses.length === 0 && !loading && (
                <div className="glass-card p-12 text-center">
                    <HistoryIcon size={48} className="mx-auto text-text-muted mb-4" />
                    <p className="text-text-primary">No analysis history yet.</p>
                    <p className="text-body text-text-muted mt-2">Upload and analyze files on the Upload page to see them here.</p>
                </div>
            )}

            <h2 className="section-header">Past Analyses</h2>
            <div className="space-y-3">
                {analyses.map((a) => (
                    <button
                        key={a.analysis_id}
                        type="button"
                        onClick={() => navigate(`/history/${a.analysis_id}`)}
                        className="w-full glass-card p-6 flex items-center justify-between gap-4 text-left hover:border-primary/35 transition-colors group"
                    >
                        <div className="flex items-center gap-4 min-w-0 flex-1">
                            <div className="p-2 rounded-xl bg-primary/10 flex-shrink-0">
                                <FileText size={20} className="text-primary" />
                            </div>
                            <div className="min-w-0 flex-1">
                                <p className="text-body font-medium text-text-primary truncate group-hover:text-primary">{a.filename || 'Unknown'}</p>
                                <div className="flex flex-wrap gap-x-4 gap-y-1 mt-1.5 text-small text-text-muted">
                                    <span className="flex items-center gap-1">
                                        <Clock size={12} />
                                        {formatDate(a.uploaded_at)}
                                    </span>
                                    <span className="flex items-center gap-1">
                                        <HardDrive size={12} />
                                        {formatSize(a.file_size)}
                                    </span>
                                    <span className={`px-2 py-0.5 rounded text-small font-medium ${(a.monitor_type || '').toLowerCase() === 'active' ? 'bg-primary/20 text-primary border border-primary/30' : 'bg-surface text-text-muted border border-white/10'}`}>
                                        {(a.monitor_type || 'Static Monitoring').toLowerCase() === 'active' ? 'Active' : 'Passive'}
                                    </span>
                                </div>
                            </div>
                        </div>
                        <div className="flex items-center gap-4 flex-shrink-0">
                            <div className="text-right">
                                <p className="text-small text-text-muted uppercase">Flows</p>
                                <p className="text-body font-semibold text-text-primary">{a.total_flows ?? 0}</p>
                            </div>
                            <div className="text-right">
                                <p className="text-small text-text-muted uppercase">Anomalies</p>
                                <p className="text-body font-semibold text-warning">{a.anomaly_count ?? 0}</p>
                            </div>
                            <div className="text-right">
                                <p className="text-small text-text-muted uppercase">Avg Risk</p>
                                <p className="text-body font-semibold text-text-primary">{Math.round((a.avg_risk_score ?? 0) * 100)}%</p>
                            </div>
                            <ChevronRight size={20} className="text-text-muted group-hover:text-primary" />
                        </div>
                    </button>
                ))}
            </div>
        </div>
    );
}
