import { useState, useEffect } from 'react';
import { getSBOM, getVulnerabilities, analyzeSBOMFile, downloadSBOM } from '../services/api';
import { SectionHeading } from '../components/Primitives';
import {
    Shield,
    Download,
    AlertTriangle,
    Package,
    Bug,
    CheckCircle2,
    ExternalLink,
    FileUp,
    Loader2,
    Lightbulb,
    ChevronDown,
    ChevronUp,
    Info,
    Sparkles,
} from 'lucide-react';
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement } from 'chart.js';
import { Doughnut, Bar } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement);

const ALLOWED_FILES = ['.txt', '.json', 'package-lock.json', 'yarn.lock', 'Pipfile', 'poetry.lock', 'Gemfile', 'Gemfile.lock', 'go.mod', 'Cargo.toml', 'Cargo.lock'];

export default function SBOMSecurity() {
    const [sbom, setSbom] = useState(null);
    const [vulns, setVulns] = useState(null);
    const [loading, setLoading] = useState(true);
    const [analyzing, setAnalyzing] = useState(false);
    const [error, setError] = useState({ sbom: null, vulns: null });
    const [activeTab, setActiveTab] = useState('overview');
    const [selectedSeverityFilter, setSelectedSeverityFilter] = useState('');
    const [hoveredSeverity, setHoveredSeverity] = useState('');
    const [file, setFile] = useState(null);
    const [expandedTips, setExpandedTips] = useState({});
    const [showWhatIsSbom, setShowWhatIsSbom] = useState(false);

    const fetchSecurity = async () => {
        setLoading(true);
        setError({ sbom: null, vulns: null });
        try {
            const [sbomResult, vulnResult] = await Promise.allSettled([getSBOM(), getVulnerabilities()]);
            if (sbomResult.status === 'fulfilled') setSbom(sbomResult.value.data);
            else setError((e) => ({ ...e, sbom: sbomResult.reason?.message || 'SBOM unavailable' }));
            if (vulnResult.status === 'fulfilled') setVulns(vulnResult.value.data);
            else setError((e) => ({ ...e, vulns: vulnResult.reason?.message || 'Vulnerabilities unavailable' }));
        } catch (err) {
            console.error('Failed to fetch security data:', err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchSecurity();
    }, []);

    const hasUserData = !!vulns?.scanner || (sbom?.total_components ?? 0) > 0;

    const handleFileSelect = (e) => {
        const f = e.target.files?.[0];
        if (f) {
            setFile(f);
            setError({ sbom: null, vulns: null });
        }
    };

    const handleAnalyze = async () => {
        if (!file) return;
        setAnalyzing(true);
        setError({ sbom: null, vulns: null });
        try {
            const { data } = await analyzeSBOMFile(file);
            setSbom({
                total_components: data.total_components,
                components: data.components,
                format: 'CycloneDX',
                metadata: { timestamp: data.scan_timestamp, component: { name: data.filename } },
            });
            setVulns({
                total_vulnerabilities: data.total_vulnerabilities,
                dependencies_scanned: data.dependencies_scanned ?? data.total_components ?? 0,
                vulnerable_packages_count: data.vulnerable_packages_count ?? 0,
                component_scan_status: data.component_scan_status || [],
                severity_distribution: data.severity_distribution || {},
                vulnerabilities: data.vulnerabilities || [],
                scan_timestamp: data.scan_timestamp,
                scanner: data.scanner || 'CycloneDX',
                warnings: data.warnings || [],
            });
        } catch (err) {
            setError({ sbom: err.response?.data?.detail || 'Analysis failed', vulns: null });
        } finally {
            setAnalyzing(false);
        }
    };

    const toggleTips = (id) => {
        setExpandedTips((p) => ({ ...p, [id]: !p[id] }));
    };

    const severityColors = {
        Critical: { bg: '#ef444440', border: '#ef4444', text: 'text-red-400', badge: 'badge-critical' },
        High: { bg: '#f59e0b40', border: '#f59e0b', text: 'text-orange-400', badge: 'badge-high' },
        Medium: { bg: '#8b5cf640', border: '#8b5cf6', text: 'text-purple-400', badge: 'badge-medium' },
        Low: { bg: '#10b98140', border: '#10b981', text: 'text-green-400', badge: 'badge-low' },
        Unknown: { bg: '#64748b40', border: '#64748b', text: 'text-slate-400', badge: 'badge-unknown' },
    };
    const allVulns = vulns?.vulnerabilities || [];
    const severityToVulnNames = allVulns.reduce((acc, v) => {
        const sev = v?.severity || 'Unknown';
        if (!acc[sev]) acc[sev] = [];
        acc[sev].push(v?.id || v?.package || 'Unknown');
        return acc;
    }, {});
    const hoveredNames = hoveredSeverity ? (severityToVulnNames[hoveredSeverity] || []) : [];
    const filteredVulns = allVulns.filter((v) => {
        if (!selectedSeverityFilter) return true;
        if (selectedSeverityFilter === 'Critical/High') return v?.severity === 'Critical' || v?.severity === 'High';
        return v?.severity === selectedSeverityFilter;
    });
    const metadata = sbom?.metadata || {};
    const metadataComponent = metadata?.component || {};
    const metadataTools = metadata?.tools || [];

    return (
        <div className="space-y-8">
            {/* Header */}
            <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
                <div>
                    <SectionHeading title="SBOM Security" />
                    <p className="text-body text-text-primary mt-2 max-w-2xl leading-relaxed">
                        A <strong className="text-primary">Software Bill of Materials (SBOM)</strong> is a list of every dependency in your project—like an ingredient list for your code. We parse your dependency file, build that list, then check each package against known vulnerability databases so you can see what’s safe and what needs updating.
                    </p>
                    <button
                        type="button"
                        onClick={() => setShowWhatIsSbom((v) => !v)}
                        className="mt-3 flex items-center gap-2 text-small font-medium text-primary hover:opacity-90 transition-opacity"
                    >
                        <Info size={14} />
                        {showWhatIsSbom ? 'Hide how it works' : 'How it works'}
                        <ChevronDown size={14} className={`transition-transform ${showWhatIsSbom ? 'rotate-180' : ''}`} />
                    </button>
                    {showWhatIsSbom && (
                        <div className="mt-3 p-4 rounded-xl bg-primary/10 border border-primary/20 text-body text-text-primary space-y-2 animate-fade-in">
                            <p><strong className="text-text-primary">1. Upload</strong> — Choose a dependency file (e.g. requirements.txt, package.json).</p>
                            <p><strong className="text-text-primary">2. Parse</strong> — We extract package name, version, and ecosystem (PyPI, npm, etc.).</p>
                            <p><strong className="text-text-primary">3. Build SBOM</strong> — We create a standard component list (CycloneDX format).</p>
                            <p><strong className="text-text-primary">4. Check vulnerabilities</strong> — Each component is checked against the OSV database (CVE, GitHub Advisories, and more).</p>
                            <p><strong className="text-text-primary">5. Report</strong> — You get severity, fixed versions, upgrade commands, and advisory links.</p>
                        </div>
                    )}
                </div>
                {hasUserData && (
                    <a
                        href={downloadSBOM()}
                        download="sbom.json"
                        className="px-4 py-2.5 rounded-[10px] border border-primary text-primary text-body font-medium hover:bg-primary/10 transition-colors flex items-center gap-2 shrink-0"
                    >
                        <Download size={16} />
                        Download SBOM
                    </a>
                )}
            </div>

            {/* Upload Zone — interactive */}
            <div
                role="button"
                tabIndex={0}
                onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') document.getElementById('sbom-file-input').click(); }}
                className="glass-card p-6 sm:p-8 border-2 border-dashed border-white/12 hover:border-primary/50 hover:bg-primary/5 transition-colors cursor-pointer rounded-xl group drop-zone"
                onClick={() => document.getElementById('sbom-file-input').click()}
            >
                <input
                    id="sbom-file-input"
                    type="file"
                    accept=".txt,.json,Pipfile,poetry.lock,Gemfile,Gemfile.lock,go.mod,Cargo.toml,Cargo.lock,yarn.lock"
                    onChange={handleFileSelect}
                    className="hidden"
                />
                <div className="flex flex-col sm:flex-row items-center gap-5">
                    <div className="p-4 rounded-xl bg-primary/10 border border-primary/20 group-hover:border-primary/35 transition-colors">
                        <FileUp size={28} className="text-primary" />
                    </div>
                    <div className="flex-1 text-center sm:text-left">
                        <p className="text-body font-semibold text-text-primary flex items-center gap-2 justify-center sm:justify-start">
                            {file ? (
                                <>
                                    <CheckCircle2 size={18} className="text-success shrink-0" />
                                    {file.name}
                                </>
                            ) : (
                                <>
                                    <Sparkles size={18} className="text-primary shrink-0" />
                                    Drop your dependency file here or click to browse
                                </>
                            )}
                        </p>
                        <p className="text-small text-text-muted mt-1.5">
                            Supported: requirements.txt, package.json, package-lock.json, yarn.lock, Pipfile, poetry.lock, Gemfile, Gemfile.lock, go.mod, Cargo.toml, Cargo.lock
                        </p>
                    </div>
                    <button
                        onClick={(e) => { e.stopPropagation(); handleAnalyze(); }}
                        disabled={!file || analyzing}
                        className="px-6 py-3 rounded-[10px] bg-primary text-white text-body font-semibold hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 transition-opacity shrink-0"
                    >
                        {analyzing ? (
                            <>
                                <Loader2 size={16} className="animate-spin" />
                                Scanning...
                            </>
                        ) : (
                            <>
                                <Shield size={16} />
                                Analyze
                            </>
                        )}
                    </button>
                </div>
            </div>

            {(error.sbom || error.vulns) && (
                <div className="glass-card p-4 border-warning/30 bg-warning/10 flex items-center gap-3">
                    <AlertTriangle size={18} className="text-warning shrink-0" />
                    <div className="text-body text-text-primary">
                        {error.sbom && <span>{error.sbom}. </span>}
                        {error.vulns && <span>Vulnerabilities: {error.vulns}. </span>}
                    </div>
                    <button
                        onClick={fetchSecurity}
                        className="px-4 py-2 rounded-[10px] border border-primary text-primary text-small font-medium hover:bg-primary/10"
                    >
                        Retry
                    </button>
                </div>
            )}

            {vulns?.warnings?.length > 0 && (
                <div className="glass-card p-4 border-primary/20 bg-primary/5 flex items-start gap-3">
                    <AlertTriangle size={18} className="text-primary shrink-0 mt-0.5" />
                    <div className="text-body text-text-primary">
                        {vulns.warnings.map((w, i) => (
                            <p key={i}>{w}</p>
                        ))}
                    </div>
                </div>
            )}

            {loading && !sbom && !vulns ? (
                <div className="flex items-center justify-center h-96">
                    <Loader2 size={32} className="animate-spin text-primary" />
                </div>
            ) : !hasUserData ? (
                <div className="glass-card p-10 sm:p-12 text-center rounded-xl border border-white/10">
                    <div className="inline-flex p-4 rounded-xl bg-primary/10 border border-primary/20 mb-4">
                        <Package size={48} className="text-primary" />
                    </div>
                    <h3 className="text-h2 font-semibold text-text-primary mb-2">Ready to scan</h3>
                    <p className="text-body text-text-muted max-w-md mx-auto">
                        Pick a dependency file above and click <strong className="text-primary">Analyze</strong>. You’ll get a component list, vulnerability results, and upgrade suggestions.
                    </p>
                </div>
            ) : (
                <>
                    {/* KPIs */}
                    <h2 className="section-header">Security Overview</h2>
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                        <button
                            type="button"
                            onClick={() => { setActiveTab('components'); setSelectedSeverityFilter(''); }}
                            className="glass-card p-6 border-primary/20 text-left hover:border-primary/35 transition-colors"
                        >
                            <div className="flex items-center gap-3">
                                <Package size={18} className="text-primary" />
                                <div>
                                    <p className="text-small text-text-muted">Components</p>
                                    <p className="text-2xl font-bold text-text-primary">{sbom?.total_components || 0}</p>
                                </div>
                            </div>
                        </button>
                        <button
                            type="button"
                            onClick={() => { setActiveTab('vulnerabilities'); setSelectedSeverityFilter(''); }}
                            className="glass-card p-6 border-danger/20 text-left hover:border-danger/35 transition-colors"
                        >
                            <div className="flex items-center gap-3">
                                <Bug size={18} className="text-danger" />
                                <div>
                                    <p className="text-small text-text-muted">Vulnerabilities</p>
                                    <p className="text-2xl font-bold text-text-primary">{vulns?.total_vulnerabilities || 0}</p>
                                </div>
                            </div>
                        </button>
                        <button
                            type="button"
                            onClick={() => { setActiveTab('vulnerabilities'); setSelectedSeverityFilter('Critical/High'); }}
                            className="glass-card p-6 border-warning/20 text-left hover:border-warning/35 transition-colors"
                        >
                            <div className="flex items-center gap-3">
                                <AlertTriangle size={18} className="text-warning" />
                                <div>
                                    <p className="text-small text-text-muted">Critical/High</p>
                                    <p className="text-2xl font-bold text-text-primary">
                                        {(vulns?.severity_distribution?.Critical || 0) + (vulns?.severity_distribution?.High || 0)}
                                    </p>
                                </div>
                            </div>
                        </button>
                        <div className="glass-card p-6 border-success/20">
                            <div className="flex items-center gap-3">
                                <CheckCircle2 size={18} className="text-success" />
                                <div>
                                    <p className="text-small text-text-muted">Scanner</p>
                                    <p className="text-lg font-bold text-text-primary">{vulns?.scanner || 'OSV'}</p>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Tabs */}
                    <div className="flex gap-2 border-b border-white/10 pb-0">
                        {['overview', 'components', 'scan-status', 'vulnerabilities'].map((tab) => (
                            <button
                                key={tab}
                                onClick={() => setActiveTab(tab)}
                                className={`px-4 py-2 text-body font-medium capitalize transition-colors border-b-2 -mb-px ${activeTab === tab ? 'text-primary border-primary' : 'text-text-muted border-transparent hover:text-text-primary'}`}
                            >
                                {tab === 'scan-status' ? 'Scan status' : tab}
                            </button>
                        ))}
                    </div>

                    {/* Scan status per package */}
                    {activeTab === 'scan-status' && (
                        <div className="glass-card overflow-hidden animate-fade-in">
                            <div className="p-6 border-b border-white/10">
                                <h3 className="text-h2 font-semibold text-text-primary">Scan status per package</h3>
                                <p className="text-small text-text-muted mt-1">Each dependency and whether vulnerabilities were found.</p>
                            </div>
                            <div className="overflow-x-auto">
                                <table className="w-full data-table">
                                    <thead>
                                        <tr>
                                            <th>#</th>
                                            <th>Package</th>
                                            <th>Version</th>
                                            <th>Ecosystem</th>
                                            <th>Status</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {(vulns?.component_scan_status || []).map((s, i) => (
                                            <tr key={i}>
                                                <td className="font-mono text-small text-primary">#{i + 1}</td>
                                                <td className="font-medium text-text-primary text-body">{s.name}</td>
                                                <td>
                                                    <span className="px-2 py-0.5 rounded-md bg-surface text-small font-mono text-primary border border-white/10">{s.version}</span>
                                                </td>
                                                <td className="text-small text-text-muted">{s.ecosystem || '—'}</td>
                                                <td>
                                                    {s.scanned ? (
                                                        s.vulnerable ? (
                                                            <span className={`text-small font-medium ${severityColors[s.max_severity]?.text || 'text-warning'}`}>
                                                                {s.vuln_count} vulnerability{s.vuln_count !== 1 ? 's' : ''} ({s.max_severity})
                                                            </span>
                                                        ) : (
                                                            <span className="text-small text-success">No vulnerabilities</span>
                                                        )
                                                    ) : (
                                                        <span className="text-small text-text-muted">Not scanned (unknown version)</span>
                                                    )}
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                            {(vulns?.component_scan_status || []).length === 0 && (
                                <div className="p-8 text-center text-text-muted text-body">No scan status. Run an analysis first.</div>
                            )}
                        </div>
                    )}

                    {/* Overview */}
                    {activeTab === 'overview' && (
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 animate-fade-in">
                            <div className="glass-card p-6">
                                <h3 className="text-h2 font-semibold text-text-primary mb-4">Vulnerability Severity</h3>
                                <div className="h-64 flex items-center justify-center">
                                    {(vulns?.total_vulnerabilities ?? 0) === 0 ? (
                                        <div className="flex flex-col items-center justify-center gap-4">
                                            <div className="w-32 h-32 rounded-full bg-success/20 border-2 border-success/50 flex items-center justify-center">
                                                <span className="text-2xl font-bold text-success">Safe</span>
                                            </div>
                                            <p className="text-body text-text-primary text-center max-w-xs">
                                                No vulnerabilities found. Your packages are good to go.
                                            </p>
                                        </div>
                                    ) : (
                                        <Doughnut
                                            data={{
                                                labels: Object.keys(vulns?.severity_distribution || {}),
                                                datasets: [{
                                                    data: Object.values(vulns?.severity_distribution || {}),
                                                    backgroundColor: (Object.keys(vulns?.severity_distribution || {})).map((sev) =>
                                                        sev === 'Unknown' ? '#A78BFA99' : (severityColors[sev]?.bg || '#A78BFA99')
                                                    ),
                                                    borderColor: (Object.keys(vulns?.severity_distribution || {})).map((sev) =>
                                                        sev === 'Unknown' ? '#A78BFA' : (severityColors[sev]?.border || '#A78BFA')
                                                    ),
                                                    borderWidth: 1,
                                                    spacing: 2,
                                                    borderRadius: 4,
                                                }],
                                            }}
                                            options={{
                                                responsive: true,
                                                maintainAspectRatio: false,
                                                cutout: '60%',
                                                onHover: (event, elements) => {
                                                    if (elements?.length) {
                                                        const idx = elements[0].index;
                                                        setHoveredSeverity(Object.keys(vulns?.severity_distribution || {})[idx] || '');
                                                    } else setHoveredSeverity('');
                                                },
                                                onClick: (_, elements) => {
                                                    if (elements?.length) {
                                                        const sev = Object.keys(vulns?.severity_distribution || {})[elements[0].index];
                                                        setActiveTab('vulnerabilities');
                                                        setSelectedSeverityFilter(sev);
                                                    }
                                                },
                                                plugins: { legend: { position: 'right', labels: { color: '#B0B5BA', font: { size: 13 } } } },
                                            }}
                                        />
                                    )}
                                </div>
                            </div>
                            <div className="glass-card p-6">
                                <h3 className="text-h2 font-semibold text-text-primary mb-4">Severity Breakdown</h3>
                                <div className="space-y-4 mt-4">
                                    {Object.entries(vulns?.severity_distribution || {}).map(([sev, count]) => {
                                        const total = vulns?.total_vulnerabilities || 1;
                                        const pct = Math.round((count / total) * 100);
                                        const sc = severityColors[sev];
                                        return (
                                            <button
                                                key={sev}
                                                type="button"
                                                onClick={() => { setActiveTab('vulnerabilities'); setSelectedSeverityFilter(sev); }}
                                                className="w-full text-left group"
                                            >
                                                <div className="flex justify-between text-small mb-1.5">
                                                    <span className={`font-medium ${sc?.text}`}>{sev}</span>
                                                    <span className="text-text-muted">{count} ({pct}%)</span>
                                                </div>
                                                <div className="h-3 rounded-full bg-background overflow-hidden">
                                                    <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, backgroundColor: sc?.border }} />
                                                </div>
                                            </button>
                                        );
                                    })}
                                </div>
                                <div className="mt-6 p-4 rounded-xl bg-background/60 border border-white/10">
                                    <p className="text-small text-text-muted mb-1">Scanner</p>
                                    <p className="text-body font-medium text-text-primary">{vulns?.scanner || 'OSV'}</p>
                                    <p className="text-small text-text-muted mt-2 mb-1">Last Scan</p>
                                    <p className="text-body font-medium text-text-primary">
                                        {vulns?.scan_timestamp ? new Date(vulns.scan_timestamp).toLocaleString() : 'N/A'}
                                    </p>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Components */}
                    {activeTab === 'components' && (
                        <div className="glass-card overflow-hidden animate-fade-in">
                            <div className="overflow-x-auto">
                                <table className="w-full data-table">
                                    <thead>
                                        <tr>
                                            <th>#</th>
                                            <th>Package Name</th>
                                            <th>Version</th>
                                            <th>Ecosystem</th>
                                            <th>Type</th>
                                            <th>PURL</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {(sbom?.components || []).map((comp, i) => (
                                            <tr key={i}>
                                                <td className="font-mono text-small text-primary">#{i + 1}</td>
                                                <td className="font-medium text-text-primary text-body">{comp.name}</td>
                                                <td>
                                                    <span className="px-2 py-0.5 rounded-md bg-surface text-small font-mono text-primary border border-white/10">{comp.version}</span>
                                                </td>
                                                <td className="text-small text-text-muted">{comp.ecosystem || '—'}</td>
                                                <td className="text-small text-text-muted capitalize">{comp.type || 'library'}</td>
                                                <td className="text-small text-text-muted font-mono max-w-xs truncate">{comp.purl || '—'}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}

                    {/* Vulnerabilities with Tips */}
                    {activeTab === 'vulnerabilities' && (
                        <div className="space-y-3 animate-fade-in">
                            {(vulns?.total_vulnerabilities === 0 && (sbom?.total_components ?? 0) > 0) && (
                                <div className="glass-card p-4 border border-success/20 bg-success/10">
                                    <p className="text-body text-success">
                                        No vulnerabilities found. Dependencies scanned: {vulns?.dependencies_scanned ?? 0}. This confirms the scan worked.
                                    </p>
                                </div>
                            )}
                            <div className="flex items-center justify-between">
                                <p className="text-small text-text-muted">
                                    Showing {filteredVulns.length} vulnerabilities
                                    {selectedSeverityFilter ? ` (${selectedSeverityFilter})` : ''}
                                </p>
                                {selectedSeverityFilter && (
                                    <button
                                        type="button"
                                        onClick={() => setSelectedSeverityFilter('')}
                                        className="px-3 py-2 rounded-[10px] border border-primary text-primary text-small font-medium hover:bg-primary/10"
                                    >
                                        Clear Filter
                                    </button>
                                )}
                            </div>
                            {filteredVulns.map((v) => {
                                const sc = severityColors[v.severity];
                                const isExpanded = expandedTips[v.id];
                                const tips = v.tips || [];
                                return (
                                    <div
                                        key={`${v.id}-${v.package}`}
                                        className={`glass-card p-6 border ${sc?.badge === 'badge-critical' ? 'border-danger/20' : 'border-white/10'}`}
                                    >
                                        <div className="flex items-start justify-between">
                                            <div className="flex items-start gap-3 flex-1">
                                                <Bug size={18} className={`${sc?.text} mt-0.5`} />
                                                <div className="flex-1 min-w-0">
                                                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                                                        <span className="text-body font-bold text-text-primary font-mono">{v.id}</span>
                                                        <span className={`px-2 py-0.5 rounded-md text-small font-medium ${sc?.badge}`}>{v.severity}</span>
                                                    </div>
                                                    <p className="text-body text-text-primary mb-2">{v.description}</p>
                                                    <div className="flex items-center gap-4 text-small text-text-muted flex-wrap">
                                                        <span>
                                                            <span className="text-text-muted">Package:</span>{' '}
                                                            <span className="font-mono text-text-primary">{v.package} v{v.version}</span>
                                                        </span>
                                                        <span>
                                                            <span className="text-text-muted">Fixed in:</span>{' '}
                                                            <span className="font-mono text-success">v{v.fixed_in}</span>
                                                        </span>
                                                        {v.fixed_in && v.fixed_in !== 'Not specified' && (
                                                            <span className="text-primary">
                                                                Upgrade: {v.package} → {v.fixed_in}
                                                            </span>
                                                        )}
                                                    </div>
                                                    {/* Tips */}
                                                    {tips.length > 0 && (
                                                        <div className="mt-3">
                                                            <button
                                                                type="button"
                                                                onClick={() => toggleTips(v.id)}
                                                                className="flex items-center gap-2 text-small font-medium text-primary hover:opacity-90"
                                                            >
                                                                <Lightbulb size={14} />
                                                                {tips.length} Tips to fix this
                                                                {isExpanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                                                            </button>
                                                            {isExpanded && (
                                                                <ul className="mt-2 pl-5 space-y-1.5 text-small text-text-primary list-disc">
                                                                    {tips.map((tip, idx) => (
                                                                        <li key={idx}>{tip}</li>
                                                                    ))}
                                                                </ul>
                                                            )}
                                                        </div>
                                                    )}
                                                </div>
                                            </div>
                                            <a
                                                href={v.url || `https://nvd.nist.gov/vuln/detail/${v.id}`}
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                title="Advisory (CVE / GitHub / OSV)"
                                                className="p-2 rounded-[10px] hover:bg-white/5 text-text-muted hover:text-primary transition-colors shrink-0 flex items-center gap-1 text-small"
                                            >
                                                <ExternalLink size={14} />
                                                Advisory
                                            </a>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    )}

                    {/* SBOM Metadata */}
                    {(metadata?.timestamp || metadata?.component) && (
                        <div className="glass-card p-6">
                            <h3 className="text-h2 font-semibold text-text-primary mb-4">SBOM Metadata</h3>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                <div className="p-4 rounded-xl bg-background/60 border border-white/10">
                                    <p className="text-small text-text-muted mb-1">Timestamp</p>
                                    <p className="text-body text-text-primary font-mono">{metadata?.timestamp || '—'}</p>
                                </div>
                                <div className="p-4 rounded-xl bg-background/60 border border-white/10">
                                    <p className="text-small text-text-muted mb-1">Component</p>
                                    <p className="text-body text-text-primary">{metadataComponent?.name || '—'} {metadataComponent?.version ? `(${metadataComponent.version})` : ''}</p>
                                </div>
                            </div>
                        </div>
                    )}
                </>
            )}
        </div>
    );
}
