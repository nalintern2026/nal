import { useState, useEffect } from 'react';
import {
    startRealtimeMonitor,
    stopRealtimeMonitor,
    getRealtimeStatus,
    getRealtimeInterfaces,
} from '../services/api';
import {
    Radio,
    Play,
    Square,
    Loader2,
    AlertTriangle,
    CheckCircle2,
    Wifi,
    Activity,
} from 'lucide-react';
import { SectionHeading, StatusBanner } from '../components/Primitives';

export default function ActiveMonitoring() {
    const [status, setStatus] = useState(null);
    const [interfaces, setInterfaces] = useState([]);
    const [selectedInterface, setSelectedInterface] = useState('');
    const [loading, setLoading] = useState(true);
    const [actionLoading, setActionLoading] = useState(false);
    const [error, setError] = useState(null);
    const [lastUpdated, setLastUpdated] = useState(null);

    const fetchStatus = async () => {
        try {
            const { data } = await getRealtimeStatus();
            setStatus(data);
            setError(null);
            setLastUpdated(new Date().toLocaleTimeString());
            if (data.running && data.interface) {
                const runningIface = data.interface.replace(' (default)', '').replace('lo (default)', '');
                if (runningIface && runningIface !== 'lo (default)') {
                    setSelectedInterface(runningIface);
                }
            }
        } catch (err) {
            setError(err.response?.data?.message || 'Failed to fetch status');
        }
    };

    const fetchInterfaces = async () => {
        try {
            const { data } = await getRealtimeInterfaces();
            const ifaces = data.interfaces || [];
            const preferred = ['lo', 'enp0s31f6', 'eth0', 'wlan0'];
            ifaces.sort((a, b) => {
                const ai = preferred.indexOf(a);
                const bi = preferred.indexOf(b);
                if (ai !== -1 && bi !== -1) return ai - bi;
                if (ai !== -1) return -1;
                if (bi !== -1) return 1;
                return a.localeCompare(b);
            });
            setInterfaces(ifaces);
            if (!selectedInterface && ifaces.length) {
                setSelectedInterface(ifaces[0] || '');
            }
        } catch (err) {
            setInterfaces(['lo', 'eth0', 'wlan0']);
        }
    };

    useEffect(() => {
        const load = async () => {
            setLoading(true);
            setError(null);
            await Promise.all([fetchStatus(), fetchInterfaces()]);
            setLoading(false);
        };
        load();
    }, []);

    // Refresh every 2s when capturing (live updates), 5s when stopped
    useEffect(() => {
        const intervalMs = status?.running ? 2000 : 5000;
        const interval = setInterval(fetchStatus, intervalMs);
        return () => clearInterval(interval);
    }, [status?.running]);

    const handleStart = async () => {
        setActionLoading(true);
        setError(null);
        try {
            const { data } = await startRealtimeMonitor(selectedInterface);
            if (data.status === 'error') {
                setError(data.message || 'Failed to start');
            } else {
                await fetchStatus();
            }
        } catch (err) {
            setError(err.response?.data?.message || 'Failed to start monitoring');
        } finally {
            setActionLoading(false);
        }
    };

    const handleStop = async () => {
        setActionLoading(true);
        setError(null);
        try {
            await stopRealtimeMonitor();
            await fetchStatus();
        } catch (err) {
            setError(err.response?.data?.message || 'Failed to stop monitoring');
        } finally {
            setActionLoading(false);
        }
    };

    if (loading) {
        return (
            <div className="flex items-center justify-center h-96">
                <Loader2 size={32} className="animate-spin text-primary" />
            </div>
        );
    }

    return (
        <div className="max-w-2xl mx-auto space-y-8">
            <SectionHeading
                title="Active Monitoring"
                subtitle="Live packet capture and flow analysis. Run backend with sudo for packet sniffing."
            />

            {error && (
                <StatusBanner tone="warning">
                    <span className="inline-flex items-center gap-2"><AlertTriangle size={16} />{error}</span>
                </StatusBanner>
            )}

            <div className="glass-card p-6 border-primary/20">
                <div className="flex items-center gap-3 mb-6">
                    <div className="p-3 rounded-xl bg-primary/10">
                        <Radio size={24} className="text-primary" />
                    </div>
                    <div>
                        <h3 className="text-h2 font-semibold text-text-primary">Monitor Control</h3>
                        <p className="text-small text-text-muted">Start or stop live packet capture</p>
                    </div>
                </div>

                <div className="space-y-4">
                    <div>
                        <label className="block text-small font-medium text-text-muted uppercase tracking-wider mb-2">
                            Network Interface
                        </label>
                        <select
                            value={selectedInterface}
                            onChange={(e) => setSelectedInterface(e.target.value)}
                            disabled={status?.running}
                            className="w-full px-4 py-3 rounded-xl bg-background border border-white/10 text-text-primary focus:outline-none focus:border-primary/50 disabled:opacity-60"
                        >
                            <option value="">Default (lo – captures local API traffic)</option>
                            {interfaces.map((iface) => (
                                <option key={iface} value={iface}>
                                    {iface === 'lo' ? `${iface} (loopback, try first)` : iface}
                                </option>
                            ))}
                        </select>
                    </div>

                    <div className="flex gap-3">
                        <button
                            onClick={handleStart}
                            disabled={status?.running || actionLoading}
                            className="flex-1 px-4 py-3 rounded-[10px] bg-primary text-white font-semibold hover:opacity-90 disabled:opacity-50 flex items-center justify-center gap-2 transition-opacity"
                        >
                            {actionLoading ? (
                                <Loader2 size={18} className="animate-spin" />
                            ) : (
                                <Play size={18} />
                            )}
                            Start
                        </button>
                        <button
                            onClick={handleStop}
                            disabled={!status?.running || actionLoading}
                            className="flex-1 px-4 py-3 rounded-[10px] border border-danger/50 text-danger font-semibold hover:bg-danger/10 disabled:opacity-50 flex items-center justify-center gap-2 transition-colors"
                        >
                            <Square size={18} />
                            Stop
                        </button>
                    </div>
                </div>
            </div>

            <div className="glass-card p-6">
                <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
                    <h3 className="text-h2 font-semibold text-text-primary flex items-center gap-2">
                        <Activity size={16} className="text-primary" />
                        Status
                    </h3>
                    <span className="text-small text-text-muted">
                        {status?.running ? (
                            <>
                                <span className="text-primary font-medium">Live • </span>
                                updates every 2s • Last: {lastUpdated || '—'}
                            </>
                        ) : (
                            <>Last updated: {lastUpdated || '—'}</>
                        )}
                    </span>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="p-4 rounded-xl bg-background/60 border border-white/10">
                        <p className="text-small text-text-muted mb-1">State</p>
                        <p className={`text-body font-bold ${status?.running ? 'text-success' : 'text-text-muted'}`}>
                            {status?.running ? (
                                <span className="flex items-center gap-2">
                                    <span className="w-2 h-2 rounded-full bg-success" />
                                    Running
                                </span>
                            ) : (
                                'Stopped'
                            )}
                        </p>
                    </div>
                    <div className="p-4 rounded-xl bg-background/60 border border-white/10">
                        <p className="text-small text-text-muted mb-1">Interface</p>
                        <p className="text-body font-mono text-text-primary">{status?.interface || '—'}</p>
                    </div>
                    <div className="p-4 rounded-xl bg-background/60 border border-white/10">
                        <p className="text-small text-text-muted mb-1">Capture Windows</p>
                        <p className="text-body font-bold text-primary">{status?.capture_count ?? 0}</p>
                    </div>
                    <div className="p-4 rounded-xl bg-background/60 border border-white/10">
                        <p className="text-small text-text-muted mb-1">Last Batch Flows</p>
                        <p className="text-body font-bold text-primary">{status?.last_flow_count ?? 0}</p>
                    </div>
                    {status?.flow_counts && (
                        <div className="p-4 rounded-xl bg-background/60 border border-white/10 col-span-2">
                            <p className="text-small text-text-muted mb-1">Total in DB (active / passive)</p>
                            <p className="text-body font-mono text-text-primary">
                                active: {status.flow_counts.active ?? 0} | passive: {status.flow_counts.passive ?? 0}
                            </p>
                            {(status.flow_counts.active ?? 0) === 0 && status?.running && !status?.capture_error && (
                                <p className="text-small text-warning mt-1">Capturing on loopback. Use the app (refresh Dashboard) to generate traffic.</p>
                            )}
                        </div>
                    )}
                    {status?.capture_error && (
                        <div className="p-4 rounded-xl bg-danger/10 border border-danger/30 col-span-2">
                            <p className="text-small text-danger font-medium mb-1">Capture error</p>
                            <p className="text-body text-red-300 font-mono break-all">{status.capture_error}</p>
                            <p className="text-small text-warning mt-2">Run backend with sudo: <code className="px-1 rounded bg-surface font-mono">cd nal/backend && sudo .venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000</code></p>
                        </div>
                    )}
                </div>
                {!status?.running && (
                    <p className="text-warning text-body mt-4 flex items-center gap-2">
                        <Play size={16} />
                        Click <strong>Start</strong> above to begin live capture. Backend must run with sudo.
                    </p>
                )}
            </div>

            <div className="glass-card p-6 border-primary/10">
                <div className="flex items-start gap-3">
                    <AlertTriangle size={20} className="text-primary shrink-0 mt-0.5" />
                    <div className="text-body text-text-primary space-y-2">
                        <p>
                            <strong>Note:</strong> Active monitoring captures packets from the selected interface.
                            Flows are classified and inserted into the database with <code className="px-1 rounded bg-surface font-mono border border-white/10">monitor_type=active</code>.
                        </p>
                        <p>
                            The Dashboard shows aggregated data from both passive uploads and active monitoring.
                            Refresh the Dashboard to see live updates.
                        </p>
                        <p className="text-text-muted text-small">
                            <strong>Must run backend with sudo</strong> for live capture: <code className="px-1 rounded bg-surface font-mono border border-white/10">cd nal/backend && sudo .venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000</code>
                        </p>
                    </div>
                </div>
            </div>
        </div>
    );
}
