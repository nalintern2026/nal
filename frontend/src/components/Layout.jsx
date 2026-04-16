import { useState, useEffect } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
    LayoutDashboard,
    Upload,
    Network,
    AlertTriangle,
    BarChart3,
    Shield,
    Menu,
    X,
    Activity,
    Wifi,
    History as HistoryIcon,
    Radio,
    ShieldCheck,
} from 'lucide-react';
import { checkHealth, isUploadInProgress } from '../services/api';

const navItems = [
    { path: '/', label: 'Dashboard', icon: LayoutDashboard },
    { path: '/upload', label: 'Upload', icon: Upload },
    { path: '/active', label: 'Active Monitoring', icon: Radio },
    { path: '/history', label: 'History', icon: HistoryIcon },
    { path: '/traffic', label: 'Traffic Analysis', icon: Network },
    { path: '/anomalies', label: 'Anomalies', icon: AlertTriangle },
    { path: '/osint', label: 'OSINT Validation', icon: ShieldCheck },
    { path: '/models', label: 'Model Performance', icon: BarChart3 },
    { path: '/security', label: 'SBOM Security', icon: Shield },
];

export default function Layout({ children }) {
    const [sidebarOpen, setSidebarOpen] = useState(true);
    const [apiStatus, setApiStatus] = useState('checking');
    const location = useLocation();
    const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';
    let apiHost = 'localhost:8000';
    try {
        apiHost = new URL(apiUrl).origin;
    } catch {
        apiHost = apiUrl;
    }

    const checkApi = async () => {
        try {
            await checkHealth();
            setApiStatus('connected');
        } catch {
            if (isUploadInProgress()) {
                setApiStatus('busy');
            } else {
                setApiStatus('disconnected');
            }
        }
    };

    useEffect(() => {
        checkApi();
        const interval = setInterval(checkApi, 30000);
        return () => clearInterval(interval);
    }, []);

    return (
        <div className="flex h-screen bg-background bg-grid">
            {/* Sidebar */}
            <aside
                className={`${sidebarOpen ? 'w-72' : 'w-[88px]'} fixed h-full z-30 transition-all duration-300 ease-in-out bg-background/95 border-r border-white/10`}
            >
                {/* Logo */}
                <div className="flex items-center justify-between h-16 px-4 border-b border-white/10">
                    <div className="flex items-center gap-3">
                        <div className="relative">
                            <div className="w-9 h-9 rounded-xl bg-primary/90 shadow-[0_0_0_3px_rgba(0,173,181,0.15)] flex items-center justify-center">
                                <Wifi size={18} className="text-white" />
                            </div>
                            <div className="absolute -top-0.5 -right-0.5 w-3 h-3 rounded-full bg-success border-2 border-background" />
                        </div>
                        {sidebarOpen && (
                            <div className="animate-fade-in">
                                <h1 className="text-sm font-bold text-primary leading-tight tracking-wide">NetGuard</h1>
                                <p className="text-small text-text-muted font-medium">Security Intelligence</p>
                            </div>
                        )}
                    </div>
                    <button
                        onClick={() => setSidebarOpen(!sidebarOpen)}
                        className="p-1.5 rounded-lg hover:bg-white/5 text-text-muted hover:text-text-primary transition-colors"
                    >
                        {sidebarOpen ? <X size={16} /> : <Menu size={16} />}
                    </button>
                </div>

                {/* Nav Links */}
                <nav className="mt-4 px-3 space-y-1.5">
                    {navItems.map((item) => {
                        const Icon = item.icon;
                        const isActive = location.pathname === item.path;
                        return (
                            <NavLink
                                key={item.path}
                                to={item.path}
                                className={`flex items-center gap-3 px-3 py-2.5 rounded-xl text-body font-medium transition-colors duration-200 group ${isActive
                                    ? 'bg-primary/15 text-primary border border-primary/25'
                                    : 'text-text-muted hover:text-text-primary hover:bg-white/5 border border-transparent'
                                }`}
                            >
                                <Icon
                                    size={18}
                                    className={`flex-shrink-0 transition-colors ${isActive ? 'text-primary' : 'text-text-muted group-hover:text-text-primary'}`}
                                />
                                {sidebarOpen && <span>{item.label}</span>}
                            </NavLink>
                        );
                    })}
                </nav>

                {/* Status indicator */}
                <div className="absolute bottom-4 left-3 right-3">
                    <div className={`glass-card p-3 ${sidebarOpen ? '' : 'flex justify-center'}`}>
                        <div className="flex items-center gap-2">
                            <div
                                className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${apiStatus === 'connected'
                                    ? 'bg-success'
                                    : apiStatus === 'disconnected'
                                        ? 'bg-danger'
                                        : apiStatus === 'busy'
                                            ? 'bg-warning'
                                            : 'bg-info'
                                }`}
                            />
                            {sidebarOpen && (
                                <div className="animate-fade-in flex flex-col gap-0.5 min-w-0">
                                    <p className="text-small font-medium text-text-primary">
                                        {apiStatus === 'connected' ? 'API Connected' : apiStatus === 'disconnected' ? 'API Offline' : apiStatus === 'busy' ? 'Processing upload...' : 'Checking...'}
                                    </p>
                                    <p className="text-small text-text-muted">
                                        {apiStatus === 'disconnected' ? (
                                            <button type="button" onClick={checkApi} className="text-primary hover:underline">Retry</button>
                                        ) : (
                                            apiHost
                                        )}
                                    </p>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            </aside>

            {/* Main Content */}
            <main className={`flex-1 ${sidebarOpen ? 'ml-72' : 'ml-[88px]'} transition-all duration-300 overflow-y-auto`}>
                {/* Top Bar */}
                <header
                    className="sticky top-0 z-20 h-14 flex items-center justify-between px-8 bg-background/92 backdrop-blur border-b border-white/10"
                >
                    <div className="flex items-center gap-3">
                        <Activity size={16} className="text-primary" />
                        <h2 className="text-body font-semibold text-text-primary">
                            {navItems.find(n => n.path === location.pathname)?.label || (location.pathname.startsWith('/history/') && location.pathname !== '/history' ? 'Report' : 'Dashboard')}
                        </h2>
                    </div>
                    <div className="flex items-center gap-4">
                        <div className="flex items-center gap-2 text-small text-text-muted">
                            <div className="w-1.5 h-1.5 rounded-full bg-primary" />
                            Live Monitoring
                        </div>
                    </div>
                </header>

                {apiStatus === 'disconnected' && (
                    <div className="mx-8 mt-4 rounded-xl border border-warning/30 bg-warning/10 px-4 py-3 flex items-center justify-between gap-3">
                        <p className="text-small text-amber-200">
                            Backend is offline. UI is still available; live data updates will resume when API is back.
                        </p>
                        <button
                            type="button"
                            onClick={checkApi}
                            className="px-4 py-2 rounded-[10px] text-small font-medium border border-primary text-primary hover:bg-primary/10 transition-colors"
                        >
                            Retry Connection
                        </button>
                    </div>
                )}
                {apiStatus === 'busy' && (
                    <div className="mx-8 mt-4 rounded-xl border border-primary/25 bg-primary/10 px-4 py-3 flex items-center gap-3">
                        <p className="text-small text-primary">
                            Processing your upload. Large files can take several minutes; the page will update when done.
                        </p>
                    </div>
                )}

                {/* Page Content */}
                <div className="p-8 animate-fade-in max-w-[1600px]">
                    {children}
                </div>
            </main>
        </div>
    );
}
