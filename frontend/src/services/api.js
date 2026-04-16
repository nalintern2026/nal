import axios from 'axios';

const RAW_API_URL = (import.meta.env.VITE_API_URL || '').trim();
const API_BASE = RAW_API_URL || 'http://127.0.0.1:8000/api';
const API_KEY = (import.meta.env.VITE_NETGUARD_API_KEY || '').trim();

const api = axios.create({
    baseURL: API_BASE,
    timeout: 30000,
    headers: {
        'Content-Type': 'application/json',
    },
});

api.interceptors.request.use((cfg) => {
    const next = { ...cfg };
    if (API_KEY) {
        next.headers = { ...(next.headers || {}), 'x-api-key': API_KEY };
    }
    return next;
});

api.interceptors.response.use(
    (response) => {
        const payload = response?.data;
        if (payload && typeof payload === 'object' && 'status' in payload && 'data' in payload) {
            return { ...response, data: payload.data };
        }
        return response;
    },
    (error) => {
        const wrappedErr = error?.response?.data?.error;
        const detail = wrappedErr?.message || error?.response?.data?.detail || error?.message || 'Request failed';
        error.friendlyMessage = detail;
        return Promise.reject(error);
    }
);

// Upload in progress – avoid marking "offline" while backend is busy processing large file
let uploadInProgress = false;
export function setUploadInProgress(value) {
    uploadInProgress = Boolean(value);
}
export function isUploadInProgress() {
    return uploadInProgress;
}

// Health – use longer timeout so backend busy with upload doesn't trigger "offline"
const HEALTH_TIMEOUT_MS = 120000; // 2 min when backend may be processing large upload
export const checkHealth = () => {
    return api.get('/health', { timeout: HEALTH_TIMEOUT_MS });
};

// Dashboard (monitorType: 'passive' | 'active' to filter by source)
export const getDashboardStats = (monitorType = '') => {
    const params = monitorType ? { monitor_type: monitorType } : {};
    return api.get('/dashboard/stats', {
        params: { ...params, _: Date.now() },
        headers: { 'Cache-Control': 'no-cache' },
    });
};

// Traffic
export const getTrafficFlows = (params = {}) => api.get('/traffic/flows', { params });
export const getTrafficTrends = (params = {}) => api.get('/traffic/trends', { params });

// Anomalies / Threats
export const getAnomalies = (params = {}) => api.get('/anomalies', { params });

// OSINT Validation
export const getOsintFlows = (params = {}) => api.get('/osint/flows', { params });

// Model Metrics
export const getModelMetrics = () => api.get('/models/metrics');

// Upload
export const uploadFile = (file) => {
    const formData = new FormData();
    formData.append('file', file);
    return api.post('/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        timeout: 0,
    });
};
export const getUploadJob = (jobId) => api.get(`/upload/jobs/${jobId}`);
export const listUploadJobs = (limit = 50) => api.get('/upload/jobs', { params: { limit } });
export const getUploadFlows = (analysisId, params = {}) => api.get(`/upload/${analysisId}/flows`, { params });

// History (monitorType: '' | 'passive' | 'active')
export const getHistory = (limit = 100, monitorType = '') => {
    const params = { limit };
    if (monitorType) params.monitor_type = monitorType;
    return api.get('/history', { params });
};
export const getHistoryReport = (analysisId) => api.get(`/history/${analysisId}`);

// Security / SBOM
export const getSBOM = () => api.get('/security/sbom');
export const getVulnerabilities = () => api.get('/security/vulnerabilities');
export const analyzeSBOMFile = (file) => {
    const formData = new FormData();
    formData.append('file', file);
    return api.post('/security/sbom/analyze', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        timeout: 60000,
    });
};
export const downloadSBOM = () => `${API_BASE}/security/sbom/download`;

// Active / Realtime Monitoring
export const startRealtimeMonitor = (iface = '') =>
    api.post('/realtime/start', null, { params: { interface: iface } });
export const stopRealtimeMonitor = () => api.post('/realtime/stop');
export const getRealtimeStatus = () => api.get('/realtime/status');
export const getRealtimeInterfaces = () => api.get('/realtime/interfaces');
export const getAlerts = (params = {}) => api.get('/alerts', { params });
export const getAlert = (id) => api.get(`/alerts/${id}`);
export const updateAlert = (id, status) => api.patch(`/alerts/${id}`, { status });
export const getModelVersions = () => api.get('/model/versions');

export default api;
