import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import Upload from './pages/Upload';
import History from './pages/History';
import HistoryReport from './pages/HistoryReport';
import TrafficAnalysis from './pages/TrafficAnalysis';
import Anomalies from './pages/Anomalies';
import OSINTValidation from './pages/OSINTValidation';
import ModelPerformance from './pages/ModelPerformance';
import SBOMSecurity from './pages/SBOMSecurity';
import ActiveMonitoring from './pages/ActiveMonitoring';
import Alerts from './pages/Alerts';

function App() {
  return (
    <Router>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/upload" element={<Upload />} />
          <Route path="/history" element={<History />} />
          <Route path="/history/:id" element={<HistoryReport />} />
          <Route path="/traffic" element={<TrafficAnalysis />} />
          <Route path="/anomalies" element={<Anomalies />} />
          <Route path="/osint" element={<OSINTValidation />} />
          <Route path="/models" element={<ModelPerformance />} />
          <Route path="/active" element={<ActiveMonitoring />} />
          <Route path="/security" element={<SBOMSecurity />} />
          <Route path="/alerts" element={<Alerts />} />
        </Routes>
      </Layout>
    </Router>
  );
}

export default App;
