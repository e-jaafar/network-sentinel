'use client';

import { useState, useEffect } from 'react';
import { 
  fetchLatestScan, 
  fetchStats, 
  fetchOllamaStatus, 
  fetchAISummary,
  fetchAIAnalysis,
  startScan,
  fetchScanHistory,
  downloadPdfReport,
  configureDiscordWebhook,
  testDiscordWebhook,
  getDiscordSettings,
  login,
  logout,
  checkAuth,
  isAuthenticated,
  type ScanResults, 
  type Stats, 
  type OllamaStatus,
  type AISummary,
  type ScanHistoryItem,
  getRiskColor,
  getRiskBgColor
} from '@/lib/api';

// Login Component
function LoginPage({ onLogin }: { onLogin: () => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await login(username, password);
      onLogin();
    } catch (err: any) {
      setError(err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-cyber-dark flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="bg-cyber-darker border border-cyber-green/30 rounded-lg p-8">
          <div className="text-center mb-8">
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-cyber-green/20 border border-cyber-green mb-4">
              <ShieldIcon />
            </div>
            <h1 className="text-2xl font-bold text-cyber-green">Network Sentinel</h1>
            <p className="text-gray-400 mt-2">Sign in to access the dashboard</p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-6">
            {error && (
              <div className="bg-cyber-red/20 border border-cyber-red text-cyber-red px-4 py-3 rounded">
                {error}
              </div>
            )}

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Username
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full bg-cyber-dark border border-gray-600 rounded px-4 py-3 text-white focus:border-cyber-green focus:outline-none"
                placeholder="admin"
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-cyber-dark border border-gray-600 rounded px-4 py-3 text-white focus:border-cyber-green focus:outline-none"
                placeholder="Enter password"
                required
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-cyber-green text-cyber-dark font-bold py-3 px-4 rounded hover:bg-cyber-green/80 transition disabled:opacity-50"
            >
              {loading ? 'Signing in...' : 'Sign In'}
            </button>
          </form>

          <p className="text-center text-gray-500 text-sm mt-6">
            Default credentials: admin / sentinel
          </p>
        </div>
      </div>
    </div>
  );
}

// Icons
const ShieldIcon = () => (
  <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
  </svg>
);

const LogoutIcon = () => (
  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
  </svg>
);

const ServerIcon = () => (
  <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
  </svg>
);

const WifiIcon = () => (
  <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.905 14.14 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0" />
  </svg>
);

const BrainIcon = () => (
  <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
  </svg>
);

const RefreshIcon = ({ spinning }: { spinning?: boolean }) => (
  <svg className={`w-5 h-5 ${spinning ? 'animate-spin' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
  </svg>
);

const DownloadIcon = () => (
  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
  </svg>
);

const HistoryIcon = () => (
  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
  </svg>
);

const DiscordIcon = () => (
  <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
    <path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028 14.09 14.09 0 0 0 1.226-1.994.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/>
  </svg>
);

const SettingsIcon = () => (
  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
  </svg>
);

// Main Dashboard Component
function Dashboard({ onLogout }: { onLogout: () => void }) {
  const [scanResults, setScanResults] = useState<ScanResults | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [ollamaStatus, setOllamaStatus] = useState<OllamaStatus | null>(null);
  const [aiSummary, setAiSummary] = useState<AISummary | null>(null);
  const [aiAnalysis, setAiAnalysis] = useState<string | null>(null);
  const [scanHistory, setScanHistory] = useState<ScanHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [discordWebhook, setDiscordWebhook] = useState('');
  const [discordConfigured, setDiscordConfigured] = useState(false);

  useEffect(() => {
    loadData();
  }, []);

  async function loadData() {
    setLoading(true);
    setError(null);
    try {
      const [scanData, statsData, ollamaData, historyData, discordData] = await Promise.all([
        fetchLatestScan().catch(() => null),
        fetchStats().catch(() => null),
        fetchOllamaStatus().catch(() => null),
        fetchScanHistory(10).catch(() => ({ scans: [] })),
        getDiscordSettings().catch(() => ({ configured: false })),
      ]);
      setScanResults(scanData);
      setStats(statsData);
      setOllamaStatus(ollamaData);
      setScanHistory(historyData.scans);
      setDiscordConfigured(discordData.configured);
    } catch (err) {
      setError('Failed to load data. Is the backend running?');
    }
    setLoading(false);
  }

  async function handleScan() {
    setScanning(true);
    setError(null);
    try {
      await startScan();
      const checkScan = setInterval(async () => {
        try {
          const newResults = await fetchLatestScan();
          if (newResults.scan_time !== scanResults?.scan_time) {
            setScanResults(newResults);
            const newStats = await fetchStats();
            setStats(newStats);
            const historyData = await fetchScanHistory(10);
            setScanHistory(historyData.scans);
            setScanning(false);
            clearInterval(checkScan);
          }
        } catch (e) {}
      }, 3000);
      
      setTimeout(() => {
        clearInterval(checkScan);
        setScanning(false);
      }, 120000);
    } catch (err) {
      setError('Failed to start scan. Make sure the backend has sudo access.');
      setScanning(false);
    }
  }

  async function handleAIAnalysis() {
    setAnalyzing(true);
    setAiAnalysis(null);
    setAiSummary(null);
    setError(null);
    try {
      setAiAnalysis('Generating summary...');
      const summary = await fetchAISummary();
      setAiSummary(summary);
      
      setAiAnalysis('Generating detailed analysis... (this may take 30-60 seconds)');
      const analysis = await fetchAIAnalysis();
      setAiAnalysis(analysis.analysis);
    } catch (err) {
      setError('AI analysis failed. Ollama may be slow - try again.');
      setAiAnalysis(null);
    }
    setAnalyzing(false);
  }

  async function handleSaveDiscord() {
    try {
      await configureDiscordWebhook(discordWebhook);
      setDiscordConfigured(true);
      setError(null);
      alert('Discord webhook configured successfully!');
    } catch (err) {
      setError('Failed to save Discord webhook');
    }
  }

  async function handleTestDiscord() {
    try {
      await testDiscordWebhook();
      alert('Test notification sent to Discord!');
    } catch (err) {
      setError('Failed to send test notification. Check webhook URL.');
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="w-16 h-16 border-4 border-cyber-green border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-gray-400">Loading Network Sentinel...</p>
        </div>
      </div>
    );
  }

  return (
    <main className="min-h-screen p-6 bg-dark-bg">
      {/* Header */}
      <header className="mb-8">
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyber-green/20 rounded-lg glow-green">
              <ShieldIcon />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">Network Sentinel</h1>
              <p className="text-sm text-gray-400">AI-Powered Security Dashboard v2.0</p>
            </div>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            {/* Ollama Status */}
            <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-sm ${
              ollamaStatus?.status === 'online' 
                ? 'bg-cyber-green/20 text-cyber-green' 
                : 'bg-cyber-red/20 text-cyber-red'
            }`}>
              <span className={`w-2 h-2 rounded-full ${
                ollamaStatus?.status === 'online' ? 'bg-cyber-green' : 'bg-cyber-red'
              } animate-pulse`}></span>
              Ollama: {ollamaStatus?.status || 'Unknown'}
            </div>
            
            {/* History Button */}
            <button
              onClick={() => setShowHistory(!showHistory)}
              className="flex items-center gap-2 px-3 py-2 bg-cyber-blue/20 hover:bg-cyber-blue/30 border border-cyber-blue text-cyber-blue rounded-lg transition-all"
            >
              <HistoryIcon />
              History
            </button>
            
            {/* PDF Export */}
            <button
              onClick={() => downloadPdfReport(false)}
              className="flex items-center gap-2 px-3 py-2 bg-cyber-purple/20 hover:bg-cyber-purple/30 border border-cyber-purple text-cyber-purple rounded-lg transition-all"
            >
              <DownloadIcon />
              PDF
            </button>
            
            {/* Settings */}
            <button
              onClick={() => setShowSettings(!showSettings)}
              className={`flex items-center gap-2 px-3 py-2 rounded-lg transition-all ${
                discordConfigured 
                  ? 'bg-cyber-green/20 hover:bg-cyber-green/30 border border-cyber-green text-cyber-green'
                  : 'bg-gray-500/20 hover:bg-gray-500/30 border border-gray-500 text-gray-400'
              }`}
            >
              <SettingsIcon />
            </button>
            
            {/* Scan Button */}
            <button
              onClick={handleScan}
              disabled={scanning}
              className="flex items-center gap-2 px-4 py-2 bg-cyber-green/20 hover:bg-cyber-green/30 border border-cyber-green text-cyber-green rounded-lg transition-all disabled:opacity-50"
            >
              <RefreshIcon spinning={scanning} />
              {scanning ? 'Scanning...' : 'New Scan'}
            </button>
            
            {/* Logout Button */}
            <button
              onClick={onLogout}
              className="flex items-center gap-2 px-3 py-2 bg-cyber-red/20 hover:bg-cyber-red/30 border border-cyber-red text-cyber-red rounded-lg transition-all"
              title="Logout"
            >
              <LogoutIcon />
            </button>
          </div>
        </div>
      </header>

      {/* Settings Panel */}
      {showSettings && (
        <div className="mb-6 p-4 bg-dark-card border border-dark-border rounded-xl">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <DiscordIcon />
            Discord Notifications
          </h3>
          <div className="flex gap-2 flex-wrap">
            <input
              type="text"
              placeholder="Discord Webhook URL"
              value={discordWebhook}
              onChange={(e) => setDiscordWebhook(e.target.value)}
              className="flex-1 min-w-64 px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white placeholder-gray-500 focus:border-cyber-purple focus:outline-none"
            />
            <button
              onClick={handleSaveDiscord}
              className="px-4 py-2 bg-cyber-purple/20 hover:bg-cyber-purple/30 border border-cyber-purple text-cyber-purple rounded-lg transition-all"
            >
              Save
            </button>
            {discordConfigured && (
              <button
                onClick={handleTestDiscord}
                className="px-4 py-2 bg-cyber-blue/20 hover:bg-cyber-blue/30 border border-cyber-blue text-cyber-blue rounded-lg transition-all"
              >
                Test
              </button>
            )}
          </div>
          <p className="text-sm text-gray-400 mt-2">
            {discordConfigured 
              ? '✓ Discord notifications are enabled. You will receive alerts when new risks are detected.'
              : 'Configure a Discord webhook to receive security alerts automatically.'}
          </p>
        </div>
      )}

      {/* History Panel */}
      {showHistory && scanHistory.length > 0 && (
        <div className="mb-6 p-4 bg-dark-card border border-dark-border rounded-xl">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <HistoryIcon />
            Scan History
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-gray-400 border-b border-dark-border">
                  <th className="pb-2">Date</th>
                  <th className="pb-2">Devices</th>
                  <th className="pb-2">Ports</th>
                  <th className="pb-2">High</th>
                  <th className="pb-2">Medium</th>
                </tr>
              </thead>
              <tbody>
                {scanHistory.map((scan) => (
                  <tr key={scan.id} className="border-b border-dark-border/50">
                    <td className="py-2">{new Date(scan.scan_time).toLocaleString()}</td>
                    <td className="py-2">{scan.device_count}</td>
                    <td className="py-2">{scan.total_open_ports}</td>
                    <td className="py-2 text-cyber-red">{scan.high_risk_count}</td>
                    <td className="py-2 text-cyber-yellow">{scan.medium_risk_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {error && (
        <div className="mb-6 p-4 bg-cyber-red/20 border border-cyber-red rounded-lg text-cyber-red">
          {error}
        </div>
      )}

      {/* Stats Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <StatCard icon={<ServerIcon />} label="Devices Found" value={stats?.total_devices || 0} color="green" />
        <StatCard icon={<WifiIcon />} label="Open Ports" value={stats?.total_open_ports || 0} color="blue" />
        <StatCard icon={<ShieldIcon />} label="High Risk" value={stats?.risk_distribution?.HIGH || 0} color="red" />
        <StatCard icon={<ShieldIcon />} label="Medium Risk" value={stats?.risk_distribution?.MEDIUM || 0} color="yellow" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Device List */}
        <div className="lg:col-span-2">
          <div className="bg-dark-card border border-dark-border rounded-xl p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold">Network Devices</h2>
              {scanResults && (
                <span className="text-sm text-gray-400">
                  Last scan: {new Date(scanResults.scan_time).toLocaleString()}
                </span>
              )}
            </div>
            
            {scanResults?.devices && scanResults.devices.length > 0 ? (
              <div className="space-y-3">
                {scanResults.devices.map((device) => (
                  <DeviceCard key={device.ip} device={device} />
                ))}
              </div>
            ) : (
              <div className="text-center py-12 text-gray-400">
                <ServerIcon />
                <p className="mt-2">No devices found. Run a scan to discover your network.</p>
              </div>
            )}
          </div>
        </div>

        {/* AI Analysis Panel */}
        <div className="lg:col-span-1">
          <div className="bg-dark-card border border-dark-border rounded-xl p-6 sticky top-6">
            <div className="flex items-center gap-2 mb-4">
              <BrainIcon />
              <h2 className="text-lg font-semibold">AI Security Analysis</h2>
            </div>

            <button
              onClick={handleAIAnalysis}
              disabled={analyzing || !scanResults}
              className="w-full mb-4 flex items-center justify-center gap-2 px-4 py-3 bg-cyber-purple/20 hover:bg-cyber-purple/30 border border-cyber-purple text-cyber-purple rounded-lg transition-all disabled:opacity-50"
            >
              {analyzing ? (
                <>
                  <RefreshIcon spinning />
                  Analyzing...
                </>
              ) : (
                <>
                  <BrainIcon />
                  Analyze with AI
                </>
              )}
            </button>

            {aiSummary && (
              <div className="mb-4 p-4 bg-cyber-green/10 border border-cyber-green/30 rounded-lg">
                <h3 className="text-sm font-medium text-cyber-green mb-2">Quick Summary</h3>
                <p className="text-sm text-gray-300">{aiSummary.summary}</p>
              </div>
            )}

            {aiAnalysis && (
              <div className="p-4 bg-dark-bg rounded-lg max-h-96 overflow-y-auto">
                <h3 className="text-sm font-medium text-cyber-blue mb-2">Detailed Analysis</h3>
                <div className="text-sm text-gray-300 whitespace-pre-wrap font-mono">
                  {aiAnalysis}
                </div>
              </div>
            )}

            {!aiSummary && !aiAnalysis && (
              <p className="text-sm text-gray-400 text-center">
                Click the button above to get an AI-powered security analysis of your network.
              </p>
            )}
            
            {/* PDF with AI button */}
            {aiAnalysis && !analyzing && (
              <button
                onClick={() => downloadPdfReport(true)}
                className="w-full mt-4 flex items-center justify-center gap-2 px-4 py-2 bg-cyber-blue/20 hover:bg-cyber-blue/30 border border-cyber-blue text-cyber-blue rounded-lg transition-all"
              >
                <DownloadIcon />
                Download PDF with AI Analysis
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="mt-12 text-center text-sm text-gray-500">
        <p>Network Sentinel v2.0 | Powered by Llama 3.2 on Raspberry Pi 5</p>
        <p className="text-xs mt-1">Auto-scan every 6 hours | {scanHistory.length} scans in history</p>
      </footer>
    </main>
  );
}

// Components
function StatCard({ icon, label, value, color }: { 
  icon: React.ReactNode; 
  label: string; 
  value: number; 
  color: 'green' | 'blue' | 'red' | 'yellow' 
}) {
  const colorClasses = {
    green: 'bg-cyber-green/20 border-cyber-green text-cyber-green',
    blue: 'bg-cyber-blue/20 border-cyber-blue text-cyber-blue',
    red: 'bg-cyber-red/20 border-cyber-red text-cyber-red',
    yellow: 'bg-cyber-yellow/20 border-cyber-yellow text-cyber-yellow',
  };

  return (
    <div className={`p-4 rounded-xl border ${colorClasses[color]} card-hover`}>
      <div className="flex items-center gap-3">
        <div className="opacity-70">{icon}</div>
        <div>
          <p className="text-2xl font-bold">{value}</p>
          <p className="text-sm opacity-70">{label}</p>
        </div>
      </div>
    </div>
  );
}

function DeviceCard({ device }: { device: ScanResults['devices'][0] }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div 
      className={`p-4 rounded-lg border cursor-pointer transition-all ${getRiskBgColor(device.risk.level)} card-hover`}
      onClick={() => setExpanded(!expanded)}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className={`w-3 h-3 rounded-full ${
            device.risk.level === 'HIGH' ? 'bg-cyber-red animate-pulse' :
            device.risk.level === 'MEDIUM' ? 'bg-cyber-yellow' :
            'bg-cyber-green'
          }`}></div>
          <div>
            <p className="font-mono font-medium">{device.ip}</p>
            <p className="text-sm text-gray-400">{device.vendor}</p>
          </div>
        </div>
        <div className="text-right">
          <span className={`text-sm font-medium ${getRiskColor(device.risk.level)}`}>
            {device.risk.level}
          </span>
          {device.ports.length > 0 && (
            <p className="text-xs text-gray-400">{device.ports.length} port(s)</p>
          )}
        </div>
      </div>

      {expanded && (
        <div className="mt-4 pt-4 border-t border-white/10">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <p className="text-gray-400">MAC Address</p>
              <p className="font-mono">{device.mac}</p>
            </div>
            <div>
              <p className="text-gray-400">Hostname</p>
              <p className="font-mono">{device.hostname || 'N/A'}</p>
            </div>
          </div>
          
          {device.ports.length > 0 && (
            <div className="mt-3">
              <p className="text-gray-400 text-sm mb-2">Open Ports</p>
              <div className="flex flex-wrap gap-2">
                {device.ports.map((p) => (
                  <span key={p.port} className="px-2 py-1 bg-dark-bg rounded text-xs font-mono">
                    {p.port}/{p.service}
                  </span>
                ))}
              </div>
            </div>
          )}

          {device.risk.reasons.length > 0 && (
            <div className="mt-3">
              <p className="text-gray-400 text-sm mb-2">Risk Factors</p>
              <ul className="text-sm space-y-1">
                {device.risk.reasons.map((reason, i) => (
                  <li key={i} className="text-cyber-red">{reason}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// Main App Component with Auth
export default function Home() {
  const [authenticated, setAuthenticated] = useState<boolean | null>(null);

  useEffect(() => {
    // Check if user is already authenticated
    checkAuth().then(setAuthenticated);
  }, []);

  const handleLogin = () => {
    setAuthenticated(true);
  };

  const handleLogout = () => {
    logout();
    setAuthenticated(false);
  };

  // Loading state while checking auth
  if (authenticated === null) {
    return (
      <div className="min-h-screen bg-cyber-dark flex items-center justify-center">
        <div className="w-16 h-16 border-4 border-cyber-green border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  // Show login or dashboard
  return authenticated ? (
    <Dashboard onLogout={handleLogout} />
  ) : (
    <LoginPage onLogin={handleLogin} />
  );
}
