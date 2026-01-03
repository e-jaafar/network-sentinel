// API URL - uses same host as frontend
const API_BASE = typeof window !== 'undefined' 
  ? `http://${window.location.hostname}:8000`
  : 'http://localhost:8000';

// Token storage
const TOKEN_KEY = 'sentinel_token';

export function getToken(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function removeToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

export function isAuthenticated(): boolean {
  return !!getToken();
}

// Auth headers helper
function authHeaders(): HeadersInit {
  const token = getToken();
  return token ? { 'Authorization': `Bearer ${token}` } : {};
}

// Interfaces
export interface Device {
  ip: string;
  mac: string;
  hostname: string | null;
  vendor: string;
  ports: { port: number; service: string }[];
  risk: {
    score: number;
    level: 'HIGH' | 'MEDIUM' | 'LOW' | 'MINIMAL';
    reasons: string[];
  };
}

export interface ScanResults {
  scan_time: string;
  network: string;
  device_count: number;
  devices: Device[];
}

export interface Stats {
  has_data: boolean;
  scan_time?: string;
  network?: string;
  total_devices?: number;
  total_open_ports?: number;
  risk_distribution?: Record<string, number>;
  vendor_distribution?: Record<string, number>;
}

export interface OllamaStatus {
  status: string;
  host?: string;
  models?: string[];
  default_model?: string;
  model_available?: boolean;
  message?: string;
}

export interface AIAnalysis {
  analysis: string;
  analyzed_devices: number;
  model: string;
  timestamp: string;
}

export interface AISummary {
  summary: string;
  risk_counts: Record<string, number>;
  total_devices: number;
}

export interface ScanHistoryItem {
  id: number;
  scan_time: string;
  network: string;
  device_count: number;
  high_risk_count: number;
  medium_risk_count: number;
  low_risk_count: number;
  minimal_risk_count: number;
  total_open_ports: number;
  created_at: string;
}

export interface Alert {
  id: number;
  scan_id: number;
  device_ip: string;
  alert_type: string;
  message: string;
  severity: string;
  notified: boolean;
  created_at: string;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

// Auth API
export async function login(username: string, password: string): Promise<LoginResponse> {
  const res = await fetch(`${API_BASE}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  
  if (!res.ok) {
    const error = await res.json().catch(() => ({ detail: 'Login failed' }));
    throw new Error(error.detail || 'Login failed');
  }
  
  const data = await res.json();
  setToken(data.access_token);
  return data;
}

export function logout(): void {
  removeToken();
}

export async function checkAuth(): Promise<boolean> {
  const token = getToken();
  if (!token) return false;
  
  try {
    const res = await fetch(`${API_BASE}/api/auth/me`, {
      headers: authHeaders(),
    });
    return res.ok;
  } catch {
    return false;
  }
}

// API error handler
async function handleResponse<T>(res: Response): Promise<T> {
  if (res.status === 401) {
    removeToken();
    if (typeof window !== 'undefined') {
      window.location.reload();
    }
    throw new Error('Session expired');
  }
  
  if (!res.ok) {
    const error = await res.json().catch(() => ({ detail: 'Request failed' }));
    throw new Error(error.detail || 'Request failed');
  }
  
  return res.json();
}

// Protected API Functions
export async function fetchLatestScan(): Promise<ScanResults> {
  const res = await fetch(`${API_BASE}/api/scan/latest`, {
    headers: authHeaders(),
  });
  return handleResponse(res);
}

export async function fetchStats(): Promise<Stats> {
  const res = await fetch(`${API_BASE}/api/stats`, {
    headers: authHeaders(),
  });
  return handleResponse(res);
}

export async function fetchOllamaStatus(): Promise<OllamaStatus> {
  const res = await fetch(`${API_BASE}/api/ollama/status`);
  return handleResponse(res);
}

export async function startScan(network?: string): Promise<{ status: string; message: string }> {
  const res = await fetch(`${API_BASE}/api/scan/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ network, scan_ports: true }),
  });
  return handleResponse(res);
}

export async function fetchAISummary(): Promise<AISummary> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 120000);
  
  try {
    const res = await fetch(`${API_BASE}/api/ai/quick-summary`, {
      headers: authHeaders(),
      signal: controller.signal
    });
    clearTimeout(timeout);
    return handleResponse(res);
  } catch (e: any) {
    clearTimeout(timeout);
    if (e.name === 'AbortError') throw new Error('AI request timed out');
    throw e;
  }
}

export async function fetchAIAnalysis(deviceIp?: string): Promise<AIAnalysis> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 180000);
  
  try {
    const res = await fetch(`${API_BASE}/api/ai/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ device_ip: deviceIp }),
      signal: controller.signal
    });
    clearTimeout(timeout);
    return handleResponse(res);
  } catch (e: any) {
    clearTimeout(timeout);
    if (e.name === 'AbortError') throw new Error('AI request timed out');
    throw e;
  }
}

export async function fetchScanHistory(limit: number = 50): Promise<{ scans: ScanHistoryItem[]; count: number }> {
  const res = await fetch(`${API_BASE}/api/scan/history?limit=${limit}`, {
    headers: authHeaders(),
  });
  return handleResponse(res);
}

export async function fetchHistoricalScan(scanId: number): Promise<ScanResults> {
  const res = await fetch(`${API_BASE}/api/scan/history/${scanId}`, {
    headers: authHeaders(),
  });
  return handleResponse(res);
}

export async function fetchAlerts(limit: number = 100): Promise<{ alerts: Alert[]; count: number }> {
  const res = await fetch(`${API_BASE}/api/alerts?limit=${limit}`, {
    headers: authHeaders(),
  });
  return handleResponse(res);
}

export function downloadPdfReport(includeAi: boolean = false): void {
  const token = getToken();
  const url = `${API_BASE}/api/report/pdf?include_ai=${includeAi}`;
  
  // For authenticated download, we need to fetch with token
  fetch(url, { headers: authHeaders() })
    .then(res => res.blob())
    .then(blob => {
      const blobUrl = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = blobUrl;
      a.download = `network-sentinel-report-${new Date().toISOString().split('T')[0]}.pdf`;
      a.click();
      window.URL.revokeObjectURL(blobUrl);
    });
}

export async function configureDiscordWebhook(webhookUrl: string): Promise<{ status: string; message: string }> {
  const res = await fetch(`${API_BASE}/api/settings/discord`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ webhook_url: webhookUrl }),
  });
  return handleResponse(res);
}

export async function testDiscordWebhook(): Promise<{ status: string; message: string }> {
  const res = await fetch(`${API_BASE}/api/settings/discord/test`, {
    method: 'POST',
    headers: authHeaders(),
  });
  return handleResponse(res);
}

export async function getDiscordSettings(): Promise<{ configured: boolean; webhook_url_masked?: string }> {
  const res = await fetch(`${API_BASE}/api/settings/discord`, {
    headers: authHeaders(),
  });
  return handleResponse(res);
}

// Utility functions
export function getRiskColor(level: string): string {
  switch (level) {
    case 'HIGH': return 'text-cyber-red';
    case 'MEDIUM': return 'text-cyber-yellow';
    case 'LOW': return 'text-cyber-blue';
    default: return 'text-cyber-green';
  }
}

export function getRiskBgColor(level: string): string {
  switch (level) {
    case 'HIGH': return 'bg-cyber-red/20 border-cyber-red';
    case 'MEDIUM': return 'bg-cyber-yellow/20 border-cyber-yellow';
    case 'LOW': return 'bg-cyber-blue/20 border-cyber-blue';
    default: return 'bg-cyber-green/20 border-cyber-green';
  }
}
