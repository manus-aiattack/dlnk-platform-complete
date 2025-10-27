import api from './api';

export interface ScanOptions {
  target: string;
  scan_type?: 'quick' | 'full' | 'stealth' | 'aggressive';
  ports?: string;
  options?: string[];
}

export interface ScanResult {
  scan_id: string;
  target: string;
  status: 'running' | 'completed' | 'failed';
  progress: number;
  results?: any;
  started_at: string;
  completed_at?: string;
}

export const nmapService = {
  /**
   * Start a quick scan on target
   */
  quickScan: async (target: string): Promise<ScanResult> => {
    const response = await api.post('/api/scan/quick', { target });
    return response.data;
  },

  /**
   * Start a full comprehensive scan
   */
  fullScan: async (target: string): Promise<ScanResult> => {
    const response = await api.post('/api/scan/full', { target });
    return response.data;
  },

  /**
   * Start a stealth scan to avoid detection
   */
  stealthScan: async (target: string): Promise<ScanResult> => {
    const response = await api.post('/api/scan/stealth', { target });
    return response.data;
  },

  /**
   * Start a custom scan with specific options
   */
  customScan: async (options: ScanOptions): Promise<ScanResult> => {
    const response = await api.post('/api/scan/custom', options);
    return response.data;
  },

  /**
   * Get scan results by scan ID
   */
  getScanResults: async (scanId: string): Promise<ScanResult> => {
    const response = await api.get(`/api/scan/${scanId}/results`);
    return response.data;
  },

  /**
   * Get all scans
   */
  getAllScans: async (): Promise<ScanResult[]> => {
    const response = await api.get('/api/scan/all');
    return response.data;
  },

  /**
   * Cancel a running scan
   */
  cancelScan: async (scanId: string): Promise<void> => {
    await api.post(`/api/scan/${scanId}/cancel`);
  },

  /**
   * Delete scan results
   */
  deleteScan: async (scanId: string): Promise<void> => {
    await api.delete(`/api/scan/${scanId}`);
  }
};

export default nmapService;

