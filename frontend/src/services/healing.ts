import api from './api';

export interface HealingStats {
  total_errors: number;
  errors_fixed: number;
  success_rate: number;
  active_monitors: number;
  last_healing: string;
}

export interface ErrorPattern {
  id: string;
  error_type: string;
  frequency: number;
  last_occurred: string;
  auto_fixed: boolean;
  fix_strategy?: string;
}

export interface HealingAction {
  id: string;
  timestamp: string;
  error_type: string;
  action_taken: string;
  success: boolean;
  duration_ms: number;
}

export const healingService = {
  /**
   * Get self-healing statistics
   */
  getStats: async (): Promise<HealingStats> => {
    const response = await api.get('/api/healing/stats');
    return response.data;
  },

  /**
   * Get all detected error patterns
   */
  getErrors: async (): Promise<ErrorPattern[]> => {
    const response = await api.get('/api/healing/errors');
    return response.data;
  },

  /**
   * Get healing patterns and strategies
   */
  getPatterns: async (): Promise<ErrorPattern[]> => {
    const response = await api.get('/api/healing/patterns');
    return response.data;
  },

  /**
   * Get recent healing actions
   */
  getRecentActions: async (limit: number = 50): Promise<HealingAction[]> => {
    const response = await api.get(`/api/healing/actions?limit=${limit}`);
    return response.data;
  },

  /**
   * Enable/disable auto-healing for specific error type
   */
  toggleAutoHealing: async (errorType: string, enabled: boolean): Promise<void> => {
    await api.post('/api/healing/toggle', { error_type: errorType, enabled });
  },

  /**
   * Manually trigger healing for a specific error
   */
  triggerHealing: async (errorId: string): Promise<{
    success: boolean;
    message: string;
  }> => {
    const response = await api.post(`/api/healing/trigger/${errorId}`);
    return response.data;
  },

  /**
   * Add custom healing strategy
   */
  addStrategy: async (strategy: {
    error_type: string;
    detection_pattern: string;
    fix_action: string;
  }): Promise<void> => {
    await api.post('/api/healing/strategy', strategy);
  },

  /**
   * Get healing configuration
   */
  getConfig: async (): Promise<{
    enabled: boolean;
    auto_fix_enabled: boolean;
    monitoring_interval: number;
    max_retry_attempts: number;
  }> => {
    const response = await api.get('/api/healing/config');
    return response.data;
  },

  /**
   * Update healing configuration
   */
  updateConfig: async (config: any): Promise<void> => {
    await api.put('/api/healing/config', config);
  }
};

export default healingService;

