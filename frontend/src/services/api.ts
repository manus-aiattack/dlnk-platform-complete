import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor for adding API key
api.interceptors.request.use(
  (config) => {
    const apiKey = localStorage.getItem('api_key');
    if (apiKey) {
      config.headers['X-API-Key'] = apiKey;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor for handling errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401 || error.response?.status === 403) {
      // Unauthorized - redirect to login
      localStorage.removeItem('api_key');
      localStorage.removeItem('user');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// Attack API
export const attackAPI = {
  // List all attacks
  listAttacks: async (params?: { status?: string; limit?: number }) => {
    const response = await api.get('/api/attacks', { params });
    return response.data;
  },

  // Get attack details
  getAttack: async (attackId: string) => {
    const response = await api.get(`/api/attacks/${attackId}`);
    return response.data;
  },

  // Start new attack
  startAttack: async (data: {
    target_url: string;
    attack_type: string;
    agents: string[];
    options?: Record<string, any>;
  }) => {
    const response = await api.post('/api/attacks/start', data);
    return response.data;
  },

  // Stop attack
  stopAttack: async (attackId: string) => {
    const response = await api.post(`/api/attacks/${attackId}/stop`);
    return response.data;
  },

  // Get attack results
  getResults: async (attackId: string) => {
    const response = await api.get(`/api/attacks/${attackId}/results`);
    return response.data;
  },
};

// Agent API
export const agentAPI = {
  // List all agents
  listAgents: async () => {
    const response = await api.get('/api/agents');
    return response.data;
  },

  // Get agent details
  getAgent: async (agentName: string) => {
    const response = await api.get(`/api/agents/${agentName}`);
    return response.data;
  },
};

// Target API
export const targetAPI = {
  // Add target
  addTarget: async (data: {
    url: string;
    name?: string;
    tags?: string[];
  }) => {
    const response = await api.post('/api/targets', data);
    return response.data;
  },

  // List targets
  listTargets: async () => {
    const response = await api.get('/api/targets');
    return response.data;
  },

  // Get target details
  getTarget: async (targetId: string) => {
    const response = await api.get(`/api/targets/${targetId}`);
    return response.data;
  },

  // Delete target
  deleteTarget: async (targetId: string) => {
    const response = await api.delete(`/api/targets/${targetId}`);
    return response.data;
  },
};

// C2 API
export const c2API = {
  // List agents
  listAgents: async (status?: string) => {
    const response = await api.get('/api/c2/agents', { params: { status } });
    return response.data;
  },

  // Get agent
  getAgent: async (agentId: string) => {
    const response = await api.get(`/api/c2/agent/${agentId}`);
    return response.data;
  },

  // Send command
  sendCommand: async (agentId: string, command: string) => {
    const response = await api.post('/api/c2/command', {
      agent_id: agentId,
      command,
    });
    return response.data;
  },

  // Get task status
  getTaskStatus: async (taskId: string) => {
    const response = await api.get(`/api/c2/task/${taskId}`);
    return response.data;
  },

  // Deactivate agent
  deactivateAgent: async (agentId: string) => {
    const response = await api.post(`/api/c2/agent/${agentId}/deactivate`);
    return response.data;
  },
};

// Stats API
export const statsAPI = {
  // Get dashboard stats
  getDashboardStats: async () => {
    const response = await api.get('/api/stats/dashboard');
    return response.data;
  },

  // Get attack timeline
  getAttackTimeline: async (days: number = 7) => {
    const response = await api.get('/api/stats/timeline', { params: { days } });
    return response.data;
  },
};

export default api;

