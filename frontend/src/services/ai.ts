import api from './api';

export interface TargetAnalysis {
  target: string;
  vulnerabilities: Array<{
    name: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    description: string;
    cvss_score?: number;
  }>;
  recommendations: string[];
  risk_score: number;
}

export interface AttackSuggestion {
  attack_type: string;
  confidence: number;
  description: string;
  prerequisites: string[];
  expected_success_rate: number;
  steps: string[];
}

export interface ExploitPayload {
  exploit_id: string;
  payload: string;
  language: string;
  description: string;
  usage_instructions: string[];
}

export const aiService = {
  /**
   * Analyze target and identify vulnerabilities using AI
   */
  analyzeTarget: async (target: any): Promise<TargetAnalysis> => {
    const response = await api.post('/api/ai/analyze-target', target);
    return response.data;
  },

  /**
   * Get AI-powered attack suggestions based on target analysis
   */
  suggestAttack: async (target: any): Promise<AttackSuggestion[]> => {
    const response = await api.post('/api/ai/suggest-attack', target);
    return response.data;
  },

  /**
   * Generate exploit code using AI
   */
  generateExploit: async (params: {
    vulnerability: string;
    target_system: string;
    exploit_type?: string;
  }): Promise<ExploitPayload> => {
    const response = await api.post('/api/ai/generate-exploit', params);
    return response.data;
  },

  /**
   * Get AI model status and capabilities
   */
  getModelStatus: async (): Promise<{
    model: string;
    status: 'ready' | 'loading' | 'error';
    capabilities: string[];
  }> => {
    const response = await api.get('/api/ai/status');
    return response.data;
  },

  /**
   * Train AI model with new attack patterns
   */
  trainModel: async (trainingData: any): Promise<{
    success: boolean;
    message: string;
  }> => {
    const response = await api.post('/api/ai/train', trainingData);
    return response.data;
  },

  /**
   * Get AI-powered recommendations for improving attack success rate
   */
  getRecommendations: async (attackId: string): Promise<string[]> => {
    const response = await api.get(`/api/ai/recommendations/${attackId}`);
    return response.data;
  }
};

export default aiService;

