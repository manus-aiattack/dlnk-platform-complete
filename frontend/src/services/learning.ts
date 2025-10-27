import api from './api';

export interface KnowledgeEntry {
  id: string;
  category: string;
  title: string;
  content: string;
  confidence: number;
  learned_from: string;
  created_at: string;
  usage_count: number;
}

export interface LearningPattern {
  id: string;
  pattern_type: string;
  description: string;
  success_rate: number;
  times_applied: number;
  last_used: string;
}

export interface LearningStats {
  total_knowledge_entries: number;
  total_patterns: number;
  learning_rate: number;
  accuracy: number;
  last_learning_session: string;
}

export const learningService = {
  /**
   * Get knowledge base entries
   */
  getKnowledgeBase: async (category?: string): Promise<KnowledgeEntry[]> => {
    const url = category 
      ? `/api/learning/knowledge-base?category=${category}`
      : '/api/learning/knowledge-base';
    const response = await api.get(url);
    return response.data;
  },

  /**
   * Get learned patterns
   */
  getPatterns: async (): Promise<LearningPattern[]> => {
    const response = await api.get('/api/learning/patterns');
    return response.data;
  },

  /**
   * Get learning statistics
   */
  getStats: async (): Promise<LearningStats> => {
    const response = await api.get('/api/learning/stats');
    return response.data;
  },

  /**
   * Add new knowledge entry
   */
  addKnowledge: async (entry: {
    category: string;
    title: string;
    content: string;
    source: string;
  }): Promise<KnowledgeEntry> => {
    const response = await api.post('/api/learning/knowledge', entry);
    return response.data;
  },

  /**
   * Update knowledge entry
   */
  updateKnowledge: async (id: string, updates: Partial<KnowledgeEntry>): Promise<void> => {
    await api.put(`/api/learning/knowledge/${id}`, updates);
  },

  /**
   * Delete knowledge entry
   */
  deleteKnowledge: async (id: string): Promise<void> => {
    await api.delete(`/api/learning/knowledge/${id}`);
  },

  /**
   * Search knowledge base
   */
  searchKnowledge: async (query: string): Promise<KnowledgeEntry[]> => {
    const response = await api.get(`/api/learning/search?q=${encodeURIComponent(query)}`);
    return response.data;
  },

  /**
   * Get recommendations based on current context
   */
  getRecommendations: async (context: any): Promise<{
    recommendations: string[];
    confidence: number;
  }> => {
    const response = await api.post('/api/learning/recommendations', context);
    return response.data;
  },

  /**
   * Train model with new data
   */
  train: async (trainingData: any): Promise<{
    success: boolean;
    message: string;
    accuracy: number;
  }> => {
    const response = await api.post('/api/learning/train', trainingData);
    return response.data;
  },

  /**
   * Get learning history
   */
  getHistory: async (limit: number = 100): Promise<Array<{
    timestamp: string;
    event_type: string;
    description: string;
    impact: number;
  }>> => {
    const response = await api.get(`/api/learning/history?limit=${limit}`);
    return response.data;
  },

  /**
   * Export knowledge base
   */
  exportKnowledgeBase: async (): Promise<Blob> => {
    const response = await api.get('/api/learning/export', {
      responseType: 'blob'
    });
    return response.data;
  },

  /**
   * Import knowledge base
   */
  importKnowledgeBase: async (file: File): Promise<{
    success: boolean;
    imported_count: number;
  }> => {
    const formData = new FormData();
    formData.append('file', file);
    const response = await api.post('/api/learning/import', formData, {
      headers: {
        'Content-Type': 'multipart/form-data'
      }
    });
    return response.data;
  }
};

export default learningService;

