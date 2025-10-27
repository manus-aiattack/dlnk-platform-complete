import api from './api';

export interface Task {
  id: string;
  name: string;
  type: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  priority: number;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  result?: any;
  error?: string;
}

export interface ExecutorStats {
  total_tasks: number;
  running_tasks: number;
  completed_tasks: number;
  failed_tasks: number;
  queue_size: number;
  worker_count: number;
  avg_execution_time: number;
}

export interface ExecutorProgress {
  overall_progress: number;
  tasks: Array<{
    id: string;
    name: string;
    progress: number;
    status: string;
  }>;
}

export const executorService = {
  /**
   * Submit a new task for parallel execution
   */
  submitTask: async (task: {
    name: string;
    type: string;
    payload: any;
    priority?: number;
  }): Promise<Task> => {
    const response = await api.post('/api/executor/submit-task', task);
    return response.data;
  },

  /**
   * Submit multiple tasks at once
   */
  submitBatch: async (tasks: Array<{
    name: string;
    type: string;
    payload: any;
    priority?: number;
  }>): Promise<Task[]> => {
    const response = await api.post('/api/executor/submit-batch', { tasks });
    return response.data;
  },

  /**
   * Get current execution progress
   */
  getProgress: async (): Promise<ExecutorProgress> => {
    const response = await api.get('/api/executor/progress');
    return response.data;
  },

  /**
   * Get executor statistics
   */
  getStats: async (): Promise<ExecutorStats> => {
    const response = await api.get('/api/executor/stats');
    return response.data;
  },

  /**
   * Get all tasks
   */
  getAllTasks: async (status?: string): Promise<Task[]> => {
    const url = status 
      ? `/api/executor/tasks?status=${status}`
      : '/api/executor/tasks';
    const response = await api.get(url);
    return response.data;
  },

  /**
   * Get task by ID
   */
  getTask: async (taskId: string): Promise<Task> => {
    const response = await api.get(`/api/executor/tasks/${taskId}`);
    return response.data;
  },

  /**
   * Cancel a running task
   */
  cancelTask: async (taskId: string): Promise<void> => {
    await api.post(`/api/executor/tasks/${taskId}/cancel`);
  },

  /**
   * Retry a failed task
   */
  retryTask: async (taskId: string): Promise<Task> => {
    const response = await api.post(`/api/executor/tasks/${taskId}/retry`);
    return response.data;
  },

  /**
   * Delete a task
   */
  deleteTask: async (taskId: string): Promise<void> => {
    await api.delete(`/api/executor/tasks/${taskId}`);
  },

  /**
   * Clear completed tasks
   */
  clearCompleted: async (): Promise<{
    deleted_count: number;
  }> => {
    const response = await api.post('/api/executor/clear-completed');
    return response.data;
  },

  /**
   * Get executor configuration
   */
  getConfig: async (): Promise<{
    max_workers: number;
    max_queue_size: number;
    task_timeout: number;
    retry_attempts: number;
  }> => {
    const response = await api.get('/api/executor/config');
    return response.data;
  },

  /**
   * Update executor configuration
   */
  updateConfig: async (config: {
    max_workers?: number;
    max_queue_size?: number;
    task_timeout?: number;
    retry_attempts?: number;
  }): Promise<void> => {
    await api.put('/api/executor/config', config);
  },

  /**
   * Pause task execution
   */
  pause: async (): Promise<void> => {
    await api.post('/api/executor/pause');
  },

  /**
   * Resume task execution
   */
  resume: async (): Promise<void> => {
    await api.post('/api/executor/resume');
  },

  /**
   * Get task execution history
   */
  getHistory: async (limit: number = 100): Promise<Task[]> => {
    const response = await api.get(`/api/executor/history?limit=${limit}`);
    return response.data;
  }
};

export default executorService;

