import { useState, useEffect } from 'react';
import api from '../services/api';
import { Bot, Settings, AlertCircle, Activity } from 'lucide-react';

interface Agent {
  id: string;
  name: string;
  description: string;
  status: 'active' | 'inactive' | 'error';
  type: string;
  tasks_completed: number;
  success_rate: number;
  last_active: string;
}

export default function AgentList() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    loadAgents();
    const interval = setInterval(loadAgents, 10000); // Refresh every 10 seconds
    return () => clearInterval(interval);
  }, []);

  const loadAgents = async () => {
    try {
      const response = await api.get('/api/agents');
      setAgents(response.data);
      setError('');
    } catch (err: any) {
      setError(err.response?.data?.message || 'Failed to load agents');
    } finally {
      setLoading(false);
    }
  };

  const toggleAgent = async (agentId: string, currentStatus: string) => {
    try {
      const newStatus = currentStatus === 'active' ? 'inactive' : 'active';
      await api.patch(`/api/agents/${agentId}`, { status: newStatus });
      loadAgents();
    } catch (err: any) {
      setError(err.response?.data?.message || 'Failed to toggle agent');
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'bg-green-500';
      case 'inactive':
        return 'bg-gray-500';
      case 'error':
        return 'bg-red-500';
      default:
        return 'bg-gray-500';
    }
  };

  const getAgentIcon = (type: string) => {
    switch (type) {
      case 'nmap':
        return '🔍';
      case 'exploit':
        return '⚔️';
      case 'recon':
        return '🕵️';
      case 'learning':
        return '🧠';
      default:
        return '🤖';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-cyan-400 text-xl">Loading AI agents...</div>
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-3xl font-bold text-white flex items-center gap-3">
          <Bot className="w-8 h-8 text-cyan-400" />
          AI Agents
        </h1>
        <button className="bg-cyan-500 hover:bg-cyan-600 text-white px-4 py-2 rounded transition-colors">
          Deploy New Agent
        </button>
      </div>

      {error && (
        <div className="mb-6 p-4 bg-red-500/20 border border-red-500 rounded flex items-center gap-3 text-red-400">
          <AlertCircle className="w-5 h-5" />
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {agents.map(agent => (
          <div key={agent.id} className="bg-gray-800 p-6 rounded-lg hover:bg-gray-750 transition-colors">
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center gap-3">
                <span className="text-3xl">{getAgentIcon(agent.type)}</span>
                <div>
                  <h3 className="text-xl font-bold text-cyan-400">{agent.name}</h3>
                  <p className="text-sm text-gray-500">{agent.type}</p>
                </div>
              </div>
              <span className={`inline-block px-3 py-1 rounded-full text-sm text-white ${getStatusColor(agent.status)}`}>
                {agent.status}
              </span>
            </div>
            
            <p className="text-gray-400 mb-4 text-sm">{agent.description}</p>

            <div className="space-y-2 text-sm">
              <div className="flex items-center justify-between text-gray-400">
                <span>Tasks Completed:</span>
                <span className="text-white font-semibold">{agent.tasks_completed}</span>
              </div>
              <div className="flex items-center justify-between text-gray-400">
                <span>Success Rate:</span>
                <span className="text-green-400 font-semibold">{agent.success_rate}%</span>
              </div>
              <div className="flex items-center gap-2 text-gray-400">
                <Activity className="w-4 h-4" />
                <span>Last active: {agent.last_active}</span>
              </div>
            </div>

            <div className="mt-4 pt-4 border-t border-gray-700 flex gap-2">
              <button
                onClick={() => toggleAgent(agent.id, agent.status)}
                className={`flex-1 px-3 py-2 rounded text-sm transition-colors ${
                  agent.status === 'active'
                    ? 'bg-red-500/20 text-red-400 hover:bg-red-500/30'
                    : 'bg-green-500/20 text-green-400 hover:bg-green-500/30'
                }`}
              >
                {agent.status === 'active' ? 'Deactivate' : 'Activate'}
              </button>
              <button className="flex-1 text-cyan-400 hover:text-cyan-300 text-sm flex items-center justify-center gap-2 transition-colors">
                <Settings className="w-4 h-4" />
                Configure
              </button>
            </div>
          </div>
        ))}
      </div>

      {agents.length === 0 && !error && (
        <div className="text-center py-12 text-gray-400">
          No AI agents deployed. Click "Deploy New Agent" to get started.
        </div>
      )}
    </div>
  );
}

