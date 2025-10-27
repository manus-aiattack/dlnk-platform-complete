import React, { useState, useEffect } from 'react';
import { Play, Square, Trash2, Eye, Zap, Brain, Search } from 'lucide-react';
import api from '../services/api';
import nmapService from '../services/nmap';
import aiService from '../services/ai';

interface Attack {
  id: string;
  target_url: string;
  attack_type: string;
  status: string;
  started_at: string;
  completed_at?: string;
  vulnerabilities_found: number;
  progress?: number;
}

const AttackManager: React.FC = () => {
  const [attacks, setAttacks] = useState<Attack[]>([]);
  const [agents, setAgents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showNewAttackModal, setShowNewAttackModal] = useState(false);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 5000);
    return () => clearInterval(interval);
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      
      const [attacksResponse, agentsResponse] = await Promise.all([
        api.get('/api/attacks'),
        api.get('/api/agents'),
      ]);

      setAttacks(attacksResponse.data || []);
      setAgents(agentsResponse.data || []);
    } catch (error) {
      console.error('Failed to load data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleStopAttack = async (attackId: string) => {
    try {
      await api.post(`/api/attacks/${attackId}/stop`);
      await loadData();
    } catch (error) {
      console.error('Failed to stop attack:', error);
    }
  };

  const handleDeleteAttack = async (attackId: string) => {
    if (!confirm('Are you sure you want to delete this attack?')) return;
    
    try {
      await api.delete(`/api/attacks/${attackId}`);
      await loadData();
    } catch (error) {
      console.error('Failed to delete attack:', error);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running':
        return 'bg-cyan-500/20 text-cyan-400 border-cyan-500';
      case 'completed':
        return 'bg-green-500/20 text-green-400 border-green-500';
      case 'failed':
        return 'bg-red-500/20 text-red-400 border-red-500';
      case 'stopped':
        return 'bg-gray-500/20 text-gray-400 border-gray-500';
      default:
        return 'bg-gray-500/20 text-gray-400 border-gray-500';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-cyan-400 text-xl">Loading attacks...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-white flex items-center gap-3">
          <Zap className="w-8 h-8 text-cyan-400" />
          Attack Manager
        </h1>
        <button
          onClick={() => setShowNewAttackModal(true)}
          className="px-4 py-2 bg-cyan-500 text-white rounded-lg hover:bg-cyan-600 flex items-center space-x-2 transition-colors"
        >
          <Play className="w-4 h-4" />
          <span>New Attack</span>
        </button>
      </div>

      {/* Attacks Table */}
      <div className="bg-gray-800 rounded-lg shadow-xl overflow-hidden">
        <table className="min-w-full divide-y divide-gray-700">
          <thead className="bg-gray-700">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-cyan-400 uppercase tracking-wider">
                Target
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-cyan-400 uppercase tracking-wider">
                Type
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-cyan-400 uppercase tracking-wider">
                Status
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-cyan-400 uppercase tracking-wider">
                Progress
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-cyan-400 uppercase tracking-wider">
                Started
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-cyan-400 uppercase tracking-wider">
                Vulnerabilities
              </th>
              <th className="px-6 py-3 text-right text-xs font-medium text-cyan-400 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="bg-gray-800 divide-y divide-gray-700">
            {attacks.map((attack) => (
              <tr key={attack.id} className="hover:bg-gray-750 transition-colors">
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="text-sm font-medium text-white">
                    {attack.target_url}
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="text-sm text-gray-400">{attack.attack_type}</div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className={`px-3 py-1 text-xs font-semibold rounded-full border ${getStatusColor(attack.status)}`}>
                    {attack.status}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  {attack.status === 'running' && attack.progress !== undefined ? (
                    <div className="w-24">
                      <div className="w-full bg-gray-700 rounded-full h-2">
                        <div
                          className="bg-cyan-500 h-2 rounded-full transition-all duration-300"
                          style={{ width: `${attack.progress}%` }}
                        ></div>
                      </div>
                      <p className="text-xs text-gray-400 mt-1">{attack.progress}%</p>
                    </div>
                  ) : (
                    <span className="text-gray-500 text-sm">-</span>
                  )}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                  {new Date(attack.started_at).toLocaleString()}
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="text-sm font-semibold text-red-400">
                    {attack.vulnerabilities_found}
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                  <div className="flex items-center justify-end space-x-2">
                    <button
                      onClick={() => window.location.href = `/attacks/${attack.id}`}
                      className="text-cyan-400 hover:text-cyan-300 transition-colors"
                      title="View Details"
                    >
                      <Eye className="w-4 h-4" />
                    </button>
                    {attack.status === 'running' && (
                      <button
                        onClick={() => handleStopAttack(attack.id)}
                        className="text-yellow-400 hover:text-yellow-300 transition-colors"
                        title="Stop Attack"
                      >
                        <Square className="w-4 h-4" />
                      </button>
                    )}
                    {attack.status !== 'running' && (
                      <button
                        onClick={() => handleDeleteAttack(attack.id)}
                        className="text-red-400 hover:text-red-300 transition-colors"
                        title="Delete Attack"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {attacks.length === 0 && (
          <div className="text-center py-12 text-gray-400">
            No attacks found. Start a new attack to begin.
          </div>
        )}
      </div>

      {/* New Attack Modal */}
      {showNewAttackModal && (
        <NewAttackModal
          agents={agents}
          onClose={() => setShowNewAttackModal(false)}
          onSuccess={() => {
            setShowNewAttackModal(false);
            loadData();
          }}
        />
      )}
    </div>
  );
};

interface NewAttackModalProps {
  agents: any[];
  onClose: () => void;
  onSuccess: () => void;
}

const NewAttackModal: React.FC<NewAttackModalProps> = ({ agents, onClose, onSuccess }) => {
  const [formData, setFormData] = useState({
    target_url: '',
    attack_type: 'comprehensive',
    selected_agents: [] as string[],
    use_ai_suggestions: true,
    run_nmap_scan: true,
  });
  const [submitting, setSubmitting] = useState(false);
  const [aiSuggestions, setAiSuggestions] = useState<any[]>([]);
  const [scanningTarget, setScanningTarget] = useState(false);

  const handleScanTarget = async () => {
    if (!formData.target_url) {
      alert('Please enter a target URL first');
      return;
    }

    setScanningTarget(true);
    try {
      const scanResult = await nmapService.quickScan(formData.target_url);
      console.log('Scan result:', scanResult);
      
      // Get AI suggestions based on scan
      if (formData.use_ai_suggestions) {
        const suggestions = await aiService.suggestAttack({ target: formData.target_url });
        setAiSuggestions(suggestions);
      }
    } catch (error) {
      console.error('Failed to scan target:', error);
      alert('Failed to scan target');
    } finally {
      setScanningTarget(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      setSubmitting(true);
      
      await api.post('/api/attacks', {
        target_url: formData.target_url,
        attack_type: formData.attack_type,
        agents: formData.selected_agents,
        use_ai: formData.use_ai_suggestions,
        run_nmap: formData.run_nmap_scan,
      });

      onSuccess();
    } catch (error) {
      console.error('Failed to start attack:', error);
      alert('Failed to start attack');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-70 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg p-6 w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        <h2 className="text-2xl font-bold mb-4 text-white flex items-center gap-2">
          <Zap className="w-6 h-6 text-cyan-400" />
          Start New Attack
        </h2>
        
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              Target URL
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                required
                value={formData.target_url}
                onChange={(e) => setFormData({ ...formData, target_url: e.target.value })}
                className="flex-1 px-3 py-2 bg-gray-700 text-white border border-gray-600 rounded-lg focus:ring-2 focus:ring-cyan-500 focus:outline-none"
                placeholder="https://example.com or 192.168.1.1"
              />
              <button
                type="button"
                onClick={handleScanTarget}
                disabled={scanningTarget}
                className="px-4 py-2 bg-purple-500 text-white rounded-lg hover:bg-purple-600 flex items-center gap-2 disabled:opacity-50 transition-colors"
              >
                <Search className="w-4 h-4" />
                {scanningTarget ? 'Scanning...' : 'Scan'}
              </button>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              Attack Type
            </label>
            <select
              value={formData.attack_type}
              onChange={(e) => setFormData({ ...formData, attack_type: e.target.value })}
              className="w-full px-3 py-2 bg-gray-700 text-white border border-gray-600 rounded-lg focus:ring-2 focus:ring-cyan-500 focus:outline-none"
            >
              <option value="comprehensive">Comprehensive Scan</option>
              <option value="quick">Quick Scan</option>
              <option value="deep">Deep Scan</option>
              <option value="stealth">Stealth Scan</option>
              <option value="zero_day">Zero-Day Hunter</option>
            </select>
          </div>

          <div className="space-y-2">
            <label className="flex items-center space-x-2 text-gray-300">
              <input
                type="checkbox"
                checked={formData.use_ai_suggestions}
                onChange={(e) => setFormData({ ...formData, use_ai_suggestions: e.target.checked })}
                className="rounded bg-gray-700 border-gray-600"
              />
              <Brain className="w-4 h-4 text-purple-400" />
              <span className="text-sm">Use AI-powered attack suggestions</span>
            </label>
            <label className="flex items-center space-x-2 text-gray-300">
              <input
                type="checkbox"
                checked={formData.run_nmap_scan}
                onChange={(e) => setFormData({ ...formData, run_nmap_scan: e.target.checked })}
                className="rounded bg-gray-700 border-gray-600"
              />
              <Search className="w-4 h-4 text-cyan-400" />
              <span className="text-sm">Run Nmap reconnaissance scan</span>
            </label>
          </div>

          {aiSuggestions.length > 0 && (
            <div className="bg-purple-500/10 border border-purple-500 rounded-lg p-4">
              <h3 className="text-sm font-semibold text-purple-400 mb-2 flex items-center gap-2">
                <Brain className="w-4 h-4" />
                AI Suggestions
              </h3>
              <ul className="space-y-2">
                {aiSuggestions.map((suggestion, index) => (
                  <li key={index} className="text-sm text-gray-300">
                    • {suggestion.description} (Confidence: {suggestion.confidence}%)
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              Select Agents ({formData.selected_agents.length} selected)
            </label>
            <div className="bg-gray-700 border border-gray-600 rounded-lg p-3 max-h-60 overflow-y-auto">
              {agents.map((agent) => (
                <label key={agent.id} className="flex items-center space-x-2 py-2 hover:bg-gray-600 px-2 rounded transition-colors">
                  <input
                    type="checkbox"
                    checked={formData.selected_agents.includes(agent.id)}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setFormData({
                          ...formData,
                          selected_agents: [...formData.selected_agents, agent.id],
                        });
                      } else {
                        setFormData({
                          ...formData,
                          selected_agents: formData.selected_agents.filter((a) => a !== agent.id),
                        });
                      }
                    }}
                    className="rounded bg-gray-600 border-gray-500"
                  />
                  <span className="text-sm text-white">{agent.name}</span>
                  <span className="text-xs text-gray-400">({agent.type})</span>
                </label>
              ))}
            </div>
          </div>

          <div className="flex justify-end space-x-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 border border-gray-600 text-gray-300 rounded-lg hover:bg-gray-700 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting || formData.selected_agents.length === 0}
              className="px-4 py-2 bg-cyan-500 text-white rounded-lg hover:bg-cyan-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {submitting ? 'Starting...' : 'Start Attack'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default AttackManager;

