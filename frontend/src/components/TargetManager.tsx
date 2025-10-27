import { useState, useEffect } from 'react';
import api from '../services/api';
import { Target, Search, Plus, AlertCircle } from 'lucide-react';

interface TargetInfo {
  id: string;
  host: string;
  type: string;
  status: 'vulnerable' | 'secure' | 'unknown' | 'scanning';
  open_ports: number[];
  services: string[];
  last_scan: string;
}

export default function TargetManager() {
  const [targets, setTargets] = useState<TargetInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    loadTargets();
  }, []);

  const loadTargets = async () => {
    try {
      const response = await api.get('/api/targets');
      setTargets(response.data);
      setError('');
    } catch (err: any) {
      setError(err.response?.data?.message || 'Failed to load targets');
    } finally {
      setLoading(false);
    }
  };

  const handleScan = async (targetId: string) => {
    try {
      await api.post(`/api/targets/${targetId}/scan`);
      loadTargets();
    } catch (err: any) {
      setError(err.response?.data?.message || 'Failed to start scan');
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'vulnerable':
        return 'bg-red-500';
      case 'secure':
        return 'bg-green-500';
      case 'scanning':
        return 'bg-yellow-500';
      case 'unknown':
        return 'bg-gray-500';
      default:
        return 'bg-gray-500';
    }
  };

  const filteredTargets = targets.filter(target =>
    target.host.toLowerCase().includes(searchTerm.toLowerCase()) ||
    target.type.toLowerCase().includes(searchTerm.toLowerCase())
  );

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-cyan-400 text-xl">Loading targets...</div>
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-3xl font-bold text-white flex items-center gap-3">
          <Target className="w-8 h-8 text-cyan-400" />
          Target Management
        </h1>
        <button className="bg-cyan-500 hover:bg-cyan-600 text-white px-4 py-2 rounded flex items-center gap-2 transition-colors">
          <Plus className="w-5 h-5" />
          Add Target
        </button>
      </div>

      {error && (
        <div className="mb-6 p-4 bg-red-500/20 border border-red-500 rounded flex items-center gap-3 text-red-400">
          <AlertCircle className="w-5 h-5" />
          {error}
        </div>
      )}

      <div className="mb-6">
        <div className="relative">
          <Search className="absolute left-3 top-3 w-5 h-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search targets..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-3 bg-gray-800 text-white rounded focus:outline-none focus:ring-2 focus:ring-cyan-500"
          />
        </div>
      </div>

      <div className="bg-gray-800 rounded-lg overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-700">
            <tr>
              <th className="px-6 py-3 text-left text-cyan-400 font-semibold">Target</th>
              <th className="px-6 py-3 text-left text-cyan-400 font-semibold">Type</th>
              <th className="px-6 py-3 text-left text-cyan-400 font-semibold">Status</th>
              <th className="px-6 py-3 text-left text-cyan-400 font-semibold">Open Ports</th>
              <th className="px-6 py-3 text-left text-cyan-400 font-semibold">Last Scan</th>
              <th className="px-6 py-3 text-left text-cyan-400 font-semibold">Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredTargets.map(target => (
              <tr key={target.id} className="border-t border-gray-700 hover:bg-gray-750 transition-colors">
                <td className="px-6 py-4 text-white font-medium">{target.host}</td>
                <td className="px-6 py-4 text-gray-400">{target.type}</td>
                <td className="px-6 py-4">
                  <span className={`px-3 py-1 rounded-full text-sm text-white ${getStatusColor(target.status)}`}>
                    {target.status}
                  </span>
                </td>
                <td className="px-6 py-4 text-gray-400">
                  {target.open_ports.length > 0 ? target.open_ports.join(', ') : 'None'}
                </td>
                <td className="px-6 py-4 text-gray-400">{target.last_scan}</td>
                <td className="px-6 py-4">
                  <button
                    onClick={() => handleScan(target.id)}
                    className="text-cyan-400 hover:text-cyan-300 transition-colors"
                  >
                    Scan
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {filteredTargets.length === 0 && !error && (
        <div className="text-center py-12 text-gray-400">
          {searchTerm ? 'No targets found matching your search.' : 'No targets configured. Click "Add Target" to get started.'}
        </div>
      )}
    </div>
  );
}

