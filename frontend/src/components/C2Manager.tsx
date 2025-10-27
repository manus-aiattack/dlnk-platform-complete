import { useState, useEffect } from 'react';
import api from '../services/api';
import { Server, Activity, AlertCircle } from 'lucide-react';

interface C2Server {
  id: string;
  name: string;
  host: string;
  port: number;
  status: 'active' | 'inactive' | 'error';
  connected_agents: number;
  uptime: string;
}

export default function C2Manager() {
  const [servers, setServers] = useState<C2Server[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    loadServers();
    const interval = setInterval(loadServers, 5000); // Refresh every 5 seconds
    return () => clearInterval(interval);
  }, []);

  const loadServers = async () => {
    try {
      const response = await api.get('/api/c2/servers');
      setServers(response.data);
      setError('');
    } catch (err: any) {
      setError(err.response?.data?.message || 'Failed to load C2 servers');
    } finally {
      setLoading(false);
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

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-cyan-400 text-xl">Loading C2 servers...</div>
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-3xl font-bold text-white flex items-center gap-3">
          <Server className="w-8 h-8 text-cyan-400" />
          C2 Infrastructure
        </h1>
        <button className="bg-cyan-500 hover:bg-cyan-600 text-white px-4 py-2 rounded transition-colors">
          Add Server
        </button>
      </div>

      {error && (
        <div className="mb-6 p-4 bg-red-500/20 border border-red-500 rounded flex items-center gap-3 text-red-400">
          <AlertCircle className="w-5 h-5" />
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {servers.map(server => (
          <div key={server.id} className="bg-gray-800 p-6 rounded-lg hover:bg-gray-750 transition-colors">
            <div className="flex items-start justify-between mb-4">
              <h3 className="text-xl font-bold text-cyan-400">{server.name}</h3>
              <span className={`inline-block px-3 py-1 rounded-full text-sm text-white ${getStatusColor(server.status)}`}>
                {server.status}
              </span>
            </div>
            
            <div className="space-y-2 text-gray-400">
              <p className="flex items-center gap-2">
                <Server className="w-4 h-4" />
                {server.host}:{server.port}
              </p>
              <p className="flex items-center gap-2">
                <Activity className="w-4 h-4" />
                {server.connected_agents} agents connected
              </p>
              <p className="text-sm">Uptime: {server.uptime}</p>
            </div>

            <div className="mt-4 pt-4 border-t border-gray-700 flex gap-2">
              <button className="flex-1 text-cyan-400 hover:text-cyan-300 text-sm transition-colors">
                Details
              </button>
              <button className="flex-1 text-gray-400 hover:text-white text-sm transition-colors">
                Restart
              </button>
            </div>
          </div>
        ))}
      </div>

      {servers.length === 0 && !error && (
        <div className="text-center py-12 text-gray-400">
          No C2 servers configured. Click "Add Server" to get started.
        </div>
      )}
    </div>
  );
}

