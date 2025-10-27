import React, { useEffect, useState } from 'react';
import { Activity, Target, Shield, AlertTriangle, TrendingUp, Cpu, Database } from 'lucide-react';
import api from '../services/api';
import { wsService } from '../services/websocket';
import { Line, Doughnut } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
} from 'chart.js';

// Register ChartJS components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

interface DashboardStats {
  active_attacks: number;
  total_vulnerabilities: number;
  success_rate: number;
  targets_scanned: number;
  ai_agents_active: number;
  knowledge_entries: number;
}

interface Attack {
  id: string;
  name: string;
  target: string;
  status: string;
  progress: number;
  started_at: string;
}

const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats>({
    active_attacks: 0,
    total_vulnerabilities: 0,
    success_rate: 0,
    targets_scanned: 0,
    ai_agents_active: 0,
    knowledge_entries: 0,
  });
  const [loading, setLoading] = useState(true);
  const [attacks, setAttacks] = useState<Attack[]>([]);
  const [attackHistory, setAttackHistory] = useState<number[]>([]);
  const [timeLabels, setTimeLabels] = useState<string[]>([]);

  useEffect(() => {
    loadDashboardData();

    // Connect to WebSocket for real-time updates
    wsService.connect();
    wsService.on('attack_update', handleAttackUpdate);
    wsService.on('vulnerability_found', handleVulnerabilityFound);
    wsService.on('stats_update', handleStatsUpdate);

    // Refresh data every 5 seconds
    const interval = setInterval(loadDashboardData, 5000);

    return () => {
      wsService.off('attack_update', handleAttackUpdate);
      wsService.off('vulnerability_found', handleVulnerabilityFound);
      wsService.off('stats_update', handleStatsUpdate);
      clearInterval(interval);
    };
  }, []);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      
      // Load stats
      const statsResponse = await api.get('/api/stats/dashboard');
      setStats(statsResponse.data);

      // Load active attacks
      const attacksResponse = await api.get('/api/attacks?status=running');
      setAttacks(attacksResponse.data || []);

      // Load attack history for chart
      const historyResponse = await api.get('/api/stats/attack-history');
      setAttackHistory(historyResponse.data.values || []);
      setTimeLabels(historyResponse.data.labels || []);
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleAttackUpdate = (data: any) => {
    console.log('[Dashboard] Attack update:', data);
    loadDashboardData();
  };

  const handleVulnerabilityFound = (data: any) => {
    console.log('[Dashboard] Vulnerability found:', data);
    setStats(prev => ({
      ...prev,
      total_vulnerabilities: prev.total_vulnerabilities + 1
    }));
  };

  const handleStatsUpdate = (data: any) => {
    console.log('[Dashboard] Stats update:', data);
    setStats(prev => ({ ...prev, ...data }));
  };

  // Chart data
  const lineChartData = {
    labels: timeLabels,
    datasets: [
      {
        label: 'Active Attacks',
        data: attackHistory,
        borderColor: 'rgb(6, 182, 212)',
        backgroundColor: 'rgba(6, 182, 212, 0.1)',
        fill: true,
        tension: 0.4,
      },
    ],
  };

  const lineChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        display: false,
      },
    },
    scales: {
      y: {
        beginAtZero: true,
        grid: {
          color: 'rgba(255, 255, 255, 0.1)',
        },
        ticks: {
          color: 'rgba(255, 255, 255, 0.7)',
        },
      },
      x: {
        grid: {
          color: 'rgba(255, 255, 255, 0.1)',
        },
        ticks: {
          color: 'rgba(255, 255, 255, 0.7)',
        },
      },
    },
  };

  const doughnutChartData = {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [
      {
        data: [12, 25, 38, 25],
        backgroundColor: [
          'rgba(239, 68, 68, 0.8)',
          'rgba(249, 115, 22, 0.8)',
          'rgba(234, 179, 8, 0.8)',
          'rgba(34, 197, 94, 0.8)',
        ],
        borderColor: [
          'rgb(239, 68, 68)',
          'rgb(249, 115, 22)',
          'rgb(234, 179, 8)',
          'rgb(34, 197, 94)',
        ],
        borderWidth: 2,
      },
    ],
  };

  const doughnutChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom' as const,
        labels: {
          color: 'rgba(255, 255, 255, 0.9)',
          padding: 15,
        },
      },
    },
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen bg-gray-900">
        <div className="text-xl text-cyan-400">Loading dashboard...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-white">Attack Dashboard</h1>
        <div className="flex items-center space-x-2">
          <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse"></div>
          <span className="text-sm text-gray-400">Live</span>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        <StatCard
          title="Active Attacks"
          value={stats.active_attacks}
          icon={<Activity className="w-6 h-6" />}
          color="cyan"
        />
        <StatCard
          title="Vulnerabilities Found"
          value={stats.total_vulnerabilities}
          icon={<AlertTriangle className="w-6 h-6" />}
          color="red"
        />
        <StatCard
          title="Success Rate"
          value={`${stats.success_rate}%`}
          icon={<Shield className="w-6 h-6" />}
          color="green"
        />
        <StatCard
          title="Targets Scanned"
          value={stats.targets_scanned}
          icon={<Target className="w-6 h-6" />}
          color="purple"
        />
        <StatCard
          title="AI Agents Active"
          value={stats.ai_agents_active}
          icon={<Cpu className="w-6 h-6" />}
          color="blue"
        />
        <StatCard
          title="Knowledge Entries"
          value={stats.knowledge_entries}
          icon={<Database className="w-6 h-6" />}
          color="yellow"
        />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-gray-800 rounded-lg shadow-xl p-6">
          <h2 className="text-xl font-semibold mb-4 text-white flex items-center gap-2">
            <TrendingUp className="w-5 h-5 text-cyan-400" />
            Attack Timeline
          </h2>
          <div style={{ height: '300px' }}>
            <Line data={lineChartData} options={lineChartOptions} />
          </div>
        </div>
        <div className="bg-gray-800 rounded-lg shadow-xl p-6">
          <h2 className="text-xl font-semibold mb-4 text-white">Vulnerability Distribution</h2>
          <div style={{ height: '300px' }}>
            <Doughnut data={doughnutChartData} options={doughnutChartOptions} />
          </div>
        </div>
      </div>

      {/* Active Attacks */}
      <div className="bg-gray-800 rounded-lg shadow-xl p-6">
        <h2 className="text-xl font-semibold mb-4 text-white">Active Attacks</h2>
        {attacks.length > 0 ? (
          <div className="space-y-3">
            {attacks.map(attack => (
              <div key={attack.id} className="bg-gray-700 p-4 rounded-lg">
                <div className="flex items-center justify-between mb-2">
                  <div>
                    <h3 className="text-white font-semibold">{attack.name}</h3>
                    <p className="text-gray-400 text-sm">{attack.target}</p>
                  </div>
                  <span className="px-3 py-1 bg-cyan-500 text-white rounded-full text-sm">
                    {attack.status}
                  </span>
                </div>
                <div className="w-full bg-gray-600 rounded-full h-2">
                  <div
                    className="bg-cyan-500 h-2 rounded-full transition-all duration-300"
                    style={{ width: `${attack.progress}%` }}
                  ></div>
                </div>
                <p className="text-gray-400 text-sm mt-1">{attack.progress}% complete</p>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-gray-400 text-center py-8">No active attacks</p>
        )}
      </div>
    </div>
  );
};

interface StatCardProps {
  title: string;
  value: number | string;
  icon: React.ReactNode;
  color: 'cyan' | 'red' | 'green' | 'purple' | 'blue' | 'yellow';
}

const StatCard: React.FC<StatCardProps> = ({ title, value, icon, color }) => {
  const colorClasses = {
    cyan: 'bg-cyan-500/20 text-cyan-400',
    red: 'bg-red-500/20 text-red-400',
    green: 'bg-green-500/20 text-green-400',
    purple: 'bg-purple-500/20 text-purple-400',
    blue: 'bg-blue-500/20 text-blue-400',
    yellow: 'bg-yellow-500/20 text-yellow-400',
  };

  return (
    <div className="bg-gray-800 rounded-lg shadow-xl p-6 hover:bg-gray-750 transition-colors">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-400 mb-1">{title}</p>
          <p className="text-3xl font-bold text-white">{value}</p>
        </div>
        <div className={`p-3 rounded-lg ${colorClasses[color]}`}>
          {icon}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;

