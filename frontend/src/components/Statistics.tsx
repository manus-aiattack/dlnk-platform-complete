import React, { useState, useEffect } from 'react';
import { BarChart3, TrendingUp, Target, Zap, Clock, CheckCircle } from 'lucide-react';
import { Line, Bar, Doughnut } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
} from 'chart.js';
import { api } from '../services/api';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

interface StatisticsData {
  totalAttacks: number;
  successfulAttacks: number;
  failedAttacks: number;
  averageDuration: number;
  attacksByType: Record<string, number>;
  attacksOverTime: Array<{ date: string; count: number }>;
  successRate: number;
}

export const Statistics: React.FC = () => {
  const [stats, setStats] = useState<StatisticsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState<'24h' | '7d' | '30d' | 'all'>('7d');

  useEffect(() => {
    loadStatistics();
  }, [timeRange]);

  const loadStatistics = async () => {
    try {
      setLoading(true);
      const response = await api.get(`/api/statistics?range=${timeRange}`);
      setStats(response.data);
    } catch (error) {
      console.error('Failed to load statistics:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading || !stats) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  // Chart data
  const attacksOverTimeData = {
    labels: stats.attacksOverTime.map(d => d.date),
    datasets: [
      {
        label: 'Attacks',
        data: stats.attacksOverTime.map(d => d.count),
        fill: true,
        borderColor: 'rgb(59, 130, 246)',
        backgroundColor: 'rgba(59, 130, 246, 0.1)',
        tension: 0.4
      }
    ]
  };

  const attacksByTypeData = {
    labels: Object.keys(stats.attacksByType),
    datasets: [
      {
        label: 'Attacks by Type',
        data: Object.values(stats.attacksByType),
        backgroundColor: [
          'rgba(59, 130, 246, 0.8)',
          'rgba(16, 185, 129, 0.8)',
          'rgba(245, 158, 11, 0.8)',
          'rgba(239, 68, 68, 0.8)',
          'rgba(139, 92, 246, 0.8)',
          'rgba(236, 72, 153, 0.8)'
        ]
      }
    ]
  };

  const successRateData = {
    labels: ['Successful', 'Failed'],
    datasets: [
      {
        data: [stats.successfulAttacks, stats.failedAttacks],
        backgroundColor: [
          'rgba(16, 185, 129, 0.8)',
          'rgba(239, 68, 68, 0.8)'
        ]
      }
    ]
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom' as const,
        labels: {
          color: 'rgb(156, 163, 175)'
        }
      }
    },
    scales: {
      x: {
        ticks: { color: 'rgb(156, 163, 175)' },
        grid: { color: 'rgba(156, 163, 175, 0.1)' }
      },
      y: {
        ticks: { color: 'rgb(156, 163, 175)' },
        grid: { color: 'rgba(156, 163, 175, 0.1)' }
      }
    }
  };

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <BarChart3 className="w-6 h-6 text-blue-500" />
          <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
            Attack Statistics
          </h2>
        </div>

        {/* Time range selector */}
        <div className="flex gap-2">
          {(['24h', '7d', '30d', 'all'] as const).map(range => (
            <button
              key={range}
              onClick={() => setTimeRange(range)}
              className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                timeRange === range
                  ? 'bg-blue-500 text-white'
                  : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
              }`}
            >
              {range === 'all' ? 'All Time' : range.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Total Attacks</p>
              <p className="text-3xl font-bold text-gray-900 dark:text-white mt-2">
                {stats.totalAttacks}
              </p>
            </div>
            <Target className="w-12 h-12 text-blue-500 opacity-50" />
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Success Rate</p>
              <p className="text-3xl font-bold text-green-500 mt-2">
                {stats.successRate.toFixed(1)}%
              </p>
            </div>
            <CheckCircle className="w-12 h-12 text-green-500 opacity-50" />
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Avg Duration</p>
              <p className="text-3xl font-bold text-purple-500 mt-2">
                {stats.averageDuration.toFixed(1)}s
              </p>
            </div>
            <Clock className="w-12 h-12 text-purple-500 opacity-50" />
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Successful</p>
              <p className="text-3xl font-bold text-green-500 mt-2">
                {stats.successfulAttacks}
              </p>
            </div>
            <Zap className="w-12 h-12 text-green-500 opacity-50" />
          </div>
        </div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Attacks over time */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Attacks Over Time
          </h3>
          <div className="h-64">
            <Line data={attacksOverTimeData} options={chartOptions} />
          </div>
        </div>

        {/* Attacks by type */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Attacks by Type
          </h3>
          <div className="h-64">
            <Bar data={attacksByTypeData} options={chartOptions} />
          </div>
        </div>

        {/* Success rate */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Success vs Failed
          </h3>
          <div className="h-64 flex items-center justify-center">
            <div className="w-64">
              <Doughnut data={successRateData} options={{ ...chartOptions, scales: undefined }} />
            </div>
          </div>
        </div>

        {/* Top techniques */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Top Attack Techniques
          </h3>
          <div className="space-y-3">
            {Object.entries(stats.attacksByType)
              .sort(([, a], [, b]) => b - a)
              .slice(0, 5)
              .map(([type, count], index) => (
                <div key={type} className="flex items-center gap-3">
                  <div className="flex-shrink-0 w-8 h-8 bg-blue-500 text-white rounded-full flex items-center justify-center font-bold">
                    {index + 1}
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-sm font-medium text-gray-900 dark:text-white">
                        {type}
                      </span>
                      <span className="text-sm text-gray-500 dark:text-gray-400">
                        {count} attacks
                      </span>
                    </div>
                    <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                      <div
                        className="bg-blue-500 h-2 rounded-full transition-all duration-300"
                        style={{ width: `${(count / stats.totalAttacks) * 100}%` }}
                      />
                    </div>
                  </div>
                </div>
              ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Statistics;

