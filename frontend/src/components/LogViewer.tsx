import React, { useState, useEffect, useRef } from 'react';
import { Terminal, Download, Filter, Search, X } from 'lucide-react';
import { websocketService } from '../services/websocket';

interface LogEntry {
  timestamp: string;
  level: 'info' | 'warning' | 'error' | 'success' | 'debug';
  source: string;
  message: string;
}

export const LogViewer: React.FC = () => {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [filteredLogs, setFilteredLogs] = useState<LogEntry[]>([]);
  const [filterLevel, setFilterLevel] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [autoScroll, setAutoScroll] = useState(true);
  const logContainerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Connect to WebSocket for real-time logs
    websocketService.connect();

    const handleLog = (log: LogEntry) => {
      setLogs(prev => [...prev, log].slice(-1000)); // Keep last 1000 logs
    };

    websocketService.on('log', handleLog);

    return () => {
      websocketService.off('log', handleLog);
    };
  }, []);

  useEffect(() => {
    // Filter logs based on level and search term
    let filtered = logs;

    if (filterLevel !== 'all') {
      filtered = filtered.filter(log => log.level === filterLevel);
    }

    if (searchTerm) {
      filtered = filtered.filter(log =>
        log.message.toLowerCase().includes(searchTerm.toLowerCase()) ||
        log.source.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    setFilteredLogs(filtered);
  }, [logs, filterLevel, searchTerm]);

  useEffect(() => {
    // Auto-scroll to bottom when new logs arrive
    if (autoScroll && logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [filteredLogs, autoScroll]);

  const getLevelColor = (level: string) => {
    switch (level) {
      case 'error':
        return 'text-red-500';
      case 'warning':
        return 'text-yellow-500';
      case 'success':
        return 'text-green-500';
      case 'debug':
        return 'text-gray-500';
      default:
        return 'text-blue-500';
    }
  };

  const getLevelBg = (level: string) => {
    switch (level) {
      case 'error':
        return 'bg-red-500/10';
      case 'warning':
        return 'bg-yellow-500/10';
      case 'success':
        return 'bg-green-500/10';
      case 'debug':
        return 'bg-gray-500/10';
      default:
        return 'bg-blue-500/10';
    }
  };

  const exportLogs = () => {
    const logText = filteredLogs
      .map(log => `[${log.timestamp}] [${log.level.toUpperCase()}] [${log.source}] ${log.message}`)
      .join('\n');

    const blob = new Blob([logText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `logs_${new Date().toISOString()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const clearLogs = () => {
    setLogs([]);
    setFilteredLogs([]);
  };

  return (
    <div className="flex flex-col h-full bg-white dark:bg-gray-800 rounded-lg shadow-lg">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
        <div className="flex items-center gap-2">
          <Terminal className="w-5 h-5 text-blue-500" />
          <h2 className="text-xl font-bold text-gray-900 dark:text-white">
            Log Viewer
          </h2>
          <span className="px-2 py-1 text-xs font-medium bg-blue-500/10 text-blue-500 rounded">
            {filteredLogs.length} logs
          </span>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={exportLogs}
            className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
            title="Export logs"
          >
            <Download className="w-5 h-5" />
          </button>
          <button
            onClick={clearLogs}
            className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
            title="Clear logs"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-4 p-4 border-b border-gray-200 dark:border-gray-700">
        {/* Search */}
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search logs..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
        </div>

        {/* Level filter */}
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-gray-400" />
          <select
            value={filterLevel}
            onChange={(e) => setFilterLevel(e.target.value)}
            className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          >
            <option value="all">All Levels</option>
            <option value="info">Info</option>
            <option value="success">Success</option>
            <option value="warning">Warning</option>
            <option value="error">Error</option>
            <option value="debug">Debug</option>
          </select>
        </div>

        {/* Auto-scroll toggle */}
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={autoScroll}
            onChange={(e) => setAutoScroll(e.target.checked)}
            className="w-4 h-4 text-blue-500 border-gray-300 rounded focus:ring-blue-500"
          />
          <span className="text-sm text-gray-700 dark:text-gray-300">
            Auto-scroll
          </span>
        </label>
      </div>

      {/* Log entries */}
      <div
        ref={logContainerRef}
        className="flex-1 overflow-y-auto p-4 space-y-1 font-mono text-sm"
      >
        {filteredLogs.length === 0 ? (
          <div className="flex items-center justify-center h-full text-gray-500 dark:text-gray-400">
            No logs to display
          </div>
        ) : (
          filteredLogs.map((log, index) => (
            <div
              key={index}
              className={`flex items-start gap-3 p-2 rounded ${getLevelBg(log.level)} hover:bg-opacity-50 transition-colors`}
            >
              <span className="text-gray-500 dark:text-gray-400 whitespace-nowrap">
                {log.timestamp}
              </span>
              <span className={`font-bold uppercase whitespace-nowrap ${getLevelColor(log.level)}`}>
                [{log.level}]
              </span>
              <span className="text-purple-500 whitespace-nowrap">
                [{log.source}]
              </span>
              <span className="flex-1 text-gray-900 dark:text-gray-100 break-all">
                {log.message}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default LogViewer;

