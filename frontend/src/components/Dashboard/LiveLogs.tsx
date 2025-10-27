import React from 'react';
import { useTheme } from '../../theme/ThemeProvider';

interface LogEntry {
  timestamp: string;
  agent_name?: string;
  workflow_id?: string;
  target_id?: string;
  message: string;
  level: string;
}

const LiveLogs: React.FC = () => {
  const { theme } = useTheme();
  const [logs, setLogs] = React.useState<LogEntry[]>([]);
  const [connectionStatus, setConnectionStatus] = React.useState<'connecting' | 'connected' | 'disconnected' | 'error'>('connecting');

  React.useEffect(() => {
    let ws: WebSocket | null = null;

    const connectWebSocket = () => {
      setConnectionStatus('connecting');

      ws = new WebSocket('ws://localhost:8000/ws/logs');

      ws.onopen = () => {
        setConnectionStatus('connected');
        addLog({
          timestamp: new Date().toISOString(),
          message: 'Connected to live log stream.',
          level: 'info'
        });
      };

      ws.onmessage = (event) => {
        try {
          const logData = JSON.parse(event.data);
          addLog(logData);
        } catch (error) {
          console.error('Error parsing log data:', error);
        }
      };

      ws.onclose = () => {
        setConnectionStatus('disconnected');
        setTimeout(connectWebSocket, 5000);
      };

      ws.onerror = () => {
        setConnectionStatus('error');
        ws?.close();
      };
    };

    connectWebSocket();

    // Add initial log
    addLog({
      timestamp: new Date().toISOString(),
      message: 'System initialized...',
      level: 'info'
    });

    return () => {
      ws?.close();
    };
  }, []);

  const addLog = (logData: LogEntry) => {
    setLogs(prev => [...prev, logData].slice(-50)); // Keep last 50 logs
  };

  const getLevelColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'success':
        return theme.colors.success;
      case 'error':
        return theme.colors.error;
      case 'warning':
        return theme.colors.warning;
      case 'info':
      default:
        return theme.colors.info;
    }
  };

  const formatLogMessage = (log: LogEntry) => {
    let message = `[${new Date(log.timestamp).toLocaleTimeString()}]`;
    if (log.agent_name) message += ` [${log.agent_name}]`;
    if (log.workflow_id) message += ` [WF:${log.workflow_id.substring(0, 8)}]`;
    if (log.target_id) message += ` [Target:${log.target_id}]`;
    message += ` ${log.message}`;
    return message;
  };

  return (
    <div style={{
      background: `rgba(26, 31, 58, 0.8)`,
      border: `1px solid ${theme.colors.border}`,
      borderRadius: theme.borderRadius.md,
      padding: theme.spacing.md,
      boxShadow: theme.shadows.md,
      transition: theme.transitions.normal,
      marginTop: theme.spacing.md
    }}>
      <h2 style={{
        color: theme.colors.info,
        marginBottom: theme.spacing.md,
        paddingBottom: theme.spacing.sm,
        borderBottom: `1px solid ${theme.colors.border}`,
        fontSize: '18px',
        fontWeight: 'bold',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center'
      }}>
        Live Logs
        <span style={{
          fontSize: '12px',
          color: connectionStatus === 'connected' ? theme.colors.success :
                 connectionStatus === 'error' ? theme.colors.error : theme.colors.textSecondary
        }}>
          {connectionStatus === 'connected' ? 'Connected' :
           connectionStatus === 'connecting' ? 'Connecting...' :
           connectionStatus === 'error' ? 'Error' : 'Disconnected'}
        </span>
      </h2>

      <div style={{
        background: `rgba(30, 30, 50, 0.8)`,
        border: `1px solid ${theme.colors.border}`,
        borderRadius: theme.borderRadius.md,
        padding: theme.spacing.md,
        maxHeight: '400px',
        overflowY: 'auto' as const,
        fontFamily: theme.fonts.monospace,
        fontSize: '13px',
        color: theme.colors.textSecondary
      }}>
        {logs.map((log, index) => (
          <div
            key={index}
            style={{
              padding: `${theme.spacing.xs} ${theme.spacing.sm}`,
              marginBottom: theme.spacing.xs,
              borderLeft: `3px solid ${getLevelColor(log.level)}`,
              paddingLeft: theme.spacing.md,
              color: getLevelColor(log.level)
            }}
          >
            {formatLogMessage(log)}
          </div>
        ))}
      </div>
    </div>
  );
};

export default LiveLogs;