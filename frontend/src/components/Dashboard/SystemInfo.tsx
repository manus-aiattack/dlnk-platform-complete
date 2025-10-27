import React from 'react';
import { useTheme } from '../../theme/ThemeProvider';

interface SystemInfoData {
  uptime: string;
  endpoint: string;
  lastUpdate: string;
}

const SystemInfo: React.FC = () => {
  const { theme } = useTheme();
  const [systemInfo, setSystemInfo] = React.useState<SystemInfoData>({
    uptime: '0s',
    endpoint: 'http://localhost:8000',
    lastUpdate: '-'
  });

  React.useEffect(() => {
    const startTime = new Date();

    const updateUptime = () => {
      const now = new Date();
      const elapsed = Math.floor((now - startTime) / 1000);
      const hours = Math.floor(elapsed / 3600);
      const minutes = Math.floor((elapsed % 3600) / 60);
      const seconds = elapsed % 60;

      let uptimeStr = '';
      if (hours > 0) uptimeStr += hours + 'h ';
      if (minutes > 0) uptimeStr += minutes + 'm ';
      uptimeStr += seconds + 's';

      setSystemInfo(prev => ({ ...prev, uptime: uptimeStr }));
    };

    const interval = setInterval(updateUptime, 1000);
    return () => clearInterval(interval);
  }, []);

  React.useEffect(() => {
    const updateLastUpdate = () => {
      setSystemInfo(prev => ({
        ...prev,
        lastUpdate: new Date().toLocaleTimeString()
      }));
    };

    updateLastUpdate();
    const interval = setInterval(updateLastUpdate, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{
      background: `rgba(26, 31, 58, 0.8)`,
      border: `1px solid ${theme.colors.border}`,
      borderRadius: theme.borderRadius.md,
      padding: theme.spacing.md,
      boxShadow: theme.shadows.md,
      transition: theme.transitions.normal
    }}>
      <h2 style={{
        color: theme.colors.info,
        marginBottom: theme.spacing.md,
        paddingBottom: theme.spacing.sm,
        borderBottom: `1px solid ${theme.colors.border}`,
        fontSize: '18px',
        fontWeight: 'bold'
      }}>
        System Info
      </h2>

      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: theme.spacing.md
      }}>
        <span style={{
          color: theme.colors.textSecondary,
          fontSize: '14px'
        }}>
          API Endpoint:
        </span>
        <span style={{
          color: theme.colors.info,
          fontSize: '14px',
          fontFamily: 'monospace'
        }}>
          {systemInfo.endpoint}
        </span>
      </div>

      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: theme.spacing.md
      }}>
        <span style={{
          color: theme.colors.textSecondary,
          fontSize: '14px'
        }}>
          Uptime:
        </span>
        <span style={{
          color: theme.colors.success,
          fontWeight: 'bold',
          fontSize: '14px'
        }}>
          {systemInfo.uptime}
        </span>
      </div>

      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: theme.spacing.md
      }}>
        <span style={{
          color: theme.colors.textSecondary,
          fontSize: '14px'
        }}>
          Last Update:
        </span>
        <span style={{
          color: theme.colors.text,
          fontSize: '12px'
        }}>
          {systemInfo.lastUpdate}
        </span>
      </div>
    </div>
  );
};

export default SystemInfo;