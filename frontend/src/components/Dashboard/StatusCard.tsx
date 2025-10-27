import React from 'react';
import { useTheme } from '../../theme/ThemeProvider';

interface StatusData {
  status: string;
  agents: number;
  results: number;
  phase: string;
}

const StatusCard: React.FC = () => {
  const { theme } = useTheme();
  const [statusData, setStatusData] = React.useState<StatusData>({
    status: 'Initializing...',
    agents: 0,
    results: 0,
    phase: '-'
  });

  React.useEffect(() => {
    const fetchStatus = async () => {
      try {
        const response = await fetch('/status');
        const data = await response.json();
        setStatusData({
          status: data.running ? 'Running' : 'Idle',
          agents: data.agents_registered,
          results: data.results_count,
          phase: data.current_phase || '-'
        });
      } catch (error) {
        console.error('Error fetching status:', error);
      }
    };

    fetchStatus();
    const interval = setInterval(fetchStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  const getStatusColor = (status: string) => {
    if (status === 'Running') return theme.colors.success;
    if (status === 'Idle') return theme.colors.warning;
    return theme.colors.error;
  };

  return (
    <div style={{
      background: `rgba(26, 31, 58, 0.8)`,
      border: `1px solid ${theme.colors.border}`,
      borderRadius: theme.borderRadius.md,
      padding: theme.spacing.md,
      boxShadow: theme.shadows.md,
      transition: theme.transitions.normal,
      color: theme.colors.text
    }}>
      <h2 style={{
        color: theme.colors.info,
        marginBottom: theme.spacing.md,
        paddingBottom: theme.spacing.sm,
        borderBottom: `1px solid ${theme.colors.border}`,
        fontSize: '18px',
        fontWeight: 'bold'
      }}>
        Framework Status
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
          Status:
        </span>
        <span style={{
          color: getStatusColor(statusData.status),
          fontWeight: 'bold',
          fontSize: '16px'
        }}>
          {statusData.status}
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
          Agents:
        </span>
        <span style={{
          color: theme.colors.info,
          fontWeight: 'bold',
          fontSize: '16px'
        }}>
          {statusData.agents}
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
          Results:
        </span>
        <span style={{
          color: theme.colors.success,
          fontWeight: 'bold',
          fontSize: '16px'
        }}>
          {statusData.results}
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
          Current Phase:
        </span>
        <span style={{
          color: theme.colors.text,
          fontSize: '14px'
        }}>
          {statusData.phase}
        </span>
      </div>

      <button
        onClick={() => window.location.reload()}
        style={{
          background: `linear-gradient(135deg, ${theme.colors.info} 0%, #0099cc 100%)`,
          color: '#000',
          border: 'none',
          padding: `${theme.spacing.sm} ${theme.spacing.md}`,
          borderRadius: theme.borderRadius.sm,
          cursor: 'pointer',
          fontWeight: 'bold',
          fontSize: '14px',
          transition: theme.transitions.normal,
          width: '100%',
          marginTop: theme.spacing.md
        }}
        onMouseOver={(e) => {
          e.currentTarget.style.background = `linear-gradient(135deg, ${theme.colors.primary} 0%, #00cc66 100%)`;
          e.currentTarget.style.transform = 'scale(1.05)';
        }}
        onMouseOut={(e) => {
          e.currentTarget.style.background = `linear-gradient(135deg, ${theme.colors.info} 0%, #0099cc 100%)`;
          e.currentTarget.style.transform = 'scale(1)';
        }}
      >
        Refresh
      </button>
    </div>
  );
};

export default StatusCard;