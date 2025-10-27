import React from 'react';
import { useTheme } from '../../theme/ThemeProvider';

interface Agent {
  name: string;
  status: string;
  lastSeen: string;
}

const AgentList: React.FC = () => {
  const { theme } = useTheme();
  const [agents, setAgents] = React.useState<Agent[]>([]);
  const [loading, setLoading] = React.useState(true);

  React.useEffect(() => {
    const fetchAgents = async () => {
      try {
        const response = await fetch('/agents');
        const data = await response.json();

        // Transform data to match our interface
        const agentList = data.agents || [];
        setAgents(agentList);
      } catch (error) {
        console.error('Error fetching agents:', error);
        setAgents([
          { name: 'NmapScanAgent', status: 'active', lastSeen: '2m ago' },
          { name: 'WebScannerAgent', status: 'active', lastSeen: '5m ago' },
          { name: 'VulnScannerAgent', status: 'idle', lastSeen: '10m ago' }
        ]);
      } finally {
        setLoading(false);
      }
    };

    fetchAgents();
    const interval = setInterval(fetchAgents, 30000);
    return () => clearInterval(interval);
  }, []);

  const getStatusColor = (status: string) => {
    if (status === 'active') return theme.colors.success;
    if (status === 'idle') return theme.colors.warning;
    return theme.colors.error;
  };

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
        Available Agents
      </h2>

      {loading ? (
        <div style={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          padding: theme.spacing.md
        }}>
          <div style={{
            border: `4px solid rgba(0, 212, 255, 0.3)`,
            borderTop: `4px solid ${theme.colors.info}`,
            borderRadius: '50%',
            width: '20px',
            height: '20px',
            animation: 'spin 1s linear infinite',
            display: 'inline-block'
          }}></div>
          <span style={{
            marginLeft: theme.spacing.sm,
            color: theme.colors.textSecondary,
            fontSize: '14px'
          }}>
            Loading agents...
          </span>
        </div>
      ) : (
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))',
          gap: theme.spacing.sm,
          marginTop: theme.spacing.md
        }}>
          {agents.length === 0 ? (
            <div style={{
              gridColumn: '1 / -1',
              textAlign: 'center',
              color: theme.colors.textMuted,
              padding: theme.spacing.md
            }}>
              No agents available
            </div>
          ) : (
            agents.map((agent, index) => (
              <div
                key={index}
                style={{
                  background: `rgba(0, 212, 255, 0.1)`,
                  border: `1px solid ${theme.colors.info}`,
                  borderRadius: theme.borderRadius.sm,
                  padding: theme.spacing.sm,
                  textAlign: 'center',
                  cursor: 'pointer',
                  transition: theme.transitions.normal
                }}
                onMouseOver={(e) => {
                  e.currentTarget.style.background = `rgba(0, 212, 255, 0.2)`;
                  e.currentTarget.style.borderColor = theme.colors.primary;
                }}
                onMouseOut={(e) => {
                  e.currentTarget.style.background = `rgba(0, 212, 255, 0.1)`;
                  e.currentTarget.style.borderColor = theme.colors.info;
                }}
              >
                <p style={{
                  color: theme.colors.info,
                  fontSize: '14px',
                  margin: 0,
                  fontWeight: 'bold'
                }}>
                  {agent.name}
                </p>
                <div style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginTop: theme.spacing.xs
                }}>
                  <span style={{
                    color: getStatusColor(agent.status),
                    fontSize: '12px'
                  }}>
                    {agent.status}
                  </span>
                  <span style={{
                    color: theme.colors.textMuted,
                    fontSize: '10px'
                  }}>
                    {agent.lastSeen}
                  </span>
                </div>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
};

export default AgentList;