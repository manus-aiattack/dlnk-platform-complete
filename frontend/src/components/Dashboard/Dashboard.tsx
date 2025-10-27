import React from 'react';
import { useTheme } from '../../theme/ThemeProvider';
import StatusCard from './StatusCard';
import QuickActions from './QuickActions';
import SystemInfo from './SystemInfo';
import AgentList from './AgentList';
import LiveLogs from './LiveLogs';

const Dashboard: React.FC = () => {
  const { theme, isDark } = useTheme();

  return (
    <div style={{
      fontFamily: theme.fonts.family,
      background: theme.colors.background,
      color: theme.colors.text,
      minHeight: '100vh',
      padding: theme.spacing.md
    }}>
      <header style={{
        background: `linear-gradient(135deg, ${theme.colors.backgroundDark} 0%, ${theme.colors.background} 100%)`,
        padding: theme.spacing.md,
        borderRadius: theme.borderRadius.md,
        marginBottom: theme.spacing.md,
        border: `2px solid ${theme.colors.border}`,
        boxShadow: theme.shadows.md
      }}>
        <h1 style={{
          color: theme.colors.info,
          fontSize: '28px',
          margin: 0,
          textAlign: 'center'
        }}>
          ⚡ Apex Predator - Autonomous Penetration Testing Framework
        </h1>
        <p style={{
          color: theme.colors.textSecondary,
          fontSize: '14px',
          textAlign: 'center',
          marginTop: theme.spacing.xs
        }}>
          Real-time Dashboard & Control Center
        </p>
      </header>

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
        gap: theme.spacing.md,
        marginBottom: theme.spacing.md
      }}>
        <StatusCard />
        <QuickActions />
        <SystemInfo />
      </div>

      <div style={{
        display: 'grid',
        gap: theme.spacing.md
      }}>
        <AgentList />
        <LiveLogs />
      </div>
    </div>
  );
};

export default Dashboard;