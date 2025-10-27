import React from 'react';
import { useTheme } from '../../theme/ThemeProvider';

const QuickActions: React.FC = () => {
  const { theme } = useTheme();

  const handleRunWorkflow = () => {
    // Open modal or navigate to workflow execution
    console.log('Running workflow...');
  };

  const handleExecuteAgent = () => {
    // Open modal or navigate to agent execution
    console.log('Executing agent...');
  };

  const handleViewLogs = () => {
    // Navigate to logs section
    console.log('Viewing logs...');
  };

  const handleExportResults = () => {
    // Export functionality
    console.log('Exporting results...');
  };

  const buttonStyle = {
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
    marginBottom: theme.spacing.sm,
    textAlign: 'center' as const
  };

  const buttonHoverStyle = {
    background: `linear-gradient(135deg, ${theme.colors.primary} 0%, #00cc66 100%)`,
    transform: 'scale(1.05)'
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
        Quick Actions
      </h2>

      <div style={{
        display: 'flex',
        flexDirection: 'column' as const,
        gap: theme.spacing.sm
      }}>
        <button
          onClick={handleRunWorkflow}
          style={buttonStyle}
          onMouseOver={(e) => {
            Object.assign(e.currentTarget.style, buttonHoverStyle);
          }}
          onMouseOut={(e) => {
            e.currentTarget.style.background = `linear-gradient(135deg, ${theme.colors.info} 0%, #0099cc 100%)`;
            e.currentTarget.style.transform = 'scale(1)';
          }}
        >
          Run Workflow
        </button>

        <button
          onClick={handleExecuteAgent}
          style={buttonStyle}
          onMouseOver={(e) => {
            Object.assign(e.currentTarget.style, buttonHoverStyle);
          }}
          onMouseOut={(e) => {
            e.currentTarget.style.background = `linear-gradient(135deg, ${theme.colors.info} 0%, #0099cc 100%)`;
            e.currentTarget.style.transform = 'scale(1)';
          }}
        >
          Execute Agent
        </button>

        <button
          onClick={handleViewLogs}
          style={buttonStyle}
          onMouseOver={(e) => {
            Object.assign(e.currentTarget.style, buttonHoverStyle);
          }}
          onMouseOut={(e) => {
            e.currentTarget.style.background = `linear-gradient(135deg, ${theme.colors.info} 0%, #0099cc 100%)`;
            e.currentTarget.style.transform = 'scale(1)';
          }}
        >
          View Logs
        </button>

        <button
          onClick={handleExportResults}
          style={buttonStyle}
          onMouseOver={(e) => {
            Object.assign(e.currentTarget.style, buttonHoverStyle);
          }}
          onMouseOut={(e) => {
            e.currentTarget.style.background = `linear-gradient(135deg, ${theme.colors.info} 0%, #0099cc 100%)`;
            e.currentTarget.style.transform = 'scale(1)';
          }}
        >
          Export Results
        </button>
      </div>
    </div>
  );
};

export default QuickActions;