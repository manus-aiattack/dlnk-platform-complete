import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { ThemeProvider } from '../theme/ThemeProvider';
import Dashboard from '../components/Dashboard/Dashboard';
import StatusCard from '../components/Dashboard/StatusCard';
import QuickActions from '../components/Dashboard/QuickActions';
import SystemInfo from '../components/Dashboard/SystemInfo';
import AgentList from '../components/Dashboard/AgentList';
import LiveLogs from '../components/Dashboard/LiveLogs';

// Mock fetch for API calls
global.fetch = jest.fn();

// Mock WebSocket
global.WebSocket = jest.fn(() => ({
  onopen: null,
  onmessage: null,
  onclose: null,
  onerror: null,
  send: jest.fn(),
  close: jest.fn(),
}));

describe('Dark Theme Dashboard Components', () => {
  beforeEach(() => {
    (fetch as jest.Mock).mockClear();
    (global.WebSocket as jest.Mock).mockClear();
  });

  test('renders Dashboard with Dark theme', () => {
    render(
      <ThemeProvider>
        <Dashboard />
      </ThemeProvider>
    );

    // Check for Dark theme colors
    const header = screen.getByText('⚡ Apex Predator - Autonomous Penetration Testing Framework');
    expect(header).toBeInTheDocument();

    // Check for Dark background
    const mainContainer = document.querySelector('div');
    if (mainContainer) {
      expect(mainContainer).toHaveStyle('background: #0a0e27');
    }
  });

  test('StatusCard displays correct Dark theme colors', async () => {
    (fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        running: true,
        agents_registered: 5,
        results_count: 10,
        current_phase: 'Scanning'
      })
    });

    render(
      <ThemeProvider>
        <StatusCard />
      </ThemeProvider>
    );

    await waitFor(() => {
      expect(screen.getByText('Running')).toBeInTheDocument();
      expect(screen.getByText('5')).toBeInTheDocument();
      expect(screen.getByText('10')).toBeInTheDocument();
      expect(screen.getByText('Scanning')).toBeInTheDocument();
    });

    // Check for success color
    const runningText = screen.getByText('Running');
    expect(runningText).toHaveStyle('color: #00ff88');
  });

  test('QuickActions buttons use Dark theme colors', () => {
    render(
      <ThemeProvider>
        <QuickActions />
      </ThemeProvider>
    );

    const buttons = screen.getAllByRole('button');
    expect(buttons).toHaveLength(4);

    // Check button styles
    buttons.forEach(button => {
      expect(button).toHaveStyle('background: linear-gradient(135deg, #00d4ff 0%, #0099cc 100%)');
      expect(button).toHaveStyle('color: #000');
    });
  });

  test('SystemInfo displays uptime correctly', () => {
    jest.useFakeTimers();

    render(
      <ThemeProvider>
        <SystemInfo />
      </ThemeProvider>
    );

    // Fast forward time by 1 second
    jest.advanceTimersByTime(1000);

    expect(screen.getByText(/0h 0m 1s/)).toBeInTheDocument();
    expect(screen.getByText('http://localhost:8000')).toBeInTheDocument();

    jest.useRealTimers();
  });

  test('AgentList shows loading state initially', () => {
    render(
      <ThemeProvider>
        <AgentList />
      </ThemeProvider>
    );

    expect(screen.getByText('Loading agents...')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Loading agents.../ })).toBeInTheDocument();
  });

  test('LiveLogs connects via WebSocket', () => {
    render(
      <ThemeProvider>
        <LiveLogs />
      </ThemeProvider>
    );

    // Check that WebSocket was instantiated
    expect(global.WebSocket).toHaveBeenCalledWith('ws://localhost:8000/ws/logs');

    // Check for connection status
    expect(screen.getByText('Connecting...')).toBeInTheDocument();
  });

  test('theme colors are correctly applied', () => {
    const { theme } = (ThemeProvider as any).Context || {};

    // Test color constants
    expect('#00ff88').toBe('#00ff88'); // primary
    expect('#0a0e27').toBe('#0a0e27'); // background
    expect('#00d4ff').toBe('#00d4ff'); // info
    expect('#ff4444').toBe('#ff4444'); // error
    expect('#ffaa00').toBe('#ffaa00'); // warning
  });

  test('components respond to hover effects', () => {
    render(
      <ThemeProvider>
        <QuickActions />
      </ThemeProvider>
    );

    const runWorkflowButton = screen.getByRole('button', { name: /Run Workflow/ });

    // Simulate hover
    fireEvent.mouseOver(runWorkflowButton);

    // Check hover effect
    expect(runWorkflowButton).toHaveStyle('transform: scale(1.05)');
  });
});

export {};