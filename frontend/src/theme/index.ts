/**
 * Theme Configuration for dLNk Attack Platform
 * Dark theme with green, black, and red color scheme
 */

export const colors = {
  // Primary colors
  primary: '#00ff88',        // Electric Green
  primaryDark: '#00cc6a',    // Darker Green
  primaryLight: '#00ff99',   // Lighter Green

  // Background colors
  background: '#0a0e27',     // Deep Space Blue
  backgroundDark: '#080c20', // Darker Background
  backgroundLight: '#1a1f3a', // Lighter Background
  surface: 'rgba(26, 31, 58, 0.9)', // Surface color

  // Text colors
  text: '#e0e0e0',          // Light Gray
  textSecondary: '#b0b0b0',  // Secondary Gray
  textMuted: '#808080',      // Muted Gray

  // Status colors
  success: '#00ff88',        // Green
  warning: '#ffaa00',        // Orange
  error: '#ff4444',          // Red
  info: '#00d4ff',          // Light Blue

  // Border colors
  border: 'rgba(0, 255, 136, 0.3)', // Green Border
  borderHover: '#00ff88',    // Hover Border

  // Special colors
  accent: '#ff4444',         // Red Accent
  accentLight: '#ff6666',    // Light Red
  online: '#00ff88',         // Online Indicator
  offline: '#ff4444',        // Offline Indicator
} as const;

export const theme = {
  colors,
  spacing: {
    xs: '4px',
    sm: '8px',
    md: '16px',
    lg: '24px',
    xl: '32px',
    xxl: '48px',
  },
  borderRadius: {
    sm: '4px',
    md: '8px',
    lg: '12px',
    xl: '16px',
    full: '9999px',
  },
  shadows: {
    sm: '0 2px 4px rgba(0, 0, 0, 0.3)',
    md: '0 4px 8px rgba(0, 0, 0, 0.3)',
    lg: '0 8px 16px rgba(0, 0, 0, 0.3)',
    xl: '0 16px 32px rgba(0, 0, 0, 0.3)',
  },
  fonts: {
    family: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
    monospace: "'Courier New', monospace",
    sizes: {
      xs: '12px',
      sm: '14px',
      md: '16px',
      lg: '18px',
      xl: '20px',
      xxl: '24px',
    },
  },
  transitions: {
    fast: '0.15s ease',
    normal: '0.3s ease',
    slow: '0.5s ease',
  },
} as const;

export default theme;