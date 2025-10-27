/**
 * Theme Provider for dLNk Attack Platform
 * Provides dark theme context to React components
 */

import React, { createContext, useContext, useState, ReactNode } from 'react';
import theme from './index';

interface ThemeContextType {
  theme: typeof theme;
  isDark: boolean;
  toggleTheme: () => void;
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

export const ThemeProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [isDark] = useState(true); // Always dark theme for dLNk

  const toggleTheme = () => {
    // Theme is always dark for dLNk, but keeping this for future extensibility
    console.log('Theme is always dark for dLNk Attack Platform');
  };

  const value = {
    theme,
    isDark,
    toggleTheme,
  };

  return (
    <ThemeContext.Provider value={value}>
      {children}
    </ThemeContext.Provider>
  );
};

export const useTheme = () => {
  const context = useContext(ThemeContext);
  if (context === undefined) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
};

export default ThemeProvider;