import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { useAuth } from './hooks/useAuth';
import { ThemeProvider, useTheme } from './theme/ThemeProvider';
import Dashboard from './components/Dashboard/Dashboard';
import AuthPanel from './components/AuthPanel';
import SettingsPanel from './components/SettingsPanel';
import ReportGenerator from './components/ReportGenerator';

// Layout components
const Layout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { theme } = useTheme();
  return (
    <ThemeProvider>
      <div style={{
        minHeight: '100vh',
        background: theme.colors.background,
        color: theme.colors.text,
        fontFamily: theme.fonts.family
      }}>
        <header style={{
          background: `linear-gradient(135deg, ${theme.colors.backgroundDark} 0%, ${theme.colors.background} 100%)`,
          padding: theme.spacing.md,
          borderRadius: theme.borderRadius.md,
          marginBottom: theme.spacing.md,
          border: `2px solid ${theme.colors.border}`,
          boxShadow: theme.shadows.md
        }}>
          <div style={{
            maxWidth: '1000px',
            margin: '0 auto',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center'
          }}>
            <div style={{
              display: 'flex',
              alignItems: 'center'
            }}>
              <h1 style={{
                fontSize: '24px',
                fontWeight: 'bold',
                color: theme.colors.info,
                margin: 0
              }}>
                ⚡ Apex Predator
              </h1>
            </div>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: theme.spacing.sm
            }}>
              <SettingsPanel />
            </div>
          </div>
        </header>
        <main style={{
          maxWidth: '1000px',
          margin: '0 auto',
          padding: theme.spacing.md
        }}>
          {children}
        </main>
      </div>
    </ThemeProvider>
  );
};

const PrivateRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-gray-900"></div>
      </div>
    );
  }

  return isAuthenticated ? <Layout>{children}</Layout> : <Navigate to="/login" />;
};

const App: React.FC = () => {
  return (
    <Router>
      <Routes>
        {/* Public routes */}
        <Route path="/login" element={<AuthPanel />} />
        <Route path="/register" element={<AuthPanel />} />

        {/* Private routes */}
        <Route
          path="/"
          element={
            <PrivateRoute>
              <Dashboard />
            </PrivateRoute>
          }
        />
        <Route
          path="/reports"
          element={
            <PrivateRoute>
              <ReportGenerator />
            </PrivateRoute>
          }
        />

        {/* Default redirect */}
        <Route path="*" element={<Navigate to="/" />} />
      </Routes>
    </Router>
  );
};

export default App;

