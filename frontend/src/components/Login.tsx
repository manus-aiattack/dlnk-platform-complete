import React, { useState } from 'react';
import { Shield, Key, AlertCircle, Loader2 } from 'lucide-react';
import api from '../services/api';

interface LoginProps {
  onLogin: () => void;
}

export default function Login({ onLogin }: LoginProps) {
  const [apiKey, setApiKey] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      // Login with API key
      const response = await api.post('/api/auth/login', { api_key: apiKey });
      
      // Store API key and user info
      localStorage.setItem('api_key', apiKey);
      localStorage.setItem('auth_token', response.data.token || apiKey);
      localStorage.setItem('user', JSON.stringify(response.data.user));
      
      // Set API key in headers for future requests
      api.defaults.headers.common['X-API-Key'] = apiKey;
      
      onLogin();
    } catch (err: any) {
      setError(err.response?.data?.detail || err.response?.data?.message || 'Invalid API key');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 flex items-center justify-center p-4">
      {/* Background Effects */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl animate-pulse delay-1000"></div>
      </div>

      {/* Login Card */}
      <div className="relative w-full max-w-md">
        <div className="bg-gray-800/80 backdrop-blur-sm p-8 rounded-2xl shadow-2xl border border-gray-700/50">
          {/* Logo and Title */}
          <div className="flex flex-col items-center mb-8">
            <div className="w-16 h-16 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-2xl flex items-center justify-center mb-4 shadow-lg shadow-cyan-500/20">
              <Shield className="w-10 h-10 text-white" />
            </div>
            <h1 className="text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500 mb-2">
              dLNk Attack Platform
            </h1>
            <p className="text-gray-400 text-sm text-center">
              AI-Powered Cybersecurity Testing Platform
            </p>
          </div>

          {/* Login Form */}
          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label className="block text-gray-300 font-medium mb-2 flex items-center space-x-2">
                <Key className="w-4 h-4 text-cyan-400" />
                <span>API Key</span>
              </label>
              <div className="relative">
                <input
                  type="password"
                  placeholder="Enter your API key"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  className="w-full p-4 bg-gray-700/50 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-cyan-500 border border-gray-600/50 font-mono text-sm transition-all"
                  required
                  autoComplete="off"
                />
              </div>
              <p className="text-gray-500 text-xs mt-2 flex items-center space-x-1">
                <AlertCircle className="w-3 h-3" />
                <span>Find your API key in workspace/ADMIN_KEY.txt</span>
              </p>
            </div>

            {/* Error Message */}
            {error && (
              <div className="p-4 bg-red-500/10 border border-red-500/50 rounded-lg text-red-400 text-sm flex items-start space-x-2 animate-shake">
                <AlertCircle className="w-5 h-5 flex-shrink-0 mt-0.5" />
                <span>{error}</span>
              </div>
            )}

            {/* Submit Button */}
            <button
              type="submit"
              disabled={loading}
              className="w-full bg-gradient-to-r from-cyan-500 to-blue-600 text-white p-4 rounded-lg hover:from-cyan-600 hover:to-blue-700 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed font-medium shadow-lg shadow-cyan-500/20 flex items-center justify-center space-x-2"
            >
              {loading ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  <span>Authenticating...</span>
                </>
              ) : (
                <>
                  <Shield className="w-5 h-5" />
                  <span>Login</span>
                </>
              )}
            </button>
          </form>

          {/* Footer */}
          <div className="mt-8 pt-6 border-t border-gray-700/50">
            <div className="text-center space-y-2">
              <p className="text-gray-400 text-sm">
                No account? API keys are generated automatically.
              </p>
              <p className="text-gray-500 text-xs">
                Contact admin for access or check documentation.
              </p>
            </div>
          </div>
        </div>

        {/* Version Info */}
        <div className="mt-4 text-center text-gray-500 text-xs">
          <p>Version 2.0.0 • Powered by AI</p>
        </div>
      </div>
    </div>
  );
}

