#!/bin/bash
# Complete Frontend Setup Script
# This script creates ALL missing files for the frontend

cd ~/manus/frontend

echo "Creating complete package.json with all dependencies..."
cat > package.json << 'EOF'
{
  "name": "manus-frontend",
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.20.0",
    "axios": "^1.6.0",
    "lucide-react": "^0.294.0",
    "socket.io-client": "^4.5.4"
  },
  "devDependencies": {
    "@types/react": "^18.2.0",
    "@types/react-dom": "^18.2.0",
    "@vitejs/plugin-react": "^4.2.0",
    "autoprefixer": "^10.4.16",
    "postcss": "^8.4.32",
    "tailwindcss": "^3.3.6",
    "typescript": "^5.3.0",
    "vite": "^5.0.0"
  }
}
EOF

echo "Creating missing components..."

# Layout component
mkdir -p src/components
cat > src/components/Layout.tsx << 'EOF'
import React from 'react';

interface LayoutProps {
  children: React.ReactNode;
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  return (
    <div className="min-h-screen bg-gray-900">
      <nav className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center">
              <span className="text-white text-xl font-bold">Manus Attack Platform</span>
            </div>
            <div className="flex space-x-4">
              <a href="/" className="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium">
                Dashboard
              </a>
              <a href="/attacks" className="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium">
                Attacks
              </a>
              <a href="/c2" className="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium">
                C2
              </a>
              <a href="/targets" className="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium">
                Targets
              </a>
              <a href="/agents" className="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium">
                Agents
              </a>
            </div>
          </div>
        </div>
      </nav>
      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        {children}
      </main>
    </div>
  );
};

export default Layout;
EOF

# Login component
cat > src/components/Login.tsx << 'EOF'
import React, { useState } from 'react';

interface LoginProps {
  onLogin: () => void;
}

const Login: React.FC<LoginProps> = ({ onLogin }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // Simple demo login
    if (username && password) {
      localStorage.setItem('auth_token', 'demo_token');
      onLogin();
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-900">
      <div className="max-w-md w-full space-y-8 p-8 bg-gray-800 rounded-lg">
        <h2 className="text-3xl font-bold text-white text-center">Manus Login</h2>
        <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
          <div>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Username"
              className="w-full px-3 py-2 border border-gray-600 rounded-md bg-gray-700 text-white"
            />
          </div>
          <div>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Password"
              className="w-full px-3 py-2 border border-gray-600 rounded-md bg-gray-700 text-white"
            />
          </div>
          <button
            type="submit"
            className="w-full py-2 px-4 bg-blue-600 hover:bg-blue-700 text-white rounded-md"
          >
            Sign In
          </button>
        </form>
      </div>
    </div>
  );
};

export default Login;
EOF

# C2Manager component
cat > src/components/C2Manager.tsx << 'EOF'
import React from 'react';

const C2Manager: React.FC = () => {
  return (
    <div className="bg-gray-800 rounded-lg p-6">
      <h2 className="text-2xl font-bold text-white mb-4">C2 Server Management</h2>
      <p className="text-gray-300">C2 server management interface</p>
    </div>
  );
};

export default C2Manager;
EOF

# TargetManager component
cat > src/components/TargetManager.tsx << 'EOF'
import React from 'react';

const TargetManager: React.FC = () => {
  return (
    <div className="bg-gray-800 rounded-lg p-6">
      <h2 className="text-2xl font-bold text-white mb-4">Target Management</h2>
      <p className="text-gray-300">Target management interface</p>
    </div>
  );
};

export default TargetManager;
EOF

# AgentList component
cat > src/components/AgentList.tsx << 'EOF'
import React from 'react';

const AgentList: React.FC = () => {
  return (
    <div className="bg-gray-800 rounded-lg p-6">
      <h2 className="text-2xl font-bold text-white mb-4">Agent List</h2>
      <p className="text-gray-300">Agent list interface</p>
    </div>
  );
};

export default AgentList;
EOF

# AttackTimeline component
cat > src/components/AttackTimeline.tsx << 'EOF'
import React from 'react';

const AttackTimeline: React.FC = () => {
  return (
    <div className="bg-gray-700 rounded-lg p-4">
      <h3 className="text-lg font-semibold text-white mb-2">Attack Timeline</h3>
      <p className="text-gray-300 text-sm">Timeline visualization</p>
    </div>
  );
};

export default AttackTimeline;
EOF

# VulnerabilityChart component
cat > src/components/VulnerabilityChart.tsx << 'EOF'
import React from 'react';

const VulnerabilityChart: React.FC = () => {
  return (
    <div className="bg-gray-700 rounded-lg p-4">
      <h3 className="text-lg font-semibold text-white mb-2">Vulnerability Chart</h3>
      <p className="text-gray-300 text-sm">Vulnerability statistics</p>
    </div>
  );
};

export default VulnerabilityChart;
EOF

# ActiveAttacks component
cat > src/components/ActiveAttacks.tsx << 'EOF'
import React from 'react';

const ActiveAttacks: React.FC = () => {
  return (
    <div className="bg-gray-700 rounded-lg p-4">
      <h3 className="text-lg font-semibold text-white mb-2">Active Attacks</h3>
      <p className="text-gray-300 text-sm">Currently running attacks</p>
    </div>
  );
};

export default ActiveAttacks;
EOF

# Update vite.config.ts to include env
cat > vite.config.ts << 'EOF'
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  define: {
    'import.meta.env': {
      VITE_API_URL: JSON.stringify(process.env.VITE_API_URL || 'http://localhost:8000'),
      VITE_WS_URL: JSON.stringify(process.env.VITE_WS_URL || 'ws://localhost:8000')
    }
  },
  server: {
    host: '0.0.0.0',
    port: 3000
  }
});
EOF

# Create .env file for vite
cat > .env << 'EOF'
VITE_API_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000
EOF

# Update tsconfig.json to fix env issues
cat > tsconfig.json << 'EOF'
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": false,
    "noUnusedLocals": false,
    "noUnusedParameters": false,
    "noFallthroughCasesInSwitch": true,
    "types": ["vite/client"]
  },
  "include": ["src"],
  "references": [{ "path": "./tsconfig.node.json" }]
}
EOF

# Create vite-env.d.ts for env types
cat > src/vite-env.d.ts << 'EOF'
/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_URL: string
  readonly VITE_WS_URL: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
EOF

echo "✅ All files created successfully!"
echo ""
echo "Now run:"
echo "  cd ~/manus"
echo "  docker compose -f docker-compose.production.yml build"

