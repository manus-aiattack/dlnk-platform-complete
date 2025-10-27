# dLNk Attack Platform - Frontend

Modern React-based frontend for the dLNk Attack Platform with real-time monitoring, AI-powered attack suggestions, and comprehensive security testing capabilities.

## 🚀 Features

- **Real-time Dashboard** - Live monitoring of attacks, vulnerabilities, and system status
- **Attack Manager** - Comprehensive attack orchestration with AI suggestions
- **C2 Infrastructure** - Command & Control server management
- **Target Management** - Scan and analyze potential targets
- **AI Agents** - Deploy and manage AI-powered security agents
- **Nmap Integration** - Built-in network scanning capabilities
- **Self-Healing** - Automatic error detection and recovery
- **Self-Learning** - Continuous improvement through machine learning
- **Parallel Execution** - Efficient task distribution and execution

## 🛠️ Tech Stack

- **Framework**: React 18 + TypeScript
- **Build Tool**: Vite
- **Styling**: Tailwind CSS
- **Routing**: React Router v6
- **Charts**: Chart.js + react-chartjs-2
- **Icons**: Lucide React
- **HTTP Client**: Axios
- **Real-time**: WebSocket

## 📦 Installation

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
```

## 🔧 Configuration

Create a `.env` file in the frontend directory:

```env
VITE_API_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000/ws
```

## 📁 Project Structure

```
frontend/
├── src/
│   ├── components/          # React components
│   │   ├── Layout.tsx       # Main layout wrapper
│   │   ├── Login.tsx        # Authentication page
│   │   ├── Dashboard.tsx    # Main dashboard
│   │   ├── AttackManager.tsx    # Attack management
│   │   ├── C2Manager.tsx    # C2 infrastructure
│   │   ├── TargetManager.tsx    # Target management
│   │   └── AgentList.tsx    # AI agents list
│   ├── services/            # API services
│   │   ├── api.ts           # Base API client
│   │   ├── websocket.ts     # WebSocket service
│   │   ├── nmap.ts          # Nmap integration
│   │   ├── ai.ts            # AI services
│   │   ├── healing.ts       # Self-healing
│   │   ├── learning.ts      # Self-learning
│   │   └── executor.ts      # Parallel execution
│   ├── styles/              # Global styles
│   ├── App.tsx              # Main app component
│   └── main.tsx             # Entry point
├── public/                  # Static assets
├── index.html               # HTML template
├── vite.config.ts           # Vite configuration
├── tailwind.config.js       # Tailwind configuration
├── tsconfig.json            # TypeScript configuration
├── package.json             # Dependencies
├── Dockerfile               # Docker configuration
└── nginx.conf               # Nginx configuration
```

## 🎨 Components

### Dashboard
Real-time monitoring dashboard with:
- Live statistics (active attacks, vulnerabilities, success rate)
- Attack timeline chart
- Vulnerability distribution chart
- Active attacks list with progress tracking

### Attack Manager
Comprehensive attack management with:
- Attack creation with AI suggestions
- Nmap integration for reconnaissance
- Agent selection and configuration
- Real-time progress tracking
- Attack history and results

### C2 Manager
Command & Control infrastructure management:
- Server status monitoring
- Connected agents tracking
- Server configuration
- Uptime monitoring

### Target Manager
Target scanning and analysis:
- Target list with search
- Port scanning
- Service detection
- Vulnerability assessment

### Agent List
AI agent management:
- Agent deployment
- Status monitoring
- Performance metrics
- Configuration management

## 🔌 API Integration

All API services are located in `src/services/`:

- **api.ts** - Base Axios client with authentication
- **nmap.ts** - Network scanning operations
- **ai.ts** - AI-powered analysis and suggestions
- **healing.ts** - Self-healing system monitoring
- **learning.ts** - Knowledge base and pattern learning
- **executor.ts** - Parallel task execution

## 🎯 Development

### Running Development Server

```bash
npm run dev
```

The application will be available at `http://localhost:5173`

### Building for Production

```bash
npm run build
```

Build output will be in the `dist/` directory.

### Docker Deployment

```bash
# Build Docker image
docker build -t dlnk-frontend .

# Run container
docker run -p 80:80 dlnk-frontend
```

## 🔐 Authentication

The application uses token-based authentication:
1. Login with username/password
2. Token is stored in localStorage
3. Token is included in all API requests via Authorization header
4. Automatic redirect to login if token is invalid

## 📊 Real-time Updates

WebSocket connection provides real-time updates for:
- Attack progress
- Vulnerability discoveries
- System statistics
- Agent status changes

## 🎨 Styling

The application uses a dark theme with cyan accents:
- Background: Gray-900
- Cards: Gray-800
- Primary: Cyan-500
- Text: White/Gray-400

All components are fully responsive and optimized for mobile devices.

## 🚀 Performance

- Code splitting with React.lazy
- Optimized bundle size with Vite
- Efficient re-rendering with React hooks
- Debounced search inputs
- Lazy loading of charts

## 📝 License

This project is part of the dLNk Attack Platform.

## 🤝 Contributing

Please follow the existing code style and component patterns when contributing.

## 📞 Support

For issues and questions, please refer to the main project documentation.

