/*
Enhanced Frontend Dashboard with Real-time Updates
Phase 6: Frontend Enhancement - React TypeScript Dashboard
*/

import React, { useState, useEffect, useRef } from 'react';
import { io, Socket } from 'socket.io-client';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  AreaChart,
  Area
} from 'recharts';
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
  CardFooter
} from './ui/card';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import { Progress } from './ui/progress';
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from './ui/alert';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from './ui/table';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs';
import { ScrollArea } from './ui/scroll-area';
import { Separator } from './ui/separator';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from './ui/dialog';
import { Input } from './ui/input';
import { Label } from './ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from './ui/select';

// Types
interface Attack {
  id: string;
  target: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  progress: number;
  currentPhase: string;
  startTime: string;
  endTime?: string;
  agents: Agent[];
  results?: AttackResults;
}

interface Agent {
  id: string;
  name: string;
  type: string;
  status: 'idle' | 'running' | 'completed' | 'failed';
  lastActivity: string;
  performanceMetrics: PerformanceMetrics;
}

interface PerformanceMetrics {
  cpuUsage: number;
  memoryUsage: number;
  executionTime: number;
  successRate: number;
}

interface SystemHealth {
  cpuUsage: number;
  memoryUsage: number;
  diskUsage: number;
  networkIO: number;
  activeConnections: number;
  errorRate: number;
  timestamp: string;
}

interface AttackResults {
  vulnerabilities: Vulnerability[];
  findings: string[];
  recommendations: string[];
}

interface Vulnerability {
  id: string;
  name: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  cve?: string;
  cvssScore: number;
  description: string;
  exploitability: 'high' | 'medium' | 'low';
}

interface WebSocketMessage {
  type: string;
  data: any;
  timestamp: string;
  clientId?: string;
  sessionId?: string;
}

// Enhanced Attack Dashboard Component
const AttackDashboard: React.FC = () => {
  // State
  const [attacks, setAttacks] = useState<Attack[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [systemHealth, setSystemHealth] = useState<SystemHealth | null>(null);
  const [selectedAttack, setSelectedAttack] = useState<Attack | null>(null);
  const [socket, setSocket] = useState<Socket | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [performanceData, setPerformanceData] = useState<any[]>([]);
  const [attackHistory, setAttackHistory] = useState<Attack[]>([]);

  // WebSocket connection
  useEffect(() => {
    const wsUrl = process.env.REACT_APP_WEBSOCKET_URL || 'ws://localhost:8000';
    const ws = io(wsUrl, {
      transports: ['websocket'],
      timeout: 10000,
    });

    ws.on('connect', () => {
      console.log('Connected to WebSocket server');
      setIsConnected(true);
      ws.emit('subscribe', { channel: 'attacks' });
      ws.emit('subscribe', { channel: 'agents' });
      ws.emit('subscribe', { channel: 'system' });
    });

    ws.on('disconnect', () => {
      console.log('Disconnected from WebSocket server');
      setIsConnected(false);
    });

    ws.on('channel.attacks', (data: any) => {
      handleAttackUpdate(data);
    });

    ws.on('channel.agents', (data: any) => {
      handleAgentUpdate(data);
    });

    ws.on('channel.system', (data: any) => {
      handleSystemUpdate(data);
    });

    setSocket(ws);

    return () => {
      ws.disconnect();
    };
  }, []);

  // Handle attack updates
  const handleAttackUpdate = (data: any) => {
    switch (data.event) {
      case 'attack_started':
        setAttacks(prev => [...prev, {
          id: data.attack_id,
          target: data.target.url || data.target,
          status: 'running',
          progress: 0,
          currentPhase: 'initializing',
          startTime: data.timestamp,
          agents: []
        }]);
        break;
      case 'attack_progress':
        setAttacks(prev => prev.map(attack =>
          attack.id === data.attack_id
            ? { ...attack, progress: data.progress, currentPhase: data.phase, status: data.status }
            : attack
        ));
        break;
      case 'attack_completed':
        setAttacks(prev => prev.map(attack =>
          attack.id === data.attack_id
            ? { ...attack, status: data.success ? 'completed' : 'failed', endTime: data.timestamp, results: data.results }
            : attack
        ));
        break;
    }
  };

  // Handle agent updates
  const handleAgentUpdate = (data: any) => {
    switch (data.event) {
      case 'agent_status_update':
        setAgents(prev => {
          const existingIndex = prev.findIndex(agent => agent.name === data.agent_name);
          if (existingIndex >= 0) {
            return prev.map((agent, index) =>
              index === existingIndex
                ? { ...agent, status: data.status, lastActivity: data.timestamp }
                : agent
            );
          } else {
            return [...prev, {
              id: data.agent_name,
              name: data.agent_name,
              type: data.details?.type || 'unknown',
              status: data.status,
              lastActivity: data.timestamp,
              performanceMetrics: {
                cpuUsage: 0,
                memoryUsage: 0,
                executionTime: 0,
                successRate: 0.8
              }
            }];
          }
        });
        break;
    }
  };

  // Handle system updates
  const handleSystemUpdate = (data: any) => {
    switch (data.event) {
      case 'system_health_update':
        setSystemHealth(data.health_data);
        break;
    }
  };

  // Performance data generation for charts
  useEffect(() => {
    const generatePerformanceData = () => {
      const now = new Date();
      const data = [];
      for (let i = 24; i >= 0; i--) {
        const timestamp = new Date(now.getTime() - i * 60000).toLocaleTimeString();
        data.push({
          time: timestamp,
          cpu: Math.random() * 30 + 20,
          memory: Math.random() * 20 + 40,
          attacks: Math.floor(Math.random() * 5),
          successRate: Math.random() * 20 + 80
        });
      }
      setPerformanceData(data);
    };

    generatePerformanceData();
    const interval = setInterval(generatePerformanceData, 60000); // Update every minute

    return () => clearInterval(interval);
  }, []);

  // Execute new attack
  const executeAttack = async (target: string, attackType: string) => {
    try {
      const response = await fetch('/api/v2/attacks/execute', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({
          target: { url: target },
          type: attackType,
          phase: 'reconnaissance'
        })
      });

      if (response.ok) {
        const result = await response.json();
        console.log('Attack executed:', result);
      }
    } catch (error) {
      console.error('Failed to execute attack:', error);
    }
  };

  // Get agent status color
  const getAgentStatusColor = (status: string) => {
    switch (status) {
      case 'running': return 'bg-yellow-500';
      case 'completed': return 'bg-green-500';
      case 'failed': return 'bg-red-500';
      default: return 'bg-gray-500';
    }
  };

  // Get attack status color
  const getAttackStatusColor = (status: string) => {
    switch (status) {
      case 'running': return 'bg-blue-500';
      case 'completed': return 'bg-green-500';
      case 'failed': return 'bg-red-500';
      default: return 'bg-gray-500';
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center">
              <h1 className="text-2xl font-bold text-gray-900">Manus AI Attack Platform</h1>
              <Badge variant="secondary" className={`ml-4 ${isConnected ? 'bg-green-500' : 'bg-red-500'}`}>
                {isConnected ? '🟢 Connected' : '🔴 Disconnected'}
              </Badge>
            </div>
            <div className="flex items-center space-x-4">
              <Button variant="outline" onClick={() => window.location.reload()}>
                Refresh
              </Button>
              <Button>
                New Attack
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <Tabs defaultValue="overview" className="space-y-8">
          <TabsList className="grid w-full grid-cols-5">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="attacks">Active Attacks</TabsTrigger>
            <TabsTrigger value="agents">Agents</TabsTrigger>
            <TabsTrigger value="performance">Performance</TabsTrigger>
            <TabsTrigger value="reports">Reports</TabsTrigger>
          </TabsList>

          {/* Overview Tab */}
          <TabsContent value="overview">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
              {/* System Health Card */}
              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">System Health</CardTitle>
                  <div className={`h-3 w-3 rounded-full ${systemHealth?.cpu_usage < 80 ? 'bg-green-500' : 'bg-red-500'}`} />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">
                    {systemHealth ? `${systemHealth.cpu_usage.toFixed(1)}%` : 'N/A'}
                  </div>
                  <p className="text-xs text-gray-600">CPU Usage</p>
                </CardContent>
              </Card>

              {/* Active Attacks Card */}
              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Active Attacks</CardTitle>
                  <svg className="h-4 w-4 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                  </svg>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{attacks.filter(a => a.status === 'running').length}</div>
                  <p className="text-xs text-gray-600">In Progress</p>
                </CardContent>
              </Card>

              {/* Agents Status Card */}
              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Agents</CardTitle>
                  <svg className="h-4 w-4 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                  </svg>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{agents.length}</div>
                  <p className="text-xs text-gray-600">Total Agents</p>
                </CardContent>
              </Card>

              {/* Success Rate Card */}
              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Success Rate</CardTitle>
                  <svg className="h-4 w-4 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">
                    {agents.length > 0 ? `${(agents.reduce((sum, agent) => sum + agent.performanceMetrics.successRate, 0) / agents.length * 100).toFixed(1)}%` : 'N/A'}
                  </div>
                  <p className="text-xs text-gray-600">Average Success Rate</p>
                </CardContent>
              </Card>
            </div>

            {/* Performance Charts */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>System Performance</CardTitle>
                  <CardDescription>CPU, Memory, and Network Usage</CardDescription>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={300}>
                    <LineChart data={performanceData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="time" />
                      <YAxis />
                      <Tooltip />
                      <Legend />
                      <Line type="monotone" dataKey="cpu" stroke="#8884d8" name="CPU Usage (%)" />
                      <Line type="monotone" dataKey="memory" stroke="#82ca9d" name="Memory Usage (%)" />
                    </LineChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Attack Performance</CardTitle>
                  <CardDescription>Attacks and Success Rate</CardDescription>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={300}>
                    <AreaChart data={performanceData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="time" />
                      <YAxis />
                      <Tooltip />
                      <Legend />
                      <Area type="monotone" dataKey="attacks" stackId="1" stroke="#8884d8" fill="#8884d8" name="Active Attacks" />
                      <Area type="monotone" dataKey="successRate" stackId="2" stroke="#82ca9d" fill="#82ca9d" name="Success Rate (%)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Active Attacks Tab */}
          <TabsContent value="attacks">
            <div className="space-y-6">
              <div className="flex justify-between items-center">
                <h2 className="text-xl font-semibold">Active Attacks</h2>
                <Dialog>
                  <DialogTrigger asChild>
                    <Button>Launch New Attack</Button>
                  </DialogTrigger>
                  <DialogContent>
                    <DialogHeader>
                      <DialogTitle>Launch New Attack</DialogTitle>
                      <DialogDescription>Configure and launch a new penetration test</DialogDescription>
                    </DialogHeader>
                    <div className="space-y-4 py-4">
                      <div>
                        <Label htmlFor="target">Target URL/IP</Label>
                        <Input id="target" placeholder="https://example.com or 192.168.1.1" />
                      </div>
                      <div>
                        <Label htmlFor="attackType">Attack Type</Label>
                        <Select>
                          <SelectTrigger>
                            <SelectValue placeholder="Select attack type" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="web">Web Application</SelectItem>
                            <SelectItem value="network">Network</SelectItem>
                            <SelectItem value="database">Database</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <Button className="w-full">Launch Attack</Button>
                    </div>
                  </DialogContent>
                </Dialog>
              </div>

              <div className="grid gap-6">
                {attacks.map((attack) => (
                  <Card key={attack.id}>
                    <CardHeader>
                      <div className="flex justify-between items-start">
                        <div>
                          <CardTitle className="text-lg">{attack.target}</CardTitle>
                          <CardDescription>Attack ID: {attack.id}</CardDescription>
                        </div>
                        <Badge className={getAttackStatusColor(attack.status)}>
                          {attack.status.toUpperCase()}
                        </Badge>
                      </div>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-4">
                        <div className="flex justify-between items-center">
                          <span>Current Phase: {attack.currentPhase}</span>
                          <span className="text-sm text-gray-500">{attack.progress.toFixed(1)}%</span>
                        </div>
                        <Progress value={attack.progress} className="w-full" />
                        <div className="grid grid-cols-2 gap-4 text-sm">
                          <div>
                            <span className="text-gray-500">Start Time:</span>
                            <br />
                            {new Date(attack.startTime).toLocaleString()}
                          </div>
                          <div>
                            <span className="text-gray-500">Agents:</span>
                            <br />
                            {attack.agents.length}
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>
          </TabsContent>

          {/* Agents Tab */}
          <TabsContent value="agents">
            <Card>
              <CardHeader>
                <CardTitle>Agent Status</CardTitle>
                <CardDescription>Real-time status of all agents</CardDescription>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Agent Name</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Last Activity</TableHead>
                      <TableHead>Performance</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {agents.map((agent) => (
                      <TableRow key={agent.id}>
                        <TableCell className="font-medium">{agent.name}</TableCell>
                        <TableCell>{agent.type}</TableCell>
                        <TableCell>
                          <div className="flex items-center space-x-2">
                            <div className={`h-2 w-2 rounded-full ${getAgentStatusColor(agent.status)}`} />
                            <span>{agent.status}</span>
                          </div>
                        </TableCell>
                        <TableCell>
                          {new Date(agent.lastActivity).toLocaleString()}
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center space-x-2">
                            <Progress value={agent.performanceMetrics.successRate * 100} className="w-20" />
                            <span className="text-sm">{(agent.performanceMetrics.successRate * 100).toFixed(1)}%</span>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Performance Tab */}
          <TabsContent value="performance">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>System Metrics</CardTitle>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={400}>
                    <BarChart data={performanceData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="time" />
                      <YAxis />
                      <Tooltip />
                      <Legend />
                      <Bar dataKey="cpu" fill="#8884d8" name="CPU Usage (%)" />
                      <Bar dataKey="memory" fill="#82ca9d" name="Memory Usage (%)" />
                    </BarChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Attack Distribution</CardTitle>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={400}>
                    <PieChart>
                      <Pie
                        data={[
                          { name: 'Web', value: 45 },
                          { name: 'Network', value: 30 },
                          { name: 'Database', value: 15 },
                          { name: 'Other', value: 10 }
                        ]}
                        cx="50%"
                        cy="50%"
                        labelLine={false}
                        label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                        outerRadius={80}
                        fill="#8884d8"
                        dataKey="value"
                      >
                        {[
                          { name: 'Web', value: 45, color: '#8884d8' },
                          { name: 'Network', value: 30, color: '#82ca9d' },
                          { name: 'Database', value: 15, color: '#ffc658' },
                          { name: 'Other', value: 10, color: '#ff7300' }
                        ].map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip />
                    </PieChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Reports Tab */}
          <TabsContent value="reports">
            <div className="space-y-6">
              <h2 className="text-xl font-semibold">Recent Reports</h2>
              <div className="grid gap-6">
                {attackHistory.map((attack) => (
                  <Card key={attack.id}>
                    <CardHeader>
                      <CardTitle>{attack.target} - {attack.status}</CardTitle>
                      <CardDescription>
                        Completed: {new Date(attack.endTime || attack.startTime).toLocaleString()}
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      {attack.results ? (
                        <div className="space-y-4">
                          <div>
                            <h4 className="font-medium">Vulnerabilities Found:</h4>
                            <ul className="list-disc list-inside text-sm text-gray-600">
                              {attack.results.vulnerabilities.map((vuln) => (
                                <li key={vuln.id} className="flex items-center space-x-2">
                                  <Badge variant={vuln.severity === 'critical' ? 'destructive' : 'secondary'}>
                                    {vuln.severity.toUpperCase()}
                                  </Badge>
                                  <span>{vuln.name}</span>
                                  <span className="text-gray-500">({vuln.cvssScore}/10)</span>
                                </li>
                              ))}
                            </ul>
                          </div>
                          <div>
                            <h4 className="font-medium">Recommendations:</h4>
                            <ul className="list-disc list-inside text-sm text-gray-600">
                              {attack.results.recommendations.map((rec, index) => (
                                <li key={index}>{rec}</li>
                              ))}
                            </ul>
                          </div>
                        </div>
                      ) : (
                        <p className="text-gray-500">No results available yet.</p>
                      )}
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
};

export default AttackDashboard;