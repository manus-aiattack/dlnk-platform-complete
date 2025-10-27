import { EventEmitter } from 'events';
import { Agent, AgentConfig } from '../core/data_models';
import { AgentLoader } from '../core/agent_loader';

export interface AgentEvent {
  type: 'agent_registered' | 'agent_unregistered' | 'agent_status_changed' | 'agent_error';
  agentId: string;
  data?: any;
  timestamp: Date;
}

export class AgentManager extends EventEmitter {
  private agents: Map<string, Agent> = new Map();
  private loader: AgentLoader;
  private isMonitoring: boolean = false;
  private monitoringInterval: NodeJS.Timeout | null = null;

  constructor(pluginDir: string = 'plugins/agents') {
    super();
    this.loader = new AgentLoader(pluginDir);
    this.setupAgentMonitoring();
  }

  async initialize(): Promise<void> {
    try {
      // Load all existing agents
      const loadedAgents = await this.loader.loadAllAgents();

      for (const agent of loadedAgents) {
        this.registerAgent(agent);
      }

      // Set up file system watching for hot reload
      this.setupFileWatching();

      console.log(`Initialized AgentManager with ${loadedAgents.length} agents`);
    } catch (error) {
      console.error('Failed to initialize AgentManager:', error);
      throw error;
    }
  }

  private registerAgent(agent: Agent): void {
    this.agents.set(agent.id, agent);

    // Emit registration event
    this.emit('agent_registered', {
      type: 'agent_registered',
      agentId: agent.id,
      data: { agentName: agent.name, agentType: agent.type },
      timestamp: new Date()
    });

    console.log(`Registered agent: ${agent.name} (${agent.id})`);
  }

  private unregisterAgent(agentId: string): void {
    const agent = this.agents.get(agentId);
    if (agent) {
      this.agents.delete(agentId);

      // Emit unregistration event
      this.emit('agent_unregistered', {
        type: 'agent_unregistered',
        agentId: agentId,
        data: { agentName: agent.name, agentType: agent.type },
        timestamp: new Date()
      });

      console.log(`Unregistered agent: ${agent.name} (${agentId})`);
    }
  }

  private setupFileWatching(): void {
    try {
      const watcher = this.loader.watchAgentChanges(async (agentId, changeType) => {
        switch (changeType) {
          case 'added':
            console.log(`New agent file detected: ${agentId}`);
            const agents = await this.loader.loadAllAgents();
            for (const agent of agents) {
              if (!this.agents.has(agent.id)) {
                this.registerAgent(agent);
              }
            }
            break;
          case 'removed':
            if (this.agents.has(agentId)) {
              await this.unregisterAgent(agentId);
            }
            break;
          case 'modified':
            console.log(`Agent modified: ${agentId}`);
            // Hot reload the modified agent
            await this.reloadAgent(agentId);
            break;
        }
      });

      console.log('File watching enabled for agent hot reload');
    } catch (error) {
      console.error('Failed to setup file watching:', error);
    }
  }

  private setupAgentMonitoring(): void {
    this.monitoringInterval = setInterval(async () => {
      if (!this.isMonitoring) return;

      for (const [agentId, agent] of this.agents) {
        try {
          const status = await agent.getStatus();

          // Check for status changes
          if (status.lastStatus !== agent.lastStatus) {
            this.emit('agent_status_changed', {
              type: 'agent_status_changed',
              agentId: agentId,
              data: { oldStatus: agent.lastStatus, newStatus: status.lastStatus },
              timestamp: new Date()
            });

            agent.lastStatus = status.lastStatus;
          }
        } catch (error) {
          this.emit('agent_error', {
            type: 'agent_error',
            agentId: agentId,
            data: { error: error.message, stack: error.stack },
            timestamp: new Date()
          });
        }
      }
    }, 30000); // Check every 30 seconds
  }

  startMonitoring(): void {
    this.isMonitoring = true;
    console.log('Agent monitoring started');
  }

  stopMonitoring(): void {
    this.isMonitoring = false;
    console.log('Agent monitoring stopped');
  }

  async reloadAgent(agentId: string): Promise<boolean> {
    try {
      const agent = this.agents.get(agentId);
      if (!agent) {
        return false;
      }

      // Get agent path for reloading
      const agentPath = agent.path || '';
      const reloadedAgent = await this.loader.reloadAgent(agentId);

      if (reloadedAgent) {
        this.unregisterAgent(agentId);
        this.registerAgent(reloadedAgent);
        return true;
      }

      return false;
    } catch (error) {
      console.error(`Failed to reload agent ${agentId}:`, error);
      return false;
    }
  }

  async executeAgent(agentId: string, task: any): Promise<any> {
    try {
      const agent = this.agents.get(agentId);
      if (!agent) {
        throw new Error(`Agent ${agentId} not found`);
      }

      if (agent.status !== 'ready') {
        throw new Error(`Agent ${agentId} is not ready (status: ${agent.status})`);
      }

      // Update agent status to running
      agent.status = 'running';
      this.emit('agent_status_changed', {
        type: 'agent_status_changed',
        agentId: agentId,
        data: { oldStatus: 'ready', newStatus: 'running' },
        timestamp: new Date()
      });

      // Execute the task
      const result = await agent.execute(task);

      // Update agent status back to ready
      agent.status = 'ready';
      this.emit('agent_status_changed', {
        type: 'agent_status_changed',
        agentId: agentId,
        data: { oldStatus: 'running', newStatus: 'ready' },
        timestamp: new Date()
      });

      return result;
    } catch (error) {
      // Update agent status to error
      const agent = this.agents.get(agentId);
      if (agent) {
        agent.status = 'error';
        this.emit('agent_status_changed', {
          type: 'agent_status_changed',
          agentId: agentId,
          data: { oldStatus: 'running', newStatus: 'error' },
          timestamp: new Date()
        });
      }

      this.emit('agent_error', {
        type: 'agent_error',
        agentId: agentId,
        data: { error: error.message, task },
        timestamp: new Date()
      });

      throw error;
    }
  }

  getAgent(agentId: string): Agent | undefined {
    return this.agents.get(agentId);
  }

  getAllAgents(): Agent[] {
    return Array.from(this.agents.values());
  }

  getAgentsByType(agentType: string): Agent[] {
    return Array.from(this.agents.values()).filter(agent => agent.type === agentType);
  }

  getReadyAgents(): Agent[] {
    return Array.from(this.agents.values()).filter(agent => agent.status === 'ready');
  }

  async updateAgentConfig(agentId: string, config: Partial<AgentConfig>): Promise<boolean> {
    try {
      const existingConfig = await this.loader.loadAgentConfig(agentId);
      if (!existingConfig) {
        return false;
      }

      const updatedConfig = { ...existingConfig, ...config };
      return await this.loader.saveAgentConfig(agentId, updatedConfig);
    } catch (error) {
      console.error(`Failed to update agent config for ${agentId}:`, error);
      return false;
    }
  }

  async getAgentStats(): Promise<any> {
    const stats = {
      totalAgents: this.agents.size,
      byType: {} as Record<string, number>,
      byStatus: {} as Record<string, number>,
      averageUptime: 0,
      lastActivity: new Date()
    };

    for (const agent of this.agents.values()) {
      // Count by type
      stats.byType[agent.type] = (stats.byType[agent.type] || 0) + 1;

      // Count by status
      stats.byStatus[agent.status] = (stats.byStatus[agent.status] || 0) + 1;
    }

    return stats;
  }

  async shutdown(): Promise<void> {
    this.stopMonitoring();

    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
    }

    // Clean up all agents
    for (const [agentId, agent] of this.agents) {
      try {
        if (typeof agent.cleanup === 'function') {
          await agent.cleanup();
        }
        this.unregisterAgent(agentId);
      } catch (error) {
        console.error(`Error during agent ${agentId} cleanup:`, error);
      }
    }

    this.agents.clear();
    console.log('AgentManager shutdown complete');
  }
}

export default AgentManager;