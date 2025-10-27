/**
 * Agent Registry with Hot Reload and Plugin System
 * Enhanced AgentRegistry with plugin discovery and dynamic loading capabilities
 */

import { Agent, AgentConfig, AttackPhase } from '../core/data_models';
import { PluginManager } from '../core/plugin_manager';
import { AgentManager } from '../core/agent_manager';
import { EventEmitter } from 'events';

export interface AgentRegistration {
  agentId: string;
  agent: Agent;
  config: AgentConfig;
  capabilities: string[];
  lastUpdated: Date;
  isActive: boolean;
}

export class EnhancedAgentRegistry extends EventEmitter {
  private agents: Map<string, AgentRegistration> = new Map();
  private pluginManager: PluginManager;
  private agentManager: AgentManager;
  private isInitialized: boolean = false;

  constructor(pluginDir: string = 'plugins') {
    super();
    this.pluginManager = new PluginManager(pluginDir);
    this.agentManager = new AgentManager(pluginDir);
  }

  async initialize(): Promise<void> {
    if (this.isInitialized) return;

    try {
      // Initialize plugin system
      await this.pluginManager.cleanup();
      await this.loadPlugins();

      // Initialize agent manager
      await this.agentManager.initialize();

      // Set up event listeners
      this.setupEventListeners();

      this.isInitialized = true;
      console.log('EnhancedAgentRegistry initialized successfully');
    } catch (error) {
      console.error('Failed to initialize EnhancedAgentRegistry:', error);
      throw error;
    }
  }

  private async loadPlugins(): Promise<void> {
    try {
      // Load all plugins from directory
      const pluginDir = 'plugins';
      if (!require('fs').existsSync(pluginDir)) {
        require('fs').mkdirSync(pluginDir, { recursive: true });
      }

      const plugins = this.pluginManager.getAllPlugins();
      console.log(`Loaded ${plugins.length} plugins`);

      // Register plugin agents
      for (const plugin of plugins) {
        if (plugin.isActive) {
          await this.registerAgent(plugin.agent, {
            id: plugin.manifest.id,
            name: plugin.manifest.name,
            type: plugin.manifest.type,
            version: plugin.manifest.version,
            capabilities: plugin.manifest.capabilities,
            config: await this.pluginManager.loadPluginConfig(plugin.manifest.id) || {}
          });
        }
      }
    } catch (error) {
      console.error('Failed to load plugins:', error);
    }
  }

  private setupEventListeners(): void {
    // Listen to plugin manager events
    this.pluginManager.on('plugin_installed', async (pluginId: string) => {
      console.log(`Plugin installed: ${pluginId}`);
      await this.reloadPluginAgents();
    });

    this.pluginManager.on('plugin_updated', async (pluginId: string) => {
      console.log(`Plugin updated: ${pluginId}`);
      await this.reloadPluginAgents();
    });

    this.pluginManager.on('plugin_removed', async (pluginId: string) => {
      console.log(`Plugin removed: ${pluginId}`);
      await this.unregisterPluginAgents(pluginId);
    });

    // Listen to agent manager events
    this.agentManager.on('agent_registered', (event) => {
      this.emit('agent_registered', event);
    });

    this.agentManager.on('agent_unregistered', (event) => {
      this.emit('agent_unregistered', event);
    });

    this.agentManager.on('agent_status_changed', (event) => {
      this.emit('agent_status_changed', event);
    });
  }

  async registerAgent(agent: Agent, config: AgentConfig): Promise<string> {
    try {
      const agentId = config.id || this.generateAgentId();

      const registration: AgentRegistration = {
        agentId,
        agent,
        config,
        capabilities: config.capabilities || [],
        lastUpdated: new Date(),
        isActive: true
      };

      this.agents.set(agentId, registration);

      // Emit registration event
      this.emit('agent_registered', {
        agentId,
        agentName: config.name,
        agentType: config.type,
        capabilities: config.capabilities
      });

      console.log(`Registered agent: ${config.name} (${agentId})`);
      return agentId;
    } catch (error) {
      console.error(`Failed to register agent ${config.name}:`, error);
      throw error;
    }
  }

  async unregisterAgent(agentId: string): Promise<boolean> {
    try {
      const registration = this.agents.get(agentId);
      if (!registration) {
        return false;
      }

      // Call agent cleanup
      if (typeof registration.agent.cleanup === 'function') {
        await registration.agent.cleanup();
      }

      this.agents.delete(agentId);

      // Emit unregistration event
      this.emit('agent_unregistered', {
        agentId,
        agentName: registration.config.name,
        agentType: registration.config.type
      });

      console.log(`Unregistered agent: ${registration.config.name} (${agentId})`);
      return true;
    } catch (error) {
      console.error(`Failed to unregister agent ${agentId}:`, error);
      return false;
    }
  }

  async installPluginFromGit(repoUrl: string, branch: string = 'main'): Promise<string | null> {
    try {
      const pluginId = await this.pluginManager.installPluginFromGit(repoUrl, branch);
      if (pluginId) {
        await this.reloadPluginAgents();
        return pluginId;
      }
      return null;
    } catch (error) {
      console.error(`Failed to install plugin from ${repoUrl}:`, error);
      return null;
    }
  }

  async installPluginFromArchive(archivePath: string): Promise<string | null> {
    try {
      const pluginId = await this.pluginManager.installPluginFromArchive(archivePath);
      if (pluginId) {
        await this.reloadPluginAgents();
        return pluginId;
      }
      return null;
    } catch (error) {
      console.error(`Failed to install plugin from archive ${archivePath}:`, error);
      return null;
    }
  }

  private async reloadPluginAgents(): Promise<void> {
    try {
      const plugins = this.pluginManager.getAllPlugins();

      // Unregister existing plugin agents
      for (const [agentId, registration] of this.agents) {
        if (registration.config.source === 'plugin') {
          await this.unregisterAgent(agentId);
        }
      }

      // Register new plugin agents
      for (const plugin of plugins) {
        if (plugin.isActive) {
          const config = await this.pluginManager.loadPluginConfig(plugin.manifest.id) || {};
          config.source = 'plugin';

          await this.registerAgent(plugin.agent, {
            id: plugin.manifest.id,
            name: plugin.manifest.name,
            type: plugin.manifest.type,
            version: plugin.manifest.version,
            capabilities: plugin.manifest.capabilities,
            config
          });
        }
      }
    } catch (error) {
      console.error('Failed to reload plugin agents:', error);
    }
  }

  private async unregisterPluginAgents(pluginId: string): Promise<void> {
    try {
      // Find and unregister agents from specific plugin
      for (const [agentId, registration] of this.agents) {
        if (registration.config.source === 'plugin' && registration.config.id === pluginId) {
          await this.unregisterAgent(agentId);
        }
      }
    } catch (error) {
      console.error(`Failed to unregister agents for plugin ${pluginId}:`, error);
    }
  }

  getAgent(agentId: string): Agent | null {
    const registration = this.agents.get(agentId);
    return registration ? registration.agent : null;
  }

  getAgentConfig(agentId: string): AgentConfig | null {
    const registration = this.agents.get(agentId);
    return registration ? registration.config : null;
  }

  getAllAgents(): Agent[] {
    return Array.from(this.agents.values())
      .filter(registration => registration.isActive)
      .map(registration => registration.agent);
  }

  getAgentsByType(agentType: string): Agent[] {
    return Array.from(this.agents.values())
      .filter(registration =>
        registration.isActive && registration.config.type === agentType
      )
      .map(registration => registration.agent);
  }

  getAgentsByPhase(phase: AttackPhase): Agent[] {
    return Array.from(this.agents.values())
      .filter(registration =>
        registration.isActive &&
        registration.capabilities.some(cap => cap.includes(phase.toString().toLowerCase()))
      )
      .map(registration => registration.agent);
  }

  getAgentsByCapability(capability: string): Agent[] {
    return Array.from(this.agents.values())
      .filter(registration =>
        registration.isActive && registration.capabilities.includes(capability)
      )
      .map(registration => registration.agent);
  }

  async updateAgentConfig(agentId: string, updates: Partial<AgentConfig>): Promise<boolean> {
    try {
      const registration = this.agents.get(agentId);
      if (!registration) {
        return false;
      }

      // Update config
      registration.config = { ...registration.config, ...updates };
      registration.lastUpdated = new Date();

      // If it's a plugin agent, save to disk
      if (registration.config.source === 'plugin') {
        await this.pluginManager.savePluginConfig(agentId, registration.config);
      }

      this.emit('agent_config_updated', {
        agentId,
        updates
      });

      return true;
    } catch (error) {
      console.error(`Failed to update agent config for ${agentId}:`, error);
      return false;
    }
  }

  async executeAgent(agentId: string, task: any): Promise<any> {
    try {
      const agent = this.getAgent(agentId);
      if (!agent) {
        throw new Error(`Agent ${agentId} not found`);
      }

      // Use agent manager for execution
      return await this.agentManager.executeAgent(agentId, task);
    } catch (error) {
      console.error(`Agent execution failed for ${agentId}:`, error);
      throw error;
    }
  }

  async getRegistryStats(): Promise<any> {
    const stats = {
      totalAgents: this.agents.size,
      activeAgents: 0,
      byType: {} as Record<string, number>,
      byPhase: {} as Record<string, number>,
      pluginAgents: 0,
      customAgents: 0,
      averageUptime: 0,
      totalExecutions: 0
    };

    const now = new Date();

    for (const registration of this.agents.values()) {
      if (registration.isActive) {
        stats.activeAgents++;

        // Count by type
        stats.byType[registration.config.type] = (stats.byType[registration.config.type] || 0) + 1;

        // Count by source
        if (registration.config.source === 'plugin') {
          stats.pluginAgents++;
        } else {
          stats.customAgents++;
        }
      }

      // Calculate uptime (simplified)
      const uptime = now.getTime() - registration.lastUpdated.getTime();
      stats.averageUptime += uptime;
    }

    stats.averageUptime = stats.totalAgents > 0 ? stats.averageUptime / stats.totalAgents : 0;

    return stats;
  }

  private generateAgentId(): string {
    return `agent_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  async shutdown(): Promise<void> {
    // Stop agent monitoring
    this.agentManager.stopMonitoring();

    // Unload all agents
    for (const agentId of this.agents.keys()) {
      await this.unregisterAgent(agentId);
    }

    // Cleanup plugin manager
    await this.pluginManager.cleanup();

    this.agents.clear();
    this.isInitialized = false;

    console.log('EnhancedAgentRegistry shutdown complete');
  }
}

export default EnhancedAgentRegistry;