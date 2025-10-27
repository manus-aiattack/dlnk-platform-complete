/**
 * AI Workflow Generator with Natural Language Processing
 * Generates attack workflows from natural language descriptions using local LLM models
 */

import { Agent } from '../core/data_models';
import { EnhancedOrchestrator } from '../core/enhanced_orchestrator';
import { EnhancedAIDecisionEngine } from '../core/ai_models/enhanced_ai_decision_engine';

export interface WorkflowStep {
  id: string;
  name: string;
  description: string;
  agentType: string;
  phase: string;
  dependencies: string[];
  parameters: Record<string, any>;
  timeout: number;
  retryCount: number;
}

export interface Workflow {
  id: string;
  name: string;
  description: string;
  target: string;
  version: string;
  steps: WorkflowStep[];
  created_at: Date;
  updated_at: Date;
  status: 'draft' | 'active' | 'completed' | 'failed';
  metadata: {
    complexity: 'low' | 'medium' | 'high';
    estimated_time: number;
    risk_level: 'low' | 'medium' | 'high';
    success_probability: number;
  };
}

export interface NLPParseResult {
  intent: 'reconnaissance' | 'exploitation' | 'privilege_escalation' | 'persistence' | 'exfiltration';
  entities: {
    target: string;
    scope: string[];
    constraints: string[];
  };
  confidence: number;
}

export class AIWorkflowGenerator {
  private orchestrator: EnhancedOrchestrator;
  private decisionEngine: EnhancedAIDecisionEngine;
  private workflows: Map<string, Workflow> = new Map();
  private nlpModel: any; // Local LLM model

  constructor(orchestrator: EnhancedOrchestrator, decisionEngine: EnhancedAIDecisionEngine) {
    this.orchestrator = orchestrator;
    this.decisionEngine = decisionEngine;
    this.initializeNLPModel();
  }

  private async initializeNLPModel(): Promise<void> {
    try {
      // Initialize local LLM model (llama3:8b-instruct-fp16 or mixtral:latest)
      this.nlpModel = await this.loadLocalLLM();
      console.log('NLP model initialized successfully');
    } catch (error) {
      console.error('Failed to initialize NLP model:', error);
      throw error;
    }
  }

  private async loadLocalLLM(): Promise<any> {
    // Load local LLM model for NLP processing
    const { execSync } = require('child_process');
    const fs = require('fs');

    // Check if model exists locally
    if (!fs.existsSync('models/llama3-8b-instruct-fp16.bin')) {
      throw new Error('Local LLM model not found');
    }

    // Initialize model (simplified - would use actual LLM library)
    return {
      generate: async (prompt: string): Promise<string> => {
        // Mock implementation - would call actual LLM
        return `Generated response for: ${prompt}`;
      },
      embed: async (text: string): Promise<number[]> => {
        // Mock implementation - would return actual embeddings
        return Array(768).fill(Math.random());
      }
    };
  }

  async parseNaturalLanguage(description: string): Promise<NLPParseResult> {
    try {
      const prompt = `
        Analyze the following penetration testing description and extract structured information:

        Description: "${description}"

        Extract the following information:
        1. Primary intent (reconnaissance, exploitation, privilege_escalation, persistence, exfiltration)
        2. Target entities (URLs, IP addresses, domain names)
        3. Scope constraints (what to test, what to avoid)
        4. Confidence score (0-1)

        Return JSON format with fields: intent, entities (target, scope, constraints), confidence
      `;

      const response = await this.nlpModel.generate(prompt);
      return JSON.parse(response);
    } catch (error) {
      console.error('Failed to parse natural language:', error);
      throw error;
    }
  }

  async generateWorkflowFromNLP(nlpResult: NLPParseResult): Promise<Workflow> {
    try {
      const workflowId = this.generateWorkflowId();
      const steps = await this.generateWorkflowSteps(nlpResult);

      const workflow: Workflow = {
        id: workflowId,
        name: this.generateWorkflowName(nlpResult),
        description: `Generated workflow for ${nlpResult.intent} on ${nlpResult.entities.target}`,
        target: nlpResult.entities.target,
        version: '1.0.0',
        steps,
        created_at: new Date(),
        updated_at: new Date(),
        status: 'draft',
        metadata: {
          complexity: this.estimateComplexity(steps),
          estimated_time: this.estimateTime(steps),
          risk_level: this.estimateRisk(steps),
          success_probability: await this.estimateSuccessProbability(steps)
        }
      };

      this.workflows.set(workflowId, workflow);
      return workflow;
    } catch (error) {
      console.error('Failed to generate workflow:', error);
      throw error;
    }
  }

  private async generateWorkflowSteps(nlpResult: NLPParseResult): Promise<WorkflowStep[]> {
    const steps: WorkflowStep[] = [];

    // Generate steps based on intent
    switch (nlpResult.intent) {
      case 'reconnaissance':
        steps.push(...this.generateReconnaissanceSteps(nlpResult));
        break;
      case 'exploitation':
        steps.push(...this.generateExploitationSteps(nlpResult));
        break;
      case 'privilege_escalation':
        steps.push(...this.generatePrivilegeEscalationSteps(nlpResult));
        break;
      case 'persistence':
        steps.push(...this.generatePersistenceSteps(nlpResult));
        break;
      case 'exfiltration':
        steps.push(...this.generateExfiltrationSteps(nlpResult));
        break;
    }

    // Add dependency resolution
    return this.resolveDependencies(steps);
  }

  private generateReconnaissanceSteps(nlpResult: NLPParseResult): WorkflowStep[] {
    return [
      {
        id: 'step-1',
        name: 'Network Discovery',
        description: 'Discover active hosts and open ports',
        agentType: 'nmap',
        phase: 'reconnaissance',
        dependencies: [],
        parameters: {
          target: nlpResult.entities.target,
          scan_type: 'stealth',
          ports: '1-10000'
        },
        timeout: 300000, // 5 minutes
        retryCount: 2
      },
      {
        id: 'step-2',
        name: 'Service Enumeration',
        description: 'Enumerate services and versions',
        agentType: 'nmap',
        phase: 'reconnaissance',
        dependencies: ['step-1'],
        parameters: {
          target: nlpResult.entities.target,
          version_detection: true
        },
        timeout: 300000,
        retryCount: 2
      },
      {
        id: 'step-3',
        name: 'Web Application Analysis',
        description: 'Analyze web applications for vulnerabilities',
        agentType: 'web-analyzer',
        phase: 'reconnaissance',
        dependencies: ['step-2'],
        parameters: {
          target: nlpResult.entities.target,
          scan_depth: 'deep'
        },
        timeout: 600000,
        retryCount: 1
      }
    ];
  }

  private generateExploitationSteps(nlpResult: NLPParseResult): WorkflowStep[] {
    return [
      {
        id: 'step-1',
        name: 'Vulnerability Assessment',
        description: 'Identify exploitable vulnerabilities',
        agentType: 'vuln-scanner',
        phase: 'exploitation',
        dependencies: [],
        parameters: {
          target: nlpResult.entities.target,
          check_exploits: true
        },
        timeout: 600000,
        retryCount: 1
      },
      {
        id: 'step-2',
        name: 'Exploit Execution',
        description: 'Execute identified exploits',
        agentType: 'exploit-engine',
        phase: 'exploitation',
        dependencies: ['step-1'],
        parameters: {
          target: nlpResult.entities.target,
          exploit_list: 'auto'
        },
        timeout: 300000,
        retryCount: 3
      }
    ];
  }

  private generatePrivilegeEscalationSteps(nlpResult: NLPParseResult): WorkflowStep[] {
    return [
      {
        id: 'step-1',
        name: 'Local Privilege Escalation',
        description: 'Attempt local privilege escalation',
        agentType: 'priv-esc',
        phase: 'privilege_escalation',
        dependencies: [],
        parameters: {
          target: nlpResult.entities.target
        },
        timeout: 300000,
        retryCount: 2
      },
      {
        id: 'step-2',
        name: 'Credential Harvesting',
        description: 'Harvest credentials for lateral movement',
        agentType: 'credential-harvester',
        phase: 'privilege_escalation',
        dependencies: ['step-1'],
        parameters: {
          target: nlpResult.entities.target
        },
        timeout: 300000,
        retryCount: 2
      }
    ];
  }

  private generatePersistenceSteps(nlpResult: NLPParseResult): WorkflowStep[] {
    return [
      {
        id: 'step-1',
        name: 'Persistence Mechanism Setup',
        description: 'Establish persistence on compromised systems',
        agentType: 'persistence',
        phase: 'persistence',
        dependencies: [],
        parameters: {
          target: nlpResult.entities.target,
          methods: ['registry', 'scheduled_tasks', 'startup_scripts']
        },
        timeout: 300000,
        retryCount: 1
      }
    ];
  }

  private generateExfiltrationSteps(nlpResult: NLPParseResult): WorkflowStep[] {
    return [
      {
        id: 'step-1',
        name: 'Data Discovery',
        description: 'Discover sensitive data for exfiltration',
        agentType: 'data-discovery',
        phase: 'exfiltration',
        dependencies: [],
        parameters: {
          target: nlpResult.entities.target,
          data_types: ['credentials', 'documents', 'databases']
        },
        timeout: 600000,
        retryCount: 1
      },
      {
        id: 'step-2',
        name: 'Data Exfiltration',
        description: 'Exfiltrate discovered data',
        agentType: 'exfiltration',
        phase: 'exfiltration',
        dependencies: ['step-1'],
        parameters: {
          target: nlpResult.entities.target,
          exfil_method: 'dns_tunnel'
        },
        timeout: 600000,
        retryCount: 2
      }
    ];
  }

  private resolveDependencies(steps: WorkflowStep[]): WorkflowStep[] {
    // Simple dependency resolution - in practice would use topological sorting
    return steps.map((step, index) => ({
      ...step,
      dependencies: step.dependencies.length > 0 ? step.dependencies : []
    }));
  }

  private estimateComplexity(steps: WorkflowStep[]): 'low' | 'medium' | 'high' {
    const complexityScore = steps.length * 2 + steps.reduce((acc, step) => acc + step.retryCount, 0);
    if (complexityScore <= 10) return 'low';
    if (complexityScore <= 20) return 'medium';
    return 'high';
  }

  private estimateTime(steps: WorkflowStep[]): number {
    return steps.reduce((total, step) => total + step.timeout, 0) / 1000 / 60; // minutes
  }

  private estimateRisk(steps: WorkflowStep[]): 'low' | 'medium' | 'high' {
    const riskFactors = steps.filter(step =>
      ['exploit', 'privilege', 'exfiltration'].some(type => step.name.toLowerCase().includes(type))
    );

    if (riskFactors.length === 0) return 'low';
    if (riskFactors.length <= 2) return 'medium';
    return 'high';
  }

  private async estimateSuccessProbability(steps: WorkflowStep[]): Promise<number> {
    try {
      // Use decision engine to estimate success probability
      const result = await this.decisionEngine.make_decision(
        {
          type: 'workflow_success_probability',
          complexity: this.estimateComplexity(steps),
          risk_level: this.estimateRisk(steps)
        },
        [{ method: 'estimate_probability' }],
        { target_complexity: 'medium' }
      );

      return result.success_probability;
    } catch (error) {
      console.error('Failed to estimate success probability:', error);
      return 0.7; // Default fallback
    }
  }

  generateWorkflowName(nlpResult: NLPParseResult): string {
    const timestamp = new Date().toISOString().split('T')[0];
    return `${nlpResult.intent}_${nlpResult.entities.target.replace(/[^a-zA-Z0-9]/g, '_')}_${timestamp}`;
  }

  generateWorkflowId(): string {
    return `workflow_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  getWorkflow(workflowId: string): Workflow | undefined {
    return this.workflows.get(workflowId);
  }

  getAllWorkflows(): Workflow[] {
    return Array.from(this.workflows.values());
  }

  async updateWorkflow(workflowId: string, updates: Partial<Workflow>): Promise<boolean> {
    try {
      const workflow = this.workflows.get(workflowId);
      if (!workflow) {
        return false;
      }

      this.workflows.set(workflowId, { ...workflow, ...updates, updated_at: new Date() });
      return true;
    } catch (error) {
      console.error(`Failed to update workflow ${workflowId}:`, error);
      return false;
    }
  }

  async executeWorkflow(workflowId: string): Promise<any> {
    try {
      const workflow = this.workflows.get(workflowId);
      if (!workflow) {
        throw new Error(`Workflow ${workflowId} not found`);
      }

      // Update status
      await this.updateWorkflow(workflowId, { status: 'active' });

      // Execute steps in order
      for (const step of workflow.steps) {
        console.log(`Executing step: ${step.name}`);
        // Here would call actual agent execution
        await new Promise(resolve => setTimeout(resolve, 1000)); // Mock execution
      }

      await this.updateWorkflow(workflowId, { status: 'completed' });
      return { success: true, workflowId };
    } catch (error) {
      console.error(`Failed to execute workflow ${workflowId}:`, error);
      await this.updateWorkflow(workflowId, { status: 'failed' });
      throw error;
    }
  }

  async saveWorkflow(workflow: Workflow): Promise<boolean> {
    try {
      const fs = require('fs');
      const path = require('path');

      const workflowDir = 'workflows';
      if (!fs.existsSync(workflowDir)) {
        fs.mkdirSync(workflowDir, { recursive: true });
      }

      const workflowPath = path.join(workflowDir, `${workflow.id}.json`);
      fs.writeFileSync(workflowPath, JSON.stringify(workflow, null, 2));

      return true;
    } catch (error) {
      console.error('Failed to save workflow:', error);
      return false;
    }
  }

  async loadWorkflow(workflowId: string): Promise<Workflow | null> {
    try {
      const fs = require('fs');
      const path = require('path');

      const workflowPath = path.join('workflows', `${workflowId}.json`);
      if (!fs.existsSync(workflowPath)) {
        return null;
      }

      const workflowData = fs.readFileSync(workflowPath, 'utf8');
      const workflow = JSON.parse(workflowData);

      // Parse dates
      workflow.created_at = new Date(workflow.created_at);
      workflow.updated_at = new Date(workflow.updated_at);

      this.workflows.set(workflowId, workflow);
      return workflow;
    } catch (error) {
      console.error(`Failed to load workflow ${workflowId}:`, error);
      return null;
    }
  }
}

export default AIWorkflowGenerator;