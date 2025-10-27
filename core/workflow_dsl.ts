/**
 * Workflow DSL (Domain Specific Language) for Penetration Testing
 * Defines a structured language for creating and executing attack workflows
 */

import { Workflow, WorkflowStep } from './ai_workflow_generator';

export interface DSLRule {
  name: string;
  type: 'action' | 'condition' | 'loop' | 'decision';
  parameters: Record<string, any>;
  children?: DSLRule[];
}

export interface DSLWorkflow {
  version: string;
  name: string;
  description: string;
  target: string;
  rules: DSLRule[];
  metadata?: {
    author?: string;
    created?: string;
    tags?: string[];
  };
}

export class WorkflowDSL {
  private parsers: Map<string, (rule: DSLRule) => WorkflowStep[]> = new Map();
  private validators: Map<string, (rule: DSLRule) => boolean> = new Map();

  constructor() {
    this.initializeParsers();
    this.initializeValidators();
  }

  private initializeParsers(): void {
    // Action parsers
    this.parsers.set('scan', (rule) => this.parseScanAction(rule));
    this.parsers.set('exploit', (rule) => this.parseExploitAction(rule));
    this.parsers.set('enum', (rule) => this.parseEnumAction(rule));
    this.parsers.set('privilege', (rule) => this.parsePrivilegeAction(rule));
    this.parsers.set('persistence', (rule) => this.parsePersistenceAction(rule));
    this.parsers.set('exfil', (rule) => this.parseExfilAction(rule));

    // Condition parsers
    this.parsers.set('if', (rule) => this.parseCondition(rule));
    this.parsers.set('loop', (rule) => this.parseLoop(rule));
  }

  private initializeValidators(): void {
    this.validators.set('scan', (rule) => this.validateScanRule(rule));
    this.validators.set('exploit', (rule) => this.validateExploitRule(rule));
    this.validators.set('enum', (rule) => this.validateEnumRule(rule));
    this.validators.set('if', (rule) => this.validateConditionRule(rule));
    this.validators.set('loop', (rule) => this.validateLoopRule(rule));
  }

  parseWorkflowDSL(dslText: string): DSLWorkflow {
    try {
      // Parse DSL text into structured format
      const lines = dslText.split('\n').filter(line => line.trim() && !line.trim().startsWith('#'));
      const workflow: DSLWorkflow = {
        version: '1.0',
        name: 'Generated Workflow',
        description: 'Generated from DSL',
        target: '',
        rules: []
      };

      let currentRule: DSLRule | null = null;

      for (const line of lines) {
        const trimmed = line.trim();

        if (trimmed.startsWith('workflow ')) {
          // Workflow definition
          const match = trimmed.match(/workflow\s+([a-zA-Z0-9_]+)\s*:\s*(.+)/);
          if (match) {
            workflow.name = match[1];
            workflow.description = match[2];
          }
        } else if (trimmed.startsWith('target ')) {
          // Target definition
          const match = trimmed.match(/target\s+(.+)/);
          if (match) {
            workflow.target = match[1];
          }
        } else if (trimmed.match(/^\s*[a-zA-Z_]+\s*:/)) {
          // Action definition
          const match = trimmed.match(/^(\s*)([a-zA-Z_]+)\s*:\s*(.+)/);
          if (match) {
            const indent = match[1].length;
            const action = match[2];
            const params = match[3];

            const rule: DSLRule = {
              name: action,
              type: 'action',
              parameters: this.parseParameters(params)
            };

            if (indent === 0) {
              workflow.rules.push(rule);
              currentRule = rule;
            } else if (currentRule) {
              if (!currentRule.children) {
                currentRule.children = [];
              }
              currentRule.children.push(rule);
            }
          }
        }
      }

      return workflow;
    } catch (error) {
      console.error('Failed to parse DSL:', error);
      throw error;
    }
  }

  convertToWorkflow(dslWorkflow: DSLWorkflow): Workflow {
    try {
      const workflowId = this.generateWorkflowId();
      const steps: WorkflowStep[] = [];

      // Convert DSL rules to workflow steps
      for (const rule of dslWorkflow.rules) {
        const ruleSteps = this.convertRuleToSteps(rule);
        steps.push(...ruleSteps);
      }

      const workflow: Workflow = {
        id: workflowId,
        name: dslWorkflow.name,
        description: dslWorkflow.description,
        target: dslWorkflow.target,
        version: dslWorkflow.version,
        steps: this.resolveDependencies(steps),
        created_at: new Date(),
        updated_at: new Date(),
        status: 'draft',
        metadata: {
          complexity: this.estimateComplexity(steps),
          estimated_time: this.estimateTime(steps),
          risk_level: this.estimateRisk(steps),
          success_probability: 0.8 // Default
        }
      };

      return workflow;
    } catch (error) {
      console.error('Failed to convert DSL to workflow:', error);
      throw error;
    }
  }

  private convertRuleToSteps(rule: DSLRule): WorkflowStep[] {
    const parser = this.parsers.get(rule.name);
    if (parser && this.validators.get(rule.name)?.(rule)) {
      return parser(rule);
    }

    // Default fallback
    return [{
      id: this.generateStepId(),
      name: rule.name,
      description: `Execute ${rule.name}`,
      agentType: 'generic',
      phase: 'execution',
      dependencies: [],
      parameters: rule.parameters,
      timeout: 300000,
      retryCount: 1
    }];
  }

  private parseParameters(paramString: string): Record<string, any> {
    const params: Record<string, any> = {};

    // Simple parameter parsing
    const pairs = paramString.split(',').map(p => p.trim());
    for (const pair of pairs) {
      const [key, value] = pair.split('=').map(p => p.trim());
      if (key && value) {
        // Try to parse as number or boolean
        if (/^\d+$/.test(value)) {
          params[key] = parseInt(value);
        } else if (value === 'true') {
          params[key] = true;
        } else if (value === 'false') {
          params[key] = false;
        } else if (value.startsWith('"') && value.endsWith('"')) {
          params[key] = value.slice(1, -1); // Remove quotes
        } else {
          params[key] = value;
        }
      }
    }

    return params;
  }

  private parseScanAction(rule: DSLRule): WorkflowStep[] {
    return [{
      id: this.generateStepId(),
      name: 'Network Scan',
      description: 'Perform network reconnaissance',
      agentType: 'nmap',
      phase: 'reconnaissance',
      dependencies: [],
      parameters: {
        target: rule.parameters.target || '${TARGET}',
        scan_type: rule.parameters.type || 'stealth',
        ports: rule.parameters.ports || '1-10000',
        ...rule.parameters
      },
      timeout: rule.parameters.timeout || 300000,
      retryCount: rule.parameters.retry || 2
    }];
  }

  private parseExploitAction(rule: DSLRule): WorkflowStep[] {
    return [{
      id: this.generateStepId(),
      name: 'Exploit Execution',
      description: 'Execute exploit against target',
      agentType: 'exploit-engine',
      phase: 'exploitation',
      dependencies: [],
      parameters: {
        target: rule.parameters.target || '${TARGET}',
        exploit: rule.parameters.exploit,
        payload: rule.parameters.payload,
        ...rule.parameters
      },
      timeout: rule.parameters.timeout || 300000,
      retryCount: rule.parameters.retry || 3
    }];
  }

  private parseEnumAction(rule: DSLRule): WorkflowStep[] {
    return [{
      id: this.generateStepId(),
      name: 'Service Enumeration',
      description: 'Enumerate services and versions',
      agentType: 'service-enum',
      phase: 'reconnaissance',
      dependencies: [],
      parameters: {
        target: rule.parameters.target || '${TARGET}',
        service: rule.parameters.service,
        ...rule.parameters
      },
      timeout: rule.parameters.timeout || 300000,
      retryCount: rule.parameters.retry || 2
    }];
  }

  private parsePrivilegeAction(rule: DSLRule): WorkflowStep[] {
    return [{
      id: this.generateStepId(),
      name: 'Privilege Escalation',
      description: 'Attempt privilege escalation',
      agentType: 'priv-esc',
      phase: 'privilege_escalation',
      dependencies: [],
      parameters: {
        target: rule.parameters.target || '${TARGET}',
        method: rule.parameters.method,
        ...rule.parameters
      },
      timeout: rule.parameters.timeout || 300000,
      retryCount: rule.parameters.retry || 2
    }];
  }

  private parsePersistenceAction(rule: DSLRule): WorkflowStep[] {
    return [{
      id: this.generateStepId(),
      name: 'Establish Persistence',
      description: 'Set up persistence mechanisms',
      agentType: 'persistence',
      phase: 'persistence',
      dependencies: [],
      parameters: {
        target: rule.parameters.target || '${TARGET}',
        methods: rule.parameters.methods || ['registry', 'scheduled_tasks'],
        ...rule.parameters
      },
      timeout: rule.parameters.timeout || 300000,
      retryCount: rule.parameters.retry || 1
    }];
  }

  private parseExfilAction(rule: DSLRule): WorkflowStep[] {
    return [{
      id: this.generateStepId(),
      name: 'Data Exfiltration',
      description: 'Exfiltrate data from target',
      agentType: 'exfil',
      phase: 'exfiltration',
      dependencies: [],
      parameters: {
        target: rule.parameters.target || '${TARGET}',
        method: rule.parameters.method || 'dns_tunnel',
        data: rule.parameters.data,
        ...rule.parameters
      },
      timeout: rule.parameters.timeout || 600000,
      retryCount: rule.parameters.retry || 2
    }];
  }

  private parseCondition(rule: DSLRule): WorkflowStep[] {
    // Conditions don't directly create steps, they modify execution flow
    return [];
  }

  private parseLoop(rule: DSLRule): WorkflowStep[] {
    // Loops don't directly create steps, they modify execution flow
    return [];
  }

  private validateScanRule(rule: DSLRule): boolean {
    return !!rule.parameters.target;
  }

  private validateExploitRule(rule: DSLRule): boolean {
    return !!rule.parameters.exploit && !!rule.parameters.target;
  }

  private validateEnumRule(rule: DSLRule): boolean {
    return !!rule.parameters.target;
  }

  private validateConditionRule(rule: DSLRule): boolean {
    return !!rule.parameters.condition;
  }

  private validateLoopRule(rule: DSLRule): boolean {
    return !!rule.parameters.times || !!rule.parameters.until;
  }

  private resolveDependencies(steps: WorkflowStep[]): WorkflowStep[] {
    // Simple dependency resolution
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
      ['exploit', 'privilege', 'exfil'].some(type => step.name.toLowerCase().includes(type))
    );

    if (riskFactors.length === 0) return 'low';
    if (riskFactors.length <= 2) return 'medium';
    return 'high';
  }

  generateWorkflowId(): string {
    return `dsl_workflow_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  generateStepId(): string {
    return `step_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  // Example DSL templates
  static getExampleTemplates(): Record<string, string> {
    return {
      'basic-recon': `
        # Basic Reconnaissance Workflow
        workflow basic_recon: Basic network reconnaissance

        target ${TARGET}

        # Network discovery
        scan:
          type: stealth
          ports: 1-10000
          timeout: 300000

        # Service enumeration
        enum:
          service: all
          timeout: 300000

        # Web application analysis
        scan:
          type: web
          depth: deep
          timeout: 600000
      `,

      'full-assessment': `
        # Comprehensive Security Assessment
        workflow full_assessment: Complete penetration test

        target ${TARGET}

        # Phase 1: Reconnaissance
        scan:
          type: comprehensive
          ports: 1-65535

        enum:
          service: all

        # Phase 2: Exploitation
        if:
          condition: vulnerabilities_found > 0
          then:
            exploit:
              method: auto
              timeout: 300000

        # Phase 3: Post-exploitation
        privilege:
          method: auto

        persistence:
          methods: [registry, scheduled_tasks]

        # Phase 4: Cleanup
        cleanup:
          method: auto
      `,

      'web-app-test': `
        # Web Application Security Test
        workflow web_app_test: Web application penetration test

        target ${TARGET}

        # Web reconnaissance
        scan:
          type: web
          depth: deep
          technologies: true

        # Vulnerability assessment
        enum:
          service: web
          check: [sql_injection, xss, csrf]

        # Exploitation
        exploit:
          target: web
          payloads: [sql_injection, xss]

        # Post-exploitation
        enum:
          service: web
          enumerate: [directories, files]

        # Cleanup
        cleanup:
          method: web
      `
    };
  }
}

export default WorkflowDSL;