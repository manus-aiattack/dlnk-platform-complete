/**
 * Workflow Automation API - RESTful API for Workflow Management
 * Provides HTTP endpoints for workflow creation, execution, and monitoring
 */

import express from 'express';
import { AIWorkflowGenerator } from '../core/ai_workflow_generator';
import { WorkflowDSL } from '../core/workflow_dsl';
import { WorkflowExecutor } from '../core/workflow_executor';
import { EnhancedOrchestrator } from '../core/enhanced_orchestrator';
import { EnhancedAIDecisionEngine } from '../core/ai_models/enhanced_ai_decision_engine';

export class WorkflowAPI {
  private app: express.Application;
  private workflowGenerator: AIWorkflowGenerator;
  private workflowDSL: WorkflowDSL;
  private workflowExecutor: WorkflowExecutor;
  private port: number;

  constructor(
    port: number = 3001,
    orchestrator: EnhancedOrchestrator,
    decisionEngine: EnhancedAIDecisionEngine
  ) {
    this.app = express();
    this.port = port;
    this.workflowGenerator = new AIWorkflowGenerator(orchestrator, decisionEngine);
    this.workflowDSL = new WorkflowDSL();
    this.workflowExecutor = new WorkflowExecutor(decisionEngine, orchestrator);

    this.setupMiddleware();
    this.setupRoutes();
  }

  private setupMiddleware(): void {
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true }));

    // CORS middleware
    this.app.use((req, res, next) => {
      res.header('Access-Control-Allow-Origin', '*');
      res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
      res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      next();
    });

    // Authentication middleware (simplified)
    this.app.use('/api/v2/*', (req, res, next) => {
      const token = req.headers.authorization?.replace('Bearer ', '');
      if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
      }
      next();
    });
  }

  private setupRoutes(): void {
    // Health check
    this.app.get('/health', (req, res) => {
      res.json({ status: 'healthy', timestamp: new Date().toISOString() });
    });

    // NLP-based workflow generation
    this.app.post('/api/v2/workflows/generate', async (req, res) => {
      try {
        const { description, target } = req.body;

        if (!description) {
          return res.status(400).json({ error: 'Description is required' });
        }

        // Parse natural language
        const nlpResult = await this.workflowGenerator.parseNaturalLanguage(description);

        // Generate workflow
        const workflow = await this.workflowGenerator.generateWorkflowFromNLP({
          ...nlpResult,
          entities: { ...nlpResult.entities, target }
        });

        res.json({
          success: true,
          workflow,
          nlp_result: nlpResult
        });
      } catch (error) {
        console.error('Workflow generation error:', error);
        res.status(500).json({ error: 'Failed to generate workflow' });
      }
    });

    // DSL-based workflow creation
    this.app.post('/api/v2/workflows/dsl', async (req, res) => {
      try {
        const { dsl, target } = req.body;

        if (!dsl) {
          return res.status(400).json({ error: 'DSL is required' });
        }

        // Parse DSL
        const dslWorkflow = this.workflowDSL.parseWorkflowDSL(dsl);

        // Set target if provided
        if (target) {
          dslWorkflow.target = target;
        }

        // Convert to executable workflow
        const workflow = this.workflowDSL.convertToWorkflow(dslWorkflow);

        res.json({
          success: true,
          workflow
        });
      } catch (error) {
        console.error('DSL workflow creation error:', error);
        res.status(500).json({ error: 'Failed to create workflow from DSL' });
      }
    });

    // Execute workflow
    this.app.post('/api/v2/workflows/:workflowId/execute', async (req, res) => {
      try {
        const { workflowId } = req.params;
        const { context = {} } = req.body;

        // Load workflow (in practice would load from storage)
        const workflow = this.workflowGenerator.getWorkflow(workflowId);
        if (!workflow) {
          return res.status(404).json({ error: 'Workflow not found' });
        }

        // Execute workflow
        const executionId = await this.workflowExecutor.executeWorkflow(workflow, context);

        res.json({
          success: true,
          executionId,
          message: 'Workflow execution started'
        });
      } catch (error) {
        console.error('Workflow execution error:', error);
        res.status(500).json({ error: 'Failed to execute workflow' });
      }
    });

    // Get execution status
    this.app.get('/api/v2/executions/:executionId/status', async (req, res) => {
      try {
        const { executionId } = req.params;

        const status = this.workflowExecutor.getExecutionStatus(executionId);
        if (!status) {
          return res.status(404).json({ error: 'Execution not found' });
        }

        res.json({
          success: true,
          status
        });
      } catch (error) {
        console.error('Get execution status error:', error);
        res.status(500).json({ error: 'Failed to get execution status' });
      }
    });

    // Cancel execution
    this.app.post('/api/v2/executions/:executionId/cancel', async (req, res) => {
      try {
        const { executionId } = req.params;

        const success = await this.workflowExecutor.cancelExecution(executionId);
        if (!success) {
          return res.status(404).json({ error: 'Execution not found' });
        }

        res.json({
          success: true,
          message: 'Execution cancelled'
        });
      } catch (error) {
        console.error('Cancel execution error:', error);
        res.status(500).json({ error: 'Failed to cancel execution' });
      }
    });

    // Pause execution
    this.app.post('/api/v2/executions/:executionId/pause', async (req, res) => {
      try {
        const { executionId } = req.params;

        const success = await this.workflowExecutor.pauseExecution(executionId);
        if (!success) {
          return res.status(404).json({ error: 'Execution not found' });
        }

        res.json({
          success: true,
          message: 'Execution paused'
        });
      } catch (error) {
        console.error('Pause execution error:', error);
        res.status(500).json({ error: 'Failed to pause execution' });
      }
    });

    // Resume execution
    this.app.post('/api/v2/executions/:executionId/resume', async (req, res) => {
      try {
        const { executionId } = req.params;

        const success = await this.workflowExecutor.resumeExecution(executionId);
        if (!success) {
          return res.status(404).json({ error: 'Execution not found or not paused' });
        }

        res.json({
          success: true,
          message: 'Execution resumed'
        });
      } catch (error) {
        console.error('Resume execution error:', error);
        res.status(500).json({ error: 'Failed to resume execution' });
      }
    });

    // Get execution history
    this.app.get('/api/v2/workflows/:workflowId/history', async (req, res) => {
      try {
        const { workflowId } = req.params;

        const history = this.workflowExecutor.getExecutionHistory(workflowId);

        res.json({
          success: true,
          history
        });
      } catch (error) {
        console.error('Get execution history error:', error);
        res.status(500).json({ error: 'Failed to get execution history' });
      }
    });

    // Optimize workflow
    this.app.post('/api/v2/workflows/:workflowId/optimize', async (req, res) => {
      try {
        const { workflowId } = req.params;

        const workflow = this.workflowGenerator.getWorkflow(workflowId);
        if (!workflow) {
          return res.status(404).json({ error: 'Workflow not found' });
        }

        const optimizedWorkflow = await this.workflowExecutor.optimizeWorkflow(workflow);

        res.json({
          success: true,
          originalWorkflow: workflow,
          optimizedWorkflow
        });
      } catch (error) {
        console.error('Workflow optimization error:', error);
        res.status(500).json({ error: 'Failed to optimize workflow' });
      }
    });

    // Get example DSL templates
    this.app.get('/api/v2/workflows/templates', async (req, res) => {
      try {
        const templates = WorkflowDSL.getExampleTemplates();

        res.json({
          success: true,
          templates
        });
      } catch (error) {
        console.error('Get templates error:', error);
        res.status(500).json({ error: 'Failed to get templates' });
      }
    });

    // Get execution statistics
    this.app.get('/api/v2/stats/executions', async (req, res) => {
      try {
        const stats = await this.workflowExecutor.getExecutionStats();

        res.json({
          success: true,
          stats
        });
      } catch (error) {
        console.error('Get execution stats error:', error);
        res.status(500).json({ error: 'Failed to get execution stats' });
      }
    });

    // Error handling
    this.app.use((err: any, req: any, res: any, next: any) => {
      console.error('API error:', err);
      res.status(500).json({ error: 'Internal server error' });
    });
  }

  start(): void {
    this.app.listen(this.port, () => {
      console.log(`Workflow API server started on port ${this.port}`);
      console.log(`Available endpoints:`);
      console.log(`  POST /api/v2/workflows/generate - Generate workflow from natural language`);
      console.log(`  POST /api/v2/workflows/dsl - Create workflow from DSL`);
      console.log(`  POST /api/v2/workflows/:id/execute - Execute workflow`);
      console.log(`  GET /api/v2/executions/:id/status - Get execution status`);
      console.log(`  POST /api/v2/executions/:id/cancel - Cancel execution`);
      console.log(`  POST /api/v2/executions/:id/pause - Pause execution`);
      console.log(`  POST /api/v2/executions/:id/resume - Resume execution`);
      console.log(`  GET /api/v2/workflows/:id/history - Get execution history`);
      console.log(`  POST /api/v2/workflows/:id/optimize - Optimize workflow`);
      console.log(`  GET /api/v2/workflows/templates - Get DSL templates`);
      console.log(`  GET /api/v2/stats/executions - Get execution statistics`);
    });
  }

  getApp(): express.Application {
    return this.app;
  }
}

export default WorkflowAPI;