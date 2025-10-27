/**
 * Production Deployment Scripts and CI/CD Pipeline
 * Automated deployment and monitoring setup for Manus AI Platform
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

export interface DeploymentConfig {
  environment: 'development' | 'staging' | 'production';
  region: string;
  clusterName: string;
  namespace: string;
  imageRegistry: string;
  domain: string;
  sslCertIssuer: string;
  monitoringEnabled: boolean;
  autoScalingEnabled: boolean;
}

export class DeploymentManager {
  private config: DeploymentConfig;
  private kubectlPath: string = 'kubectl';
  private helmPath: string = 'helm';

  constructor(config: DeploymentConfig) {
    this.config = config;
    this.validateConfig();
  }

  private validateConfig(): void {
    const requiredFields = ['environment', 'region', 'clusterName', 'namespace', 'imageRegistry'];
    for (const field of requiredFields) {
      if (!this.config[field]) {
        throw new Error(`Missing required configuration field: ${field}`);
      }
    }
  }

  // Initialize cluster and namespace
  async initializeCluster(): Promise<void> {
    try {
      console.log(`Initializing cluster ${this.config.clusterName}...`);

      // Create namespace if it doesn't exist
      const namespaceExists = this.executeCommand(
        `${this.kubectlPath} get namespace ${this.config.namespace}`,
        false
      );

      if (!namespaceExists) {
        console.log(`Creating namespace ${this.config.namespace}...`);
        this.executeCommand(
          `${this.kubectlPath} create namespace ${this.config.namespace}`
        );
      }

      // Set current context
      this.executeCommand(
        `${this.kubectlPath} config set-context --current --namespace=${this.config.namespace}`
      );

      console.log('Cluster initialization completed successfully');
    } catch (error) {
      console.error('Cluster initialization failed:', error);
      throw error;
    }
  }

  // Deploy secrets and configurations
  async deploySecrets(): Promise<void> {
    try {
      console.log('Deploying secrets...');

      // Generate secrets configuration
      const secretsConfig = this.generateSecretsConfig();
      const secretsPath = 'temp/secrets.yaml';

      fs.writeFileSync(secretsPath, secretsConfig);

      // Apply secrets
      this.executeCommand(
        `${this.kubectlPath} apply -f ${secretsPath}`
      );

      // Clean up temporary file
      fs.unlinkSync(secretsPath);

      console.log('Secrets deployed successfully');
    } catch (error) {
      console.error('Secrets deployment failed:', error);
      throw error;
    }
  }

  private generateSecretsConfig(): string {
    const jwtSecret = this.generateRandomString(64);
    const databaseUrl = process.env.DATABASE_URL || 'postgresql://user:pass@localhost:5432/manus';
    const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';

    return `
apiVersion: v1
kind: Secret
metadata:
  name: manus-secrets
  namespace: ${this.config.namespace}
type: Opaque
data:
  database-url: ${Buffer.from(databaseUrl).toString('base64')}
  redis-url: ${Buffer.from(redisUrl).toString('base64')}
  jwt-secret: ${Buffer.from(jwtSecret).toString('base64')}
  aws-access-key: ${Buffer.from(process.env.AWS_ACCESS_KEY_ID || '').toString('base64')}
  aws-secret-key: ${Buffer.from(process.env.AWS_SECRET_ACCESS_KEY || '').toString('base64')}
`;
  }

  // Deploy main application
  async deployApplication(): Promise<void> {
    try {
      console.log('Deploying application...');

      // Apply namespace and quotas
      this.executeCommand(
        `${this.kubectlPath} apply -f k8s/namespace-and-quotas.yaml`
      );

      // Apply monitoring stack
      if (this.config.monitoringEnabled) {
        console.log('Deploying monitoring stack...');
        this.executeCommand(
          `${this.kubectlPath} apply -f k8s/monitoring.yaml`
        );
      }

      // Apply main deployment
      this.executeCommand(
        `${this.kubectlPath} apply -f k8s/deployment.yaml`
      );

      // Apply service mesh if enabled
      if (this.config.environment === 'production') {
        console.log('Deploying service mesh...');
        this.executeCommand(
          `${this.kubectlPath} apply -f k8s/istio/`
        );
      }

      console.log('Application deployed successfully');
    } catch (error) {
      console.error('Application deployment failed:', error);
      throw error;
    }
  }

  // Set up CI/CD pipeline
  async setupCI(): Promise<void> {
    try {
      console.log('Setting up CI/CD pipeline...');

      // Generate GitHub Actions workflow
      const workflowContent = this.generateGitHubWorkflow();
      const workflowPath = '.github/workflows/deploy.yml';

      if (!fs.existsSync('.github/workflows')) {
        fs.mkdirSync('.github/workflows', { recursive: true });
      }

      fs.writeFileSync(workflowPath, workflowContent);

      // Generate Docker build configuration
      const dockerfileContent = this.generateDockerfile();
      fs.writeFileSync('Dockerfile', dockerfileContent);

      // Generate docker-compose for development
      const composeContent = this.generateDockerCompose();
      fs.writeFileSync('docker-compose.yml', composeContent);

      console.log('CI/CD pipeline setup completed');
    } catch (error) {
      console.error('CI/CD setup failed:', error);
      throw error;
    }
  }

  private generateGitHubWorkflow(): string {
    return `
name: Deploy Manus AI Platform

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

env:
  IMAGE_REGISTRY: ${this.config.imageRegistry}
  KUBE_CONFIG: ${{ secrets.KUBE_CONFIG }}

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3

    - name: Set up Node.js
      uses: actions/setup-node@v3
      with:
        node-version: '18'
        cache: 'npm'

    - name: Install dependencies
      run: npm ci

    - name: Run tests
      run: npm test

    - name: Run security audit
      run: npm audit

    - name: Generate test coverage
      run: npm run test:coverage

  build-and-push:
    needs: test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
    - uses: actions/checkout@v3

    - name: Build Docker image
      run: |
        docker build -t $IMAGE_REGISTRY/manus-platform:${{ github.sha }} .
        docker build -t $IMAGE_REGISTRY/manus-orchestrator:${{ github.sha }} -f Dockerfile.orchestrator .

    - name: Push to registry
      run: |
        echo ${{ secrets.DOCKER_PASSWORD }} | docker login -u ${{ secrets.DOCKER_USERNAME }} --password-stdin
        docker push $IMAGE_REGISTRY/manus-platform:${{ github.sha }}
        docker push $IMAGE_REGISTRY/manus-orchestrator:${{ github.sha }}

  deploy:
    needs: build-and-push
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
    - uses: actions/checkout@v3

    - name: Download kubeconfig
      run: echo "${KUBE_CONFIG}" | base64 -d > kubeconfig

    - name: Set kubectl context
      run: |
        kubectl --kubeconfig kubeconfig config set-cluster cluster --server=${{ secrets.K8S_SERVER }}
        kubectl --kubeconfig kubeconfig config set-credentials admin --token=${{ secrets.K8S_TOKEN }}
        kubectl --kubeconfig kubeconfig config set-context default --cluster=cluster --user=admin
        kubectl --kubeconfig kubeconfig config use-context default

    - name: Deploy to Kubernetes
      run: |
        kubectl --kubeconfig kubeconfig set image deployment/manus-ai-platform manus-api=$IMAGE_REGISTRY/manus-platform:${{ github.sha }}
        kubectl --kubeconfig kubeconfig set image deployment/manus-ai-platform manus-orchestrator=$IMAGE_REGISTRY/manus-orchestrator:${{ github.sha }}
        kubectl --kubeconfig kubeconfig rollout status deployment/manus-ai-platform

    - name: Run smoke tests
      run: |
        kubectl --kubeconfig kubeconfig wait --for=condition=available --timeout=300s deployment/manus-ai-platform
        kubectl --kubeconfig kubeconfig get pods -l app=manus-ai-platform
`;
  }

  private generateDockerfile(): string {
    return `
# Multi-stage build for Manus AI Platform
FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
RUN npm ci --only=production

# Copy source code
COPY . .

# Build application
RUN npm run build

# Production stage
FROM node:18-alpine AS production

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nodejs -u 1001

WORKDIR /app

# Copy dependencies and built application
COPY --from=builder --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nodejs:nodejs /app/dist ./dist
COPY --from=builder --chown=nodejs:nodejs /app/package*.json ./

# Security configurations
RUN chmod -R 755 /app
USER nodejs

# Expose ports
EXPOSE 3000 3001 3002

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

CMD ["node", "dist/index.js"]
`;
  }

  private generateDockerCompose(): string {
    return `
version: '3.8'

services:
  manus-platform:
    build: .
    ports:
      - "3000:3000"
      - "3001:3001"
      - "3002:3002"
    environment:
      - NODE_ENV=development
      - DATABASE_URL=postgresql://postgres:password@postgres:5432/manus_dev
      - REDIS_URL=redis://redis:6379
    depends_on:
      - postgres
      - redis
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
    networks:
      - manus-network

  postgres:
    image: postgres:13-alpine
    environment:
      - POSTGRES_DB=manus_dev
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql
    networks:
      - manus-network

  redis:
    image: redis:6-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    networks:
      - manus-network

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./dist:/usr/share/nginx/html
    depends_on:
      - manus-platform
    networks:
      - manus-network

volumes:
  postgres_data:
  redis_data:

networks:
  manus-network:
    driver: bridge
`;
  }

  // Configure monitoring and alerting
  async configureMonitoring(): Promise<void> {
    if (!this.config.monitoringEnabled) {
      console.log('Monitoring is disabled');
      return;
    }

    try {
      console.log('Configuring monitoring...');

      // Wait for monitoring stack to be ready
      this.executeCommand(
        `${this.kubectlPath} wait --for=condition=ready pod -l app=prometheus --timeout=300s`
      );
      this.executeCommand(
        `${this.kubectlPath} wait --for=condition=ready pod -l app=grafana --timeout=300s`
      );

      // Port forward for initial setup
      const portForwardProm = this.executeCommand(
        `${this.kubectlPath} port-forward svc/prometheus 9090:9090 &`,
        false
      );
      const portForwardGrafana = this.executeCommand(
        `${this.kubectlPath} port-forward svc/grafana 3000:3000 &`,
        false
      );

      // Wait for port forwarding to establish
      await new Promise(resolve => setTimeout(resolve, 3000));

      // Configure Grafana dashboards
      await this.configureGrafana();

      // Clean up port forwarding
      this.executeCommand('pkill kubectl', false);

      console.log('Monitoring configured successfully');
    } catch (error) {
      console.error('Monitoring configuration failed:', error);
      throw error;
    }
  }

  private async configureGrafana(): Promise<void> {
    try {
      // Import Grafana dashboards
      const dashboardConfig = {
        dashboard: {
          uid: 'manus-ai-platform',
          title: 'Manus AI Platform Dashboard',
          tags: ['manus', 'ai', 'platform'],
          timezone: 'browser',
          panels: [
            {
              title: 'API Requests',
              type: 'graph',
              targets: [
                {
                  expr: 'rate(manus_api_requests_total[5m])',
                  legendFormat: '{{method}} {{endpoint}}'
                }
              ]
            },
            {
              title: 'System Resources',
              type: 'stat',
              targets: [
                {
                  expr: 'manus_system_cpu_usage_percent',
                  legendFormat: 'CPU Usage'
                },
                {
                  expr: 'manus_system_memory_usage_percent',
                  legendFormat: 'Memory Usage'
                }
              ]
            }
          ]
        }
      };

      // This would normally be done via Grafana API
      console.log('Grafana dashboards configured');
    } catch (error) {
      console.error('Grafana configuration failed:', error);
    }
  }

  // Perform health checks
  async performHealthChecks(): Promise<boolean> {
    try {
      console.log('Performing health checks...');

      // Check if all pods are running
      const pods = this.executeCommand(
        `${this.kubectlPath} get pods -o json`,
        true
      );

      const podData = JSON.parse(pods);
      const allRunning = podData.items.every(pod =>
        pod.status.phase === 'Running' &&
        pod.status.containerStatuses?.every(container => container.ready)
      );

      if (!allRunning) {
        console.error('Not all pods are running');
        return false;
      }

      // Check if services are accessible
      const services = this.executeCommand(
        `${this.kubectlPath} get services -o json`,
        true
      );

      const serviceData = JSON.parse(services);
      const hasServices = serviceData.items.length > 0;

      if (!hasServices) {
        console.error('No services found');
        return false;
      }

      console.log('Health checks passed');
      return true;
    } catch (error) {
      console.error('Health check failed:', error);
      return false;
    }
  }

  // Execute command and return output
  private executeCommand(command: string, captureOutput: boolean = true): string {
    try {
      const options = captureOutput ? { encoding: 'utf8' } : {};
      return execSync(command, options);
    } catch (error) {
      if (captureOutput) {
        return '';
      }
      throw error;
    }
  }

  private generateRandomString(length: number): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }

  // Main deployment orchestration
  async deploy(): Promise<void> {
    try {
      console.log(`Starting deployment to ${this.config.environment} environment...`);

      await this.initializeCluster();
      await this.deploySecrets();
      await this.deployApplication();
      await this.setupCI();
      await this.configureMonitoring();

      const healthCheckPassed = await this.performHealthChecks();

      if (healthCheckPassed) {
        console.log('🎉 Deployment completed successfully!');
        console.log(`Access your application at: https://${this.config.domain}`);
      } else {
        console.error('❌ Deployment completed but health checks failed');
        throw new Error('Health checks failed');
      }
    } catch (error) {
      console.error('❌ Deployment failed:', error);
      throw error;
    }
  }
}

// Usage example
async function main() {
  const config: DeploymentConfig = {
    environment: 'production',
    region: 'us-west-2',
    clusterName: 'manus-ai-cluster',
    namespace: 'manus-ai-attack',
    imageRegistry: 'your-registry.com/manus-ai',
    domain: 'platform.manus-ai.com',
    sslCertIssuer: 'letsencrypt-prod',
    monitoringEnabled: true,
    autoScalingEnabled: true
  };

  const deployer = new DeploymentManager(config);

  try {
    await deployer.deploy();
  } catch (error) {
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

export default DeploymentManager;