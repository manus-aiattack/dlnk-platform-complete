# Prometheus Metrics Exporter for Manus AI Platform
# Custom metrics for AI platform monitoring

import prometheus_client
from prometheus_client import Counter, Histogram, Gauge, Info
import time
import psutil
import logging
from core.logger import log

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Custom metrics for Manus AI Platform
class ManusMetrics:
    def __init__(self):
        # API Metrics
        self.api_requests_total = Counter(
            'manus_api_requests_total',
            'Total API requests',
            ['method', 'endpoint', 'status']
        )

        self.api_request_duration = Histogram(
            'manus_api_request_duration_seconds',
            'API request duration',
            ['method', 'endpoint']
        )

        # Workflow Metrics
        self.workflow_executions_total = Counter(
            'manus_workflow_executions_total',
            'Total workflow executions',
            ['workflow_id', 'status']
        )

        self.workflow_duration = Histogram(
            'manus_workflow_duration_seconds',
            'Workflow execution duration',
            ['workflow_id']
        )

        self.workflow_steps_total = Counter(
            'manus_workflow_steps_total',
            'Total workflow steps executed',
            ['step_name', 'status']
        )

        # Agent Metrics
        self.agent_executions_total = Counter(
            'manus_agent_executions_total',
            'Total agent executions',
            ['agent_name', 'agent_type', 'status']
        )

        self.agent_execution_duration = Histogram(
            'manus_agent_execution_duration_seconds',
            'Agent execution duration',
            ['agent_name', 'agent_type']
        )

        self.active_agents = Gauge(
            'manus_active_agents',
            'Number of active agents',
            ['agent_type']
        )

        # Security Metrics
        self.auth_attempts_total = Counter(
            'manus_auth_attempts_total',
            'Total authentication attempts',
            ['status', 'method']
        )

        self.auth_duration = Histogram(
            'manus_auth_duration_seconds',
            'Authentication duration',
            ['method']
        )

        self.security_events_total = Counter(
            'manus_security_events_total',
            'Total security events',
            ['event_type', 'severity']
        )

        # Database Metrics
        self.db_connection_errors = Counter(
            'manus_db_connection_errors_total',
            'Database connection errors'
        )

        self.db_query_duration = Histogram(
            'manus_db_query_duration_seconds',
            'Database query duration',
            ['query_type']
        )

        # Redis Metrics
        self.redis_connection_errors = Counter(
            'manus_redis_connection_errors_total',
            'Redis connection errors'
        )

        self.redis_operations_total = Counter(
            'manus_redis_operations_total',
            'Redis operations',
            ['operation_type', 'status']
        )

        # System Metrics
        self.system_cpu_usage = Gauge(
            'manus_system_cpu_usage_percent',
            'System CPU usage percentage'
        )

        self.system_memory_usage = Gauge(
            'manus_system_memory_usage_percent',
            'System memory usage percentage'
        )

        self.system_disk_usage = Gauge(
            'manus_system_disk_usage_percent',
            'System disk usage percentage'
        )

        # Business Metrics
        self.total_attacks = Gauge(
            'manus_total_attacks',
            'Total number of attacks'
        )

        self.active_attacks = Gauge(
            'manus_active_attacks',
            'Number of active attacks'
        )

        self.successful_attacks = Counter(
            'manus_successful_attacks_total',
            'Total successful attacks'
        )

        self.failed_attacks = Counter(
            'manus_failed_attacks_total',
            'Total failed attacks'
        )

        # Initialize system metrics
        self._initialize_system_metrics()

    def _initialize_system_metrics(self):
        """Initialize system metrics with current values"""
        try:
            self.system_cpu_usage.set(psutil.cpu_percent())
            self.system_memory_usage.set(psutil.virtual_memory().percent)
            self.system_disk_usage.set(psutil.disk_usage('/').percent)
        except Exception as e:
            logger.error(f"Failed to initialize system metrics: {e}")

    # API Metrics Methods
    def record_api_request(self, method, endpoint, status, duration):
        """Record API request metrics"""
        self.api_requests_total.labels(method=method, endpoint=endpoint, status=status).inc()
        self.api_request_duration.labels(method=method, endpoint=endpoint).observe(duration)

    # Workflow Metrics Methods
    def record_workflow_execution(self, workflow_id, status, duration):
        """Record workflow execution metrics"""
        self.workflow_executions_total.labels(workflow_id=workflow_id, status=status).inc()
        if status == 'completed':
            self.workflow_duration.labels(workflow_id=workflow_id).observe(duration)

    def record_workflow_step(self, step_name, status):
        """Record workflow step metrics"""
        self.workflow_steps_total.labels(step_name=step_name, status=status).inc()

    # Agent Metrics Methods
    def record_agent_execution(self, agent_name, agent_type, status, duration):
        """Record agent execution metrics"""
        self.agent_executions_total.labels(
            agent_name=agent_name,
            agent_type=agent_type,
            status=status
        ).inc()
        if status == 'completed':
            self.agent_execution_duration.labels(
                agent_name=agent_name,
                agent_type=agent_type
            ).observe(duration)

    def update_active_agents(self, agent_type, count):
        """Update active agents count"""
        self.active_agents.labels(agent_type=agent_type).set(count)

    # Security Metrics Methods
    def record_auth_attempt(self, status, method, duration):
        """Record authentication attempt metrics"""
        self.auth_attempts_total.labels(status=status, method=method).inc()
        self.auth_duration.labels(method=method).observe(duration)

    def record_security_event(self, event_type, severity):
        """Record security event"""
        self.security_events_total.labels(event_type=event_type, severity=severity).inc()

    # Database Metrics Methods
    def record_db_error(self):
        """Record database connection error"""
        self.db_connection_errors.inc()

    def record_db_query(self, query_type, duration):
        """Record database query metrics"""
        self.db_query_duration.labels(query_type=query_type).observe(duration)

    # Redis Metrics Methods
    def record_redis_error(self):
        """Record Redis connection error"""
        self.redis_connection_errors.inc()

    def record_redis_operation(self, operation_type, status):
        """Record Redis operation metrics"""
        self.redis_operations_total.labels(operation_type=operation_type, status=status).inc()

    # Business Metrics Methods
    def update_total_attacks(self, count):
        """Update total attacks count"""
        self.total_attacks.set(count)

    def update_active_attacks(self, count):
        """Update active attacks count"""
        self.active_attacks.set(count)

    def record_successful_attack(self):
        """Record successful attack"""
        self.successful_attacks.inc()

    def record_failed_attack(self):
        """Record failed attack"""
        self.failed_attacks.inc()

    # System Metrics Update
    def update_system_metrics(self):
        """Update system metrics"""
        try:
            self.system_cpu_usage.set(psutil.cpu_percent(interval=1))
            self.system_memory_usage.set(psutil.virtual_memory().percent)
            self.system_disk_usage.set(psutil.disk_usage('/').percent)
        except Exception as e:
            logger.error(f"Failed to update system metrics: {e}")

# Middleware for recording API metrics
class MetricsMiddleware:
    def __init__(self, app, metrics):
        self.app = app
        self.metrics = metrics

    def __call__(self, environ, start_response):
        start_time = time.time()

        def new_start_response(status, response_headers, exc_info=None):
            # Record metrics
            duration = time.time() - start_time
            status_code = status.split(' ')[0]
            method = environ.get('REQUEST_METHOD', 'UNKNOWN')
            path = environ.get('PATH_INFO', 'UNKNOWN')

            self.metrics.record_api_request(method, path, status_code, duration)

            return start_response(status, response_headers, exc_info)

        return self.app(environ, new_start_response)

# Background metrics updater
def start_metrics_updater(metrics, interval=30):
    """Start background thread to update metrics"""
    import threading
    import time

    def update_loop():
        while True:
            try:
                metrics.update_system_metrics()
                time.sleep(interval)
            except Exception as e:
                logger.error(f"Error in metrics updater: {e}")
                time.sleep(interval)

    updater_thread = threading.Thread(target=update_loop, daemon=True)
    updater_thread.start()

# Create global metrics instance
manus_metrics = ManusMetrics()

# Start metrics updater
start_metrics_updater(manus_metrics)

# Export metrics endpoint
def metrics_endpoint():
    """Return Prometheus metrics"""
    return prometheus_client.generate_latest().decode('utf-8')

if __name__ == '__main__':
    # Start HTTP server for metrics
    from wsgiref.simple_server import make_server

    # Create a simple WSGI app that serves metrics
    def metrics_app(environ, start_response):
        if environ['PATH_INFO'] == '/metrics':
            start_response('200 OK', [('Content-Type', 'text/plain')])
            return [metrics_endpoint().encode('utf-8')]
        else:
            start_response('404 Not Found', [('Content-Type', 'text/plain')])
            return [b'Not Found']

    # Start server
    httpd = make_server('', 8000, metrics_app)
    logger.info("Metrics server started on port 8000")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Metrics server stopped")