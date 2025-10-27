# dLNk dLNk: Developer Guide

This guide provides instructions and best practices for developing and extending the dLNk dLNk framework.

## Project Structure

The project is organized into the following key directories:

```
/dlnk_dlnk
├── /agents/           # All individual agent modules
├── /api/              # FastAPI application and endpoints
├── /cli/              # Command-line interface logic
├── /config/           # Default configurations and workflows
├── /core/             # Core components (Orchestrator, AgentRegistry, etc.)
├── /docs/             # Documentation files
├── /logs/             # Log output files
├── /tests/            # Pytest test suites
└── main.py            # Main entry point for the CLI
```

## Creating a New Agent

To create a new agent, follow these steps:

1.  **Create a new Python file** in the `dlnk_dlnk/agents/` directory (e.g., `my_new_agent.py`).
2.  **Define a new class** that inherits from `BaseAgent`.
3.  **Implement the `run` method**. This is the main entry point for your agent's logic.
4.  **Define the `validate_strategy` method** to ensure the agent receives the necessary context and parameters.
5.  **Return an `AgentData` object** from the `run` method, containing the results of the agent's execution.

### Example Agent (`MyNewAgent`)

```python
# /agents/my_new_agent.py

from core.base_agent import BaseAgent
from core.data_models import AgentData, Strategy, AttackPhase
from core.logger import log

class MyNewAgent(BaseAgent):
    """A brief description of what this agent does."""

    async def run(self, strategy: Strategy) -> AgentData:
        """The main execution logic for the agent."""
        log.info(f"Running {self.name} with directive: {strategy.directive}")

        # 1. Get necessary data from context
        target_ip = await self.context_manager.get_context("target_ip")
        if not target_ip:
            return AgentData(agent_name=self.name, success=False, errors=["Target IP not found in context."])

        # 2. Perform actions (e.g., run a tool, make a request)
        # ... your logic here ...

        # 3. Create a report and return it
        report = AgentData(
            agent_name=self.name,
            success=True,
            summary=f"Successfully performed action on {target_ip}",
            raw_output="..."
        )
        return report

    def validate_strategy(self, strategy: Strategy) -> bool:
        """Validate that the agent has the required context to run."""
        return strategy.context.get("target_ip") is not None
```

The framework will automatically discover this new agent when it starts.

## Running Tests

The framework uses `pytest` for testing. To run the full test suite:

```bash
cd /path/to/dlnk_dlnk
pytest
```

To run tests for a specific file:

```bash
pytest tests/test_orchestrator.py
```

When adding new features, please include corresponding tests in the `tests/` directory.

## Logging

The framework uses a centralized logging system. To use it within an agent, simply import and use the `log` object:

```python
from core.logger import log

log.info("This is an info message.")
log.success("This indicates a successful operation.")
log.warning("This is a warning.")
log.error("This indicates an error.")
log.phase("This is for marking major phases.")
```

Logs are automatically streamed to the console, a file (`logs/dlnk_dlnk.log`), and the web dashboard via WebSockets.

## Context Management

Agents share information via the `ContextManager`. It provides a simple async key-value store backed by Redis.

*   **Setting a value**:
    ```python
    await self.context_manager.set_context("new_finding", {"port": 8080, "service": "http"})
    ```

*   **Getting a value**:
    ```python
    finding = await self.context_manager.get_context("new_finding")
    ```

## Workflow Configuration

Workflows are defined in YAML files inside the `config/` directory. A workflow consists of one or more phases, and each phase contains a list of agents to be executed.

### Example Workflow (`config/simple_workflow.yaml`)

```yaml
workflow_name: Simple Scan
description: A simple workflow to scan a target and report open ports.

phases:
  - name: Reconnaissance
    agents:
      - name: NmapScanAgent
        directive: "Perform a quick scan on the target."
        context:
          scan_args: "-T4 -F"

  - name: Reporting
    agents:
      - name: ReportingAgent
        directive: "Generate a summary report of all findings."
```

To execute this workflow:

```bash
dlnk-dlnk run --workflow config/simple_workflow.yaml --target localhost:8000
```

