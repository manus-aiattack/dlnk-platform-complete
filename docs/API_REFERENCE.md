# dLNk dLNk Framework - API Reference

**Version:** 1.0.0
**Base URL:** `/`

This document provides a detailed reference for the RESTful API of the dLNk dLNk Framework. The API allows for programmatic interaction with the framework, enabling integration with other tools and automation of complex attack workflows.

---

## 1. General Endpoints

### **`GET /`**

- **Description:** Serves the main HTML dashboard for real-time monitoring and control.
- **Response:**
  - `200 OK`: Returns the `dashboard.html` file.

### **`GET /health`**

- **Description:** A simple health check endpoint to verify that the API server is running and healthy.
- **Response:**
  - `200 OK`: Returns a JSON object indicating the status.

  **Example Response:**
  ```json
  {
    "status": "healthy",
    "version": "1.0.0",
    "framework": "dLNk dLNk"
  }
  ```

### **`GET /status`**

- **Description:** Retrieves the current operational status of the framework's orchestrator.
- **Response:**
  - `200 OK`: Returns a `StatusResponse` object with details about the framework's state.
  - `503 Service Unavailable`: If the orchestrator has not been initialized.

  **Response Model (`StatusResponse`):**
  ```json
  {
    "running": true,
    "current_phase": "Reconnaissance",
    "agents_registered": 15,
    "results_count": 5
  }
  ```

### **`WS /ws/logs`**

- **Description:** Establishes a WebSocket connection to stream real-time logs from the orchestrator and all active agents. This is the primary way to monitor live operations.
- **Usage:** Connect to this endpoint using a WebSocket client. The server will push JSON-formatted log entries as they are generated.

  **Log Entry Format:**
  ```json
  {
    "level": "INFO",
    "message": "SQLMap Agent discovered a potential SQL injection point.",
    "timestamp": "2025-10-22T10:30:00Z",
    "agent": "SQLMap Agent"
  }
  ```

---

## 2. Agent Management

### **`GET /agents`**

- **Description:** Lists all agents that have been registered with the orchestrator and are available for execution.
- **Response:**
  - `200 OK`: Returns a list of all available agents with their metadata.

  **Example Response:**
  ```json
  {
    "count": 1,
    "agents": [
      {
        "name": "SQLMap Agent",
        "description": "Automates SQL Injection discovery and exploitation.",
        "author": "Manus AI",
        "version": "2.0",
        "directives": ["find_and_exploit", "dump_database"]
      }
    ]
  }
  ```

### **`GET /agents/{agent_name}`**

- **Description:** Retrieves detailed information about a single, specified agent.
- **Path Parameters:**
  - `agent_name` (string, required): The name of the agent to retrieve (e.g., `sqlmap_agent`).
- **Response:**
  - `200 OK`: Returns the detailed information for the requested agent.
  - `404 Not Found`: If the specified agent name does not exist.

---

## 3. Workflow and Execution

### **`POST /workflows/execute`**

- **Description:** Executes a predefined attack workflow. This is a primary endpoint for starting an automated attack sequence. The execution is run as a background task.
- **Request Body (`WorkflowExecutionRequest`):**
  ```json
  {
    "workflow_path": "config/attack_full_auto_workflow.yaml",
    "target": {
      "name": "Example Corp",
      "url": "localhost:8000",
      "description": "Main web server of Example Corp."
    }
  }
  ```
- **Response:**
  - `200 OK`: Indicates that the workflow has been successfully started in the background.
  - `500 Internal Server Error`: If there was an error starting the workflow.

  **Example Response:**
  ```json
  {
    "status": "started",
    "message": "Workflow execution started for target: Example Corp",
    "target": "Example Corp"
  }
  ```

### **`POST /agents/execute`**

- **Description:** Executes a single agent with a specific directive. This allows for more granular control over the framework's operations.
- **Request Body (`AgentExecutionRequest`):**
  ```json
  {
    "agent_name": "XSS_Agent",
    "directive": "find_reflected_xss",
    "context": {
      "target_url": "localhost:8000/search?q=test"
    }
  }
  ```
- **Response:**
  - `200 OK`: Returns the result of the agent's execution.
  - `500 Internal Server Error`: If the agent execution fails.

  **Example Response:**
  ```json
  {
    "agent_name": "XSS_Agent",
    "success": true,
    "summary": "Found a reflected XSS vulnerability.",
    "errors": [],
    "data": {
      "vulnerable_url": "localhost:8000/search?q=<script>alert(1)</script>",
      "payload": "<script>alert(1)</script>"
    }
  }
  ```

---

## 4. Results

### **`GET /results`**

- **Description:** Retrieves a list of all results collected during the current campaign.
- **Response:**
  - `200 OK`: Returns a list of all result objects.

### **`GET /results/{index}`**

- **Description:** Retrieves a specific result by its index in the results list.
- **Path Parameters:**
  - `index` (integer, required): The index of the result to retrieve.
- **Response:**
  - `200 OK`: Returns the specified result object.
  - `404 Not Found`: If the index is out of bounds.

