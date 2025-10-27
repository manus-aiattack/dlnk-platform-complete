# dLNk dLNk Framework - CLI Reference

**Version:** 3.0 (Final)

This document provides a reference for the Command-Line Interface (CLI) of the dLNk dLNk Framework. The CLI is the primary tool for direct interaction and control over the framework's operations.

The base command for the CLI is `dlnk-dlnk`.

---

## 1. Core Commands

These are the main commands for controlling the framework.

### **`dlnk-dlnk run`**

- **Description:** Executes a complete attack workflow against a specified target using a YAML configuration file.
- **Usage:**
  ```bash
  dlnk-dlnk run [OPTIONS]
  ```
- **Options:**
  - `--workflow, -w TEXT`: Path to the workflow YAML file. (Default: `config/default_workflow.yaml`)
  - `--target, -t TEXT`: **(Required)** The target's URL or IP address.
  - `--name, -n TEXT`: A descriptive name for the target. (Default: 'Target')
  - `--output, -o TEXT`: Path to a JSON file to save the results.

### **`dlnk-dlnk agent`**

- **Description:** Executes a single, specific agent with a given directive and context.
- **Usage:**
  ```bash
  dlnk-dlnk agent [OPTIONS]
  ```
- **Options:**
  - `--agent, -a TEXT`: **(Required)** The name of the agent to execute (e.g., `sqlmap_agent`).
  - `--directive, -d TEXT`: **(Required)** The specific task or command for the agent to perform.
  - `--context, -c TEXT`: A JSON string representing the context or data to pass to the agent.
  - `--output, -o TEXT`: Path to a JSON file to save the result.

### **`dlnk-dlnk agents`**

- **Description:** Lists all the agents that are currently registered and available within the framework.
- **Usage:**
  ```bash
  dlnk-dlnk agents
  ```

### **`dlnk-dlnk status`**

- **Description:** Displays the current operational status of the framework's orchestrator.
- **Usage:**
  ```bash
  dlnk-dlnk status
  ```

### **`dlnk-dlnk validate`**

- **Description:** Validates the syntax and structure of a workflow YAML file.
- **Usage:**
  ```bash
  dlnk-dlnk validate --workflow <path_to_workflow.yaml>
  ```

### **`dlnk-dlnk init`**

- **Description:** Initializes a new, clean workspace directory with the required subfolders (`workflows`, `targets`, `results`, `loot`).
- **Usage:**
  ```bash
  dlnk-dlnk init
  ```

### **`dlnk-dlnk server`**

- **Description:** Starts the FastAPI web server, providing access to the REST API and the real-time dashboard.
- **Usage:**
  ```bash
  dlnk-dlnk server [OPTIONS]
  ```
- **Options:**
  - `--host, -h TEXT`: The host IP to bind the server to. (Default: `0.0.0.0`)
  - `--port, -p INTEGER`: The port to run the server on. (Default: `8000`)

### **`dlnk-dlnk version`**

- **Description:** Displays the current version of the dLNk dLNk Framework.
- **Usage:**
  ```bash
  dlnk-dlnk version
  ```

---

## 2. Attack Commands (`dlnk-dlnk attack`)

This command group, defined in `attack_cli.py`, provides a structured, phased approach to executing an attack.

### **`dlnk-dlnk attack scan`**
- **Description:** Phase 1 - Initiates reconnaissance and vulnerability scanning against a target.
- **Usage:** `dlnk-dlnk attack scan --target <URL/IP>`

### **`dlnk-dlnk attack exploit`**
- **Description:** Phase 2 - Attempts to exploit vulnerabilities found in the scan phase.
- **Usage:** `dlnk-dlnk attack exploit --scan-file <path_to_scan_results.json>`

### **`dlnk-dlnk attack post-exploit`**
- **Description:** Phase 3 - Executes post-exploitation techniques after a successful breach.
- **Usage:** `dlnk-dlnk attack post-exploit --exploit-file <path_to_exploit_results.json>`

### **`dlnk-dlnk attack full-auto`**
- **Description:** Executes a fully automated attack from scan to post-exploitation.
- **Usage:** `dlnk-dlnk attack full-auto --target <URL/IP>`

---

## 3. License Management (`dlnk-dlnk license`)

This command group, defined in `license_cli.py`, manages the framework's license keys.

### **`dlnk-dlnk license generate`**
- **Description:** (Admin only) Generates a new license key.
- **Usage:** `dlnk-dlnk license generate --days <number_of_days> --user <username>`

### **`dlnk-dlnk license activate`**
- **Description:** Activates the framework with a given license key.
- **Usage:** `dlnk-dlnk license activate <LICENSE_KEY>`

### **`dlnk-dlnk license status`**
- **Description:** Checks the status of the current license.
- **Usage:** `dlnk-dlnk license status`

