# dLNk dLNk Framework - Deployment Guide

**Version:** 3.0 (Final)

This guide provides comprehensive instructions for deploying the dLNk dLNk Framework in a production environment. The recommended deployment method is using Docker and Docker Compose, which encapsulates all required services and dependencies into isolated containers.

---

## 1. Prerequisites

Before you begin, ensure you have the following software installed on your deployment server:

- **Docker Engine:** Version 20.10.0 or newer.
- **Docker Compose:** Version 1.29.0 or newer.
- **A valid License Key:** You must have a license key to activate and use the framework.

---

## 2. Deployment Steps

The deployment process is designed to be straightforward using the provided Docker configuration.

### Step 1: Obtain the Framework Package

First, acquire the final framework package, `dlnk_dlnk_framework_v3_final.zip`, and transfer it to your deployment server.

### Step 2: Unpack the Archive

Unzip the package to create the project directory.

```bash
unzip dlnk_dlnk_framework_v3_final.zip
cd dlnk_dlnk
```

This will create a directory named `dlnk_dlnk` containing the framework source code, Docker files, and configuration.

### Step 3: Configure Environment Variables

The framework uses a `.env` file to manage configuration settings. An example file, `.env.example`, is provided. Copy this file to create your own configuration:

```bash
cp .env.example .env
```

Now, edit the `.env` file and customize the settings as needed. The most critical variable is `REDIS_PASSWORD`.

**`.env` File Contents:**
```
# Docker Settings
COMPOSE_PROJECT_NAME=dlnk_dlnk

# Redis Configuration
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=YourSecretPasswordHere # <-- CHANGE THIS

# API Server Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_DEBUG=False

# Workspace Directory
WORKSPACE_DIR=/app/workspace
```

> **Security Warning:** It is crucial to set a strong, unique password for `REDIS_PASSWORD` to secure the communication and data bus between agents.

### Step 4: Build and Launch the Containers

With the configuration in place, use Docker Compose to build the images and launch all services in detached mode.

```bash
docker-compose up --build -d
```

This command will:
1.  Build the Docker image for the dLNk dLNk application, installing all Python dependencies.
2.  Pull the official Redis image.
3.  Create and start containers for the API server and the Redis database.

### Step 5: Activate the License

Before you can run any attacks, you must activate the framework using your license key. Execute the `license activate` command inside the running `app` container:

```bash
docker-compose exec app dlnk-dlnk license activate <YOUR_LICENSE_KEY>
```

### Step 6: Verify the Deployment

Check that all containers are running correctly:

```bash
docker-compose ps
```

You should see output similar to this, with both `dlnk_dlnk_app_1` and `dlnk_dlnk_redis_1` having a status of `Up`:

```
          Name                         Command               State           Ports
-------------------------------------------------------------------------------------------
dlnk_dlnk_app_1     uvicorn web.api:app --host ...   Up      0.0.0.0:8000->8000/tcp
dlnk_dlnk_redis_1   docker-entrypoint.sh redis ...   Up      6379/tcp
```

You can also check the health of the API:

```bash
curl localhost:8000/health
```

This should return a `{"status": "healthy"}` response.

---

## 3. Accessing the Framework

Once deployed, you can interact with the framework in several ways:

- **Web Dashboard:** Open a browser and navigate to `http://<your_server_ip>:8000/dashboard`.
- **REST API:** The API is available at `http://<your_server_ip>:8000`. Refer to the `API_REFERENCE.md` for details.
- **CLI:** Use `docker-compose exec` to run CLI commands directly within the container:
  ```bash
  docker-compose exec app dlnk-dlnk <command>
  ```
  For example, to list all available agents:
  ```bash
  docker-compose exec app dlnk-dlnk agents
  ```

---

## 4. Managing the Deployment

- **Stopping the framework:** `docker-compose down`
- **Viewing logs:** `docker-compose logs -f app`
- **Updating the framework:** Pull the latest code, then rebuild the containers with `docker-compose up --build -d`.

