#!/bin/bash

# Start Redis server (if not using Docker Compose)
# sudo service redis-server start

# Run the API server
python cli/main.py server

