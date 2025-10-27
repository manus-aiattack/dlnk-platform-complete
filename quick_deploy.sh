#!/bin/bash
#
# Quick Deploy Script for dLNk Attack Platform
# This script automates the deployment process
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Main script
print_header "dLNk Attack Platform - Quick Deploy"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed!"
    print_info "Install Docker: curl -fsSL https://get.docker.com -o get-docker.sh && sudo sh get-docker.sh"
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    print_error "Docker Compose is not installed!"
    print_info "Install Docker Compose: sudo curl -L \"https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-\$(uname -s)-\$(uname -m)\" -o /usr/local/bin/docker-compose && sudo chmod +x /usr/local/bin/docker-compose"
    exit 1
fi

print_success "Docker and Docker Compose are installed"

# Check if .env file exists
if [ ! -f .env ]; then
    print_warning ".env file not found!"
    print_info "Creating .env from template..."
    
    if [ -f env.template ]; then
        cp env.template .env
        print_success ".env file created"
        print_warning "⚠️  IMPORTANT: Please edit .env file and set your passwords!"
        print_info "Run: nano .env"
        
        read -p "Do you want to edit .env now? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            ${EDITOR:-nano} .env
        else
            print_warning "Don't forget to edit .env before starting services!"
            exit 0
        fi
    else
        print_error "env.template not found!"
        exit 1
    fi
fi

print_success ".env file exists"

# Ask for deployment mode
echo ""
print_info "Select deployment mode:"
echo "1) Full Stack (PostgreSQL, Redis, Ollama, API, Frontend, Monitoring)"
echo "2) Development (SQLite, API only)"
echo "3) API + Database only"
read -p "Enter choice (1-3): " choice

case $choice in
    1)
        print_header "Deploying Full Production Stack"
        COMPOSE_FILE="docker-compose.complete.yml"
        ;;
    2)
        print_header "Deploying Development Mode"
        COMPOSE_FILE="docker-compose.yml"
        ;;
    3)
        print_header "Deploying API + Database"
        COMPOSE_FILE="docker-compose.production.yml"
        ;;
    *)
        print_error "Invalid choice!"
        exit 1
        ;;
esac

# Pull latest images
print_info "Pulling latest Docker images..."
docker-compose -f $COMPOSE_FILE pull

# Build images
print_info "Building Docker images..."
docker-compose -f $COMPOSE_FILE build

# Start services
print_info "Starting services..."
docker-compose -f $COMPOSE_FILE up -d

# Wait for services to be ready
print_info "Waiting for services to start..."
sleep 10

# Check service status
print_info "Checking service status..."
docker-compose -f $COMPOSE_FILE ps

# Health check
print_info "Running health check..."
sleep 5

if curl -f http://localhost:8000/health &> /dev/null; then
    print_success "API is healthy!"
else
    print_warning "API health check failed. Check logs with: docker-compose -f $COMPOSE_FILE logs -f api"
fi

# Display access information
echo ""
print_header "Deployment Complete! 🎉"
echo ""
print_info "Services are running:"
echo "  - API:        http://localhost:8000"
echo "  - API Docs:   http://localhost:8000/docs"
echo "  - Health:     http://localhost:8000/health"

if [ "$COMPOSE_FILE" == "docker-compose.complete.yml" ]; then
    echo "  - Frontend:   http://localhost"
    echo "  - Grafana:    http://localhost:3000 (admin/admin)"
    echo "  - Prometheus: http://localhost:9090"
fi

echo ""
print_info "Useful commands:"
echo "  - View logs:    docker-compose -f $COMPOSE_FILE logs -f"
echo "  - Stop:         docker-compose -f $COMPOSE_FILE down"
echo "  - Restart:      docker-compose -f $COMPOSE_FILE restart"
echo "  - Status:       docker-compose -f $COMPOSE_FILE ps"
echo ""

# Get admin key
if [ -f workspace/ADMIN_KEY.txt ]; then
    print_success "Admin API Key found:"
    cat workspace/ADMIN_KEY.txt
    echo ""
else
    print_warning "Admin API Key not found. It will be generated on first run."
    print_info "Check: workspace/ADMIN_KEY.txt after API starts"
fi

# Run tests
read -p "Do you want to run API tests? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_info "Running API tests..."
    sleep 5
    if [ -f test_api_fixed.py ]; then
        python3 test_api_fixed.py
    else
        print_warning "test_api_fixed.py not found"
    fi
fi

echo ""
print_success "Deployment completed successfully! 🚀"
echo ""

