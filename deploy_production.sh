#!/usr/bin/env bash
# dLNk Attack Platform - Production Deployment Script
# สำหรับ Codespace และ Production Environment

set -e  # Exit on error

echo "========================================================"
echo "dLNk Attack Platform - Production Deployment"
echo "========================================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Step 1: Check System Requirements
print_step "Checking system requirements..."

if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is not installed"
    exit 1
fi
print_success "Python 3: $(python3 --version)"

if ! command -v node &> /dev/null; then
    print_warning "Node.js is not installed (needed for frontend)"
else
    print_success "Node.js: $(node --version)"
fi

if ! command -v docker &> /dev/null; then
    print_warning "Docker is not installed (optional)"
else
    print_success "Docker: $(docker --version)"
fi

echo ""

# Step 2: Install Python Dependencies
print_step "Installing Python dependencies..."

if [ -f "requirements.txt" ]; then
    pip3 install -r requirements.txt --quiet
    print_success "Python dependencies installed"
else
    print_warning "requirements.txt not found"
fi

if [ -f "requirements-full.txt" ]; then
    print_warning "Found requirements-full.txt - installing additional dependencies..."
    pip3 install -r requirements-full.txt --quiet
    print_success "Full dependencies installed"
fi

echo ""

# Step 3: Setup Environment Variables
print_step "Setting up environment variables..."

if [ ! -f ".env" ]; then
    if [ -f ".env.template" ]; then
        cp .env.template .env
        print_success "Created .env from template"
    elif [ -f ".env.example" ]; then
        cp .env.example .env
        print_success "Created .env from example"
    else
        print_warning "No .env template found - creating basic .env"
        cat > .env << 'EOF'
# Database Configuration
DATABASE_URL=sqlite:///workspace/dlnk.db
DB_HOST=localhost
DB_PORT=5432
DB_USER=dlnk_user
DB_PASSWORD=change_this_password
DB_NAME=dlnk_attack_platform

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379

# Ollama Configuration
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=mixtral:latest

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000

# Security
SIMULATION_MODE=False
SECRET_KEY=change_this_secret_key

# Workspace
WORKSPACE_DIR=./workspace
EOF
        print_success "Created basic .env file"
    fi
else
    print_success ".env file already exists"
fi

echo ""

# Step 4: Create Workspace Directory
print_step "Creating workspace directory..."

mkdir -p workspace logs data reports config
print_success "Workspace directories created"

echo ""

# Step 5: Initialize Database
print_step "Initializing database..."

if [ -f "startup.py" ]; then
    python3 startup.py
    print_success "Database initialized"
else
    print_warning "startup.py not found - skipping database initialization"
fi

echo ""

# Step 6: Install CLI Wrapper
print_step "Installing CLI wrapper..."

if [ -f "dlnk" ]; then
    chmod +x dlnk
    
    # Try to install to /usr/local/bin
    if [ -w "/usr/local/bin" ]; then
        ln -sf "$(pwd)/dlnk" /usr/local/bin/dlnk
        print_success "CLI installed to /usr/local/bin/dlnk"
    elif [ -w "$HOME/.local/bin" ]; then
        mkdir -p "$HOME/.local/bin"
        ln -sf "$(pwd)/dlnk" "$HOME/.local/bin/dlnk"
        print_success "CLI installed to ~/.local/bin/dlnk"
        print_warning "Make sure ~/.local/bin is in your PATH"
    else
        print_warning "Cannot install CLI - use ./dlnk instead"
    fi
else
    print_warning "dlnk wrapper not found"
fi

echo ""

# Step 7: Setup Frontend (if exists)
print_step "Setting up frontend..."

if [ -d "frontend" ]; then
    cd frontend
    
    if [ -f "package.json" ]; then
        if command -v npm &> /dev/null; then
            print_step "Installing frontend dependencies..."
            npm install --silent
            print_success "Frontend dependencies installed"
            
            print_step "Building frontend..."
            npm run build
            print_success "Frontend built successfully"
        else
            print_warning "npm not found - skipping frontend setup"
        fi
    fi
    
    cd ..
else
    print_warning "Frontend directory not found"
fi

echo ""

# Step 8: Test API Server
print_step "Testing API server..."

# Set PYTHONPATH
export PYTHONPATH="$(pwd):$PYTHONPATH"

# Try to import main module
if python3 -c "import main" 2>/dev/null; then
    print_success "API server can be imported"
else
    print_warning "API server import test failed"
fi

echo ""

# Step 9: Display Status
print_step "Deployment Summary"
echo ""
echo "========================================================"
echo "Installation Complete!"
echo "========================================================"
echo ""
echo "📁 Project Directory: $(pwd)"
echo "🐍 Python Version: $(python3 --version)"
echo "📦 Workspace: $(pwd)/workspace"
echo ""
echo "🚀 Quick Start Commands:"
echo ""
echo "  # Start API Server:"
echo "  python3 main.py server"
echo "  # or"
echo "  ./dlnk server"
echo ""
echo "  # Start Frontend (if built):"
echo "  cd frontend && npm run preview"
echo "  # or serve the dist folder"
echo ""
echo "  # Run an attack:"
echo "  ./dlnk attack https://example.com"
echo ""
echo "  # Get help:"
echo "  ./dlnk --help"
echo ""
echo "📚 Documentation:"
echo "  - README.md - Project overview"
echo "  - FRONTEND_DEPLOYMENT.md - Frontend deployment guide"
echo "  - POSTGRESQL_SETUP.md - PostgreSQL setup guide"
echo "  - TESTING_GUIDE.md - Testing guide"
echo "  - DOCKER_DEPLOYMENT.md - Docker deployment guide"
echo ""
echo "⚠️  Important:"
echo "  1. Review and update .env file with your settings"
echo "  2. Change default passwords and secret keys"
echo "  3. For production, use PostgreSQL instead of SQLite"
echo "  4. Setup SSL/TLS for API and frontend"
echo ""
echo "========================================================"
echo ""

# Step 10: Check for Admin Key
if [ -f "workspace/ADMIN_KEY.txt" ]; then
    print_success "Admin API Key found:"
    echo ""
    cat workspace/ADMIN_KEY.txt
    echo ""
else
    print_warning "Admin API Key not found - will be generated on first run"
fi

echo ""
print_success "Deployment script completed successfully!"
echo ""

