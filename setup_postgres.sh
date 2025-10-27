#!/bin/bash
# Database Setup Script for dLNk Attack Platform

echo "🚀 Setting up PostgreSQL for dLNk Attack Platform..."

# Check if PostgreSQL is installed
if ! command -v psql &> /dev/null; then
    echo "❌ PostgreSQL not found. Please install PostgreSQL first."
    echo "For Ubuntu/WSL2: sudo apt update && sudo apt install postgresql postgresql-contrib"
    exit 1
fi

# Start PostgreSQL service
echo "🔄 Starting PostgreSQL service..."
sudo service postgresql start

# Create database and user
echo "🏗️ Creating database and user..."
sudo -u postgres psql << EOF
CREATE USER dlnk WITH PASSWORD 'dlnk';
CREATE DATABASE dlnk_attack_platform OWNER dlnk;
ALTER USER dlnk CREATEDB;
GRANT ALL PRIVILEGES ON DATABASE dlnk_attack_platform TO dlnk;
\q
EOF

if [ $? -eq 0 ]; then
    echo "✅ Database setup completed successfully!"
    echo "Database: dlnk_attack_platform"
    echo "User: dlnk"
    echo "Password: dlnk"
    echo ""
    echo "Next steps:"
    echo "1. Run: python setup_database.py"
    echo "2. Start API: python api/main.py"
else
    echo "❌ Database setup failed!"
    exit 1
fi