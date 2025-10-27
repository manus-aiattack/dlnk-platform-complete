-- Manus Attack Platform - Database Initialization Script
-- Created: 2025-10-24

-- Create database if not exists (handled by POSTGRES_DB env var)
-- This script runs after database creation

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    api_key VARCHAR(255) UNIQUE NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

-- Create attacks table
CREATE TABLE IF NOT EXISTS attacks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    target_url VARCHAR(1024) NOT NULL,
    attack_type VARCHAR(100) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    results JSONB,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create vulnerabilities table
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    attack_id UUID REFERENCES attacks(id) ON DELETE CASCADE,
    type VARCHAR(100) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    payload TEXT,
    evidence TEXT,
    remediation TEXT,
    cvss_score DECIMAL(3,1),
    cve_id VARCHAR(50),
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB
);

-- Create files table (for exfiltrated data)
CREATE TABLE IF NOT EXISTS exfiltrated_files (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    attack_id UUID REFERENCES attacks(id) ON DELETE CASCADE,
    file_path VARCHAR(1024) NOT NULL,
    file_type VARCHAR(100),
    file_size BIGINT,
    file_hash VARCHAR(64),
    source_path VARCHAR(1024),
    exfiltrated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB
);

-- Create logs table
CREATE TABLE IF NOT EXISTS attack_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    attack_id UUID REFERENCES attacks(id) ON DELETE CASCADE,
    level VARCHAR(50) NOT NULL,
    message TEXT NOT NULL,
    agent_name VARCHAR(255),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_attacks_user_id ON attacks(user_id);
CREATE INDEX IF NOT EXISTS idx_attacks_status ON attacks(status);
CREATE INDEX IF NOT EXISTS idx_attacks_created_at ON attacks(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_attack_id ON vulnerabilities(attack_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_exfiltrated_files_attack_id ON exfiltrated_files(attack_id);
CREATE INDEX IF NOT EXISTS idx_attack_logs_attack_id ON attack_logs(attack_id);
CREATE INDEX IF NOT EXISTS idx_attack_logs_timestamp ON attack_logs(timestamp DESC);

-- Create admin user (default password should be changed)
INSERT INTO users (username, email, api_key, role, is_active)
VALUES (
    'admin',
    'admin@manus.local',
    encode(gen_random_bytes(32), 'hex'),
    'admin',
    TRUE
)
ON CONFLICT (username) DO NOTHING;

-- Create updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_attacks_updated_at ON attacks;
CREATE TRIGGER update_attacks_updated_at
    BEFORE UPDATE ON attacks
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO postgres;

-- Log initialization
DO $$
BEGIN
    RAISE NOTICE 'Manus Attack Platform database initialized successfully';
END $$;


