-- Apex Predator AI: Database Schema
-- Version 1.1

-- ============================================================================
-- Drop existing tables to ensure a clean slate on re-initialization
-- ============================================================================
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
DROP TRIGGER IF EXISTS update_workflow_states_updated_at ON workflow_states;
DROP FUNCTION IF EXISTS update_updated_at_column();
DROP TABLE IF EXISTS workflow_states CASCADE;
DROP TABLE IF EXISTS attack_logs CASCADE;
DROP TABLE IF EXISTS api_keys CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- ============================================================================
-- Users Table
-- Stores user accounts for the system.
-- ============================================================================
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- API Keys Table
-- Stores API keys for programmatic access.
-- ============================================================================
CREATE TABLE IF NOT EXISTS api_keys (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_hash VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- Attack Logs Table
-- Records detailed events and phases of each attack.
-- ============================================================================
CREATE TABLE IF NOT EXISTS attack_logs (
    id BIGSERIAL PRIMARY KEY,
    attack_id UUID NOT NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    target_id VARCHAR(255),
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    phase VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL, -- e.g., STARTED, COMPLETED, FAILED
    details JSONB
);

-- ============================================================================
-- Workflow States Table
-- Persists the state of long-running attack workflows.
-- ============================================================================
CREATE TABLE IF NOT EXISTS workflow_states (
    id SERIAL PRIMARY KEY,
    attack_id UUID UNIQUE NOT NULL,
    state_data JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- Indexes
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_attack_logs_attack_id ON attack_logs(attack_id);
CREATE INDEX IF NOT EXISTS idx_attack_logs_user_id ON attack_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_attack_logs_timestamp ON attack_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_workflow_states_attack_id ON workflow_states(attack_id);

-- ============================================================================
-- Triggers for updated_at timestamps
-- ============================================================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_workflow_states_updated_at
BEFORE UPDATE ON workflow_states
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- End of Schema
-- ============================================================================
