-- dLNk Attack Platform - Database Schema
-- Authentication & Key Management System

-- ===== API Keys Table =====
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_value VARCHAR(64) UNIQUE NOT NULL,
    key_type VARCHAR(20) NOT NULL CHECK (key_type IN ('admin', 'user')),
    user_id VARCHAR(100),
    user_name VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    usage_count INTEGER DEFAULT 0,
    usage_limit INTEGER DEFAULT NULL,  -- NULL = unlimited (for admin)
    last_used_at TIMESTAMP,
    last_ip_address INET,
    metadata JSONB DEFAULT '{}'::jsonb,
    notes TEXT
);

CREATE INDEX idx_api_keys_key_value ON api_keys(key_value);
CREATE INDEX idx_api_keys_is_active ON api_keys(is_active);
CREATE INDEX idx_api_keys_key_type ON api_keys(key_type);

-- ===== Key Usage Logs =====
CREATE TABLE IF NOT EXISTS key_usage_logs (
    id SERIAL PRIMARY KEY,
    key_id UUID REFERENCES api_keys(id) ON DELETE CASCADE,
    endpoint VARCHAR(255),
    method VARCHAR(10),
    ip_address INET,
    user_agent TEXT,
    request_body JSONB,
    response_status INTEGER,
    response_time_ms INTEGER,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_key_usage_logs_key_id ON key_usage_logs(key_id);
CREATE INDEX idx_key_usage_logs_timestamp ON key_usage_logs(timestamp DESC);

-- ===== Attacks Table =====
CREATE TABLE IF NOT EXISTS attacks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_id UUID REFERENCES api_keys(id) ON DELETE SET NULL,
    target_url TEXT NOT NULL,
    attack_mode VARCHAR(50) DEFAULT 'auto',
    status VARCHAR(50) DEFAULT 'pending',
    progress INTEGER DEFAULT 0,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    error_message TEXT,
    target_info JSONB DEFAULT '{}'::jsonb,
    vulnerabilities_found INTEGER DEFAULT 0,
    exploits_successful INTEGER DEFAULT 0,
    data_exfiltrated_bytes BIGINT DEFAULT 0,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX idx_attacks_key_id ON attacks(key_id);
CREATE INDEX idx_attacks_status ON attacks(status);
CREATE INDEX idx_attacks_started_at ON attacks(started_at DESC);

-- ===== Vulnerabilities Table =====
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attack_id UUID REFERENCES attacks(id) ON DELETE CASCADE,
    vuln_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    url TEXT,
    parameter VARCHAR(255),
    payload TEXT,
    evidence TEXT,
    cvss_score DECIMAL(3,1),
    cve_id VARCHAR(50),
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    exploited BOOLEAN DEFAULT FALSE,
    exploited_at TIMESTAMP,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX idx_vulnerabilities_attack_id ON vulnerabilities(attack_id);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulnerabilities_vuln_type ON vulnerabilities(vuln_type);

-- ===== Exploits Table =====
CREATE TABLE IF NOT EXISTS exploits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attack_id UUID REFERENCES attacks(id) ON DELETE CASCADE,
    vulnerability_id UUID REFERENCES vulnerabilities(id) ON DELETE SET NULL,
    agent_name VARCHAR(100) NOT NULL,
    exploit_type VARCHAR(100) NOT NULL,
    success BOOLEAN DEFAULT FALSE,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    output TEXT,
    error_message TEXT,
    access_gained JSONB DEFAULT '{}'::jsonb,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX idx_exploits_attack_id ON exploits(attack_id);
CREATE INDEX idx_exploits_success ON exploits(success);

-- ===== Exfiltrated Data Table =====
CREATE TABLE IF NOT EXISTS exfiltrated_data (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attack_id UUID REFERENCES attacks(id) ON DELETE CASCADE,
    data_type VARCHAR(100) NOT NULL,
    file_path TEXT,
    file_size BIGINT,
    file_hash VARCHAR(64),
    preview TEXT,
    exfiltrated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX idx_exfiltrated_data_attack_id ON exfiltrated_data(attack_id);
CREATE INDEX idx_exfiltrated_data_data_type ON exfiltrated_data(data_type);

-- ===== System Settings Table =====
CREATE TABLE IF NOT EXISTS system_settings (
    key VARCHAR(100) PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default settings
INSERT INTO system_settings (key, value, description) VALUES
    ('line_contact_url', '', 'LINE contact URL for admin'),
    ('default_usage_limit', '100', 'Default usage limit for new keys'),
    ('rate_limit_per_minute', '60', 'API rate limit per minute'),
    ('attack_timeout_seconds', '3600', 'Default attack timeout in seconds'),
    ('data_retention_days', '30', 'Days to retain attack data')
ON CONFLICT (key) DO NOTHING;

-- ===== Admin Activity Logs =====
CREATE TABLE IF NOT EXISTS admin_logs (
    id SERIAL PRIMARY KEY,
    admin_key_id UUID REFERENCES api_keys(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    target_type VARCHAR(50),
    target_id VARCHAR(100),
    details JSONB DEFAULT '{}'::jsonb,
    ip_address INET,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_admin_logs_timestamp ON admin_logs(timestamp DESC);
CREATE INDEX idx_admin_logs_action ON admin_logs(action);

-- ===== Functions =====

-- Function to generate API key
CREATE OR REPLACE FUNCTION generate_api_key()
RETURNS VARCHAR(64) AS $$
DECLARE
    key_value VARCHAR(64);
BEGIN
    key_value := 'dlnk_' || encode(gen_random_bytes(32), 'hex');
    RETURN key_value;
END;
$$ LANGUAGE plpgsql;

-- Function to check key expiration
CREATE OR REPLACE FUNCTION is_key_expired(key_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
    expires_at TIMESTAMP;
BEGIN
    SELECT api_keys.expires_at INTO expires_at
    FROM api_keys
    WHERE api_keys.id = key_id;
    
    IF expires_at IS NULL THEN
        RETURN FALSE;
    END IF;
    
    RETURN expires_at < CURRENT_TIMESTAMP;
END;
$$ LANGUAGE plpgsql;

-- Function to check usage limit
CREATE OR REPLACE FUNCTION is_usage_limit_exceeded(key_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
    usage_count INTEGER;
    usage_limit INTEGER;
BEGIN
    SELECT api_keys.usage_count, api_keys.usage_limit INTO usage_count, usage_limit
    FROM api_keys
    WHERE api_keys.id = key_id;
    
    IF usage_limit IS NULL THEN
        RETURN FALSE;
    END IF;
    
    RETURN usage_count >= usage_limit;
END;
$$ LANGUAGE plpgsql;

-- ===== Views =====

-- View for active attacks
CREATE OR REPLACE VIEW active_attacks AS
SELECT 
    a.id,
    a.target_url,
    a.attack_mode,
    a.status,
    a.progress,
    a.started_at,
    ak.user_name,
    ak.key_value,
    COUNT(DISTINCT v.id) as vulnerabilities_count,
    COUNT(DISTINCT e.id) FILTER (WHERE e.success = TRUE) as successful_exploits
FROM attacks a
LEFT JOIN api_keys ak ON a.key_id = ak.id
LEFT JOIN vulnerabilities v ON a.id = v.attack_id
LEFT JOIN exploits e ON a.id = e.attack_id
WHERE a.status IN ('pending', 'running', 'analyzing', 'reconnaissance', 'scanning', 'exploiting', 'post_exploitation', 'exfiltrating')
GROUP BY a.id, ak.user_name, ak.key_value;

-- View for attack statistics
CREATE OR REPLACE VIEW attack_statistics AS
SELECT
    DATE(started_at) as date,
    COUNT(*) as total_attacks,
    COUNT(*) FILTER (WHERE status = 'completed') as completed_attacks,
    COUNT(*) FILTER (WHERE status = 'failed') as failed_attacks,
    AVG(vulnerabilities_found) as avg_vulnerabilities,
    AVG(exploits_successful) as avg_exploits,
    SUM(data_exfiltrated_bytes) as total_data_exfiltrated
FROM attacks
GROUP BY DATE(started_at)
ORDER BY date DESC;

-- View for key statistics
CREATE OR REPLACE VIEW key_statistics AS
SELECT
    ak.id,
    ak.key_value,
    ak.key_type,
    ak.user_name,
    ak.usage_count,
    ak.usage_limit,
    ak.last_used_at,
    COUNT(DISTINCT a.id) as total_attacks,
    COUNT(DISTINCT a.id) FILTER (WHERE a.status = 'completed') as completed_attacks,
    SUM(a.vulnerabilities_found) as total_vulnerabilities_found,
    SUM(a.data_exfiltrated_bytes) as total_data_exfiltrated
FROM api_keys ak
LEFT JOIN attacks a ON ak.id = a.key_id
GROUP BY ak.id;

-- ===== Triggers =====

-- Trigger to update last_used_at
CREATE OR REPLACE FUNCTION update_key_last_used()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE api_keys
    SET last_used_at = CURRENT_TIMESTAMP,
        last_ip_address = NEW.ip_address
    WHERE id = NEW.key_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_key_last_used
AFTER INSERT ON key_usage_logs
FOR EACH ROW
EXECUTE FUNCTION update_key_last_used();

-- Trigger to increment usage count
CREATE OR REPLACE FUNCTION increment_usage_count()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.endpoint LIKE '/api/attack%' AND NEW.method = 'POST' THEN
        UPDATE api_keys
        SET usage_count = usage_count + 1
        WHERE id = NEW.key_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_increment_usage_count
AFTER INSERT ON key_usage_logs
FOR EACH ROW
EXECUTE FUNCTION increment_usage_count();

-- ===== Comments =====
COMMENT ON TABLE api_keys IS 'API keys for authentication';
COMMENT ON TABLE key_usage_logs IS 'Logs of API key usage';
COMMENT ON TABLE attacks IS 'Attack sessions';
COMMENT ON TABLE vulnerabilities IS 'Discovered vulnerabilities';
COMMENT ON TABLE exploits IS 'Exploitation attempts';
COMMENT ON TABLE exfiltrated_data IS 'Data exfiltrated from targets';
COMMENT ON TABLE system_settings IS 'System configuration settings';
COMMENT ON TABLE admin_logs IS 'Admin activity logs';

