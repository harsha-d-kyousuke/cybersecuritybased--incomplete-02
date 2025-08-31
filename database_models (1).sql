-- backend/database/init.sql
-- Database initialization script for PostgreSQL

-- Create database (run as superuser)
-- CREATE DATABASE cyberattack_db;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'user' CHECK (role IN ('user', 'admin', 'analyst')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT true,
    last_login TIMESTAMP WITH TIME ZONE
);

-- Attack results table
CREATE TABLE IF NOT EXISTS attack_results (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    attack_type VARCHAR(50) NOT NULL,
    target_url TEXT NOT NULL,
    vulnerabilities_found JSONB DEFAULT '[]',
    severity_score DECIMAL(3,2) DEFAULT 0.00 CHECK (severity_score >= 0 AND severity_score <= 10),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    recommendations JSONB DEFAULT '[]',
    status VARCHAR(20) DEFAULT 'completed' CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    execution_time_ms INTEGER DEFAULT 0,
    payloads_tested INTEGER DEFAULT 0,
    success_rate DECIMAL(5,2) DEFAULT 0.00
);

-- Reports table
CREATE TABLE IF NOT EXISTS reports (
    id SERIAL PRIMARY KEY,
    attack_result_id INTEGER REFERENCES attack_results(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    report_type VARCHAR(20) DEFAULT 'pdf' CHECK (report_type IN ('pdf', 'json', 'html')),
    file_path TEXT,
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    file_size_bytes INTEGER DEFAULT 0,
    download_count INTEGER DEFAULT 0
);

-- Vulnerable applications table (for testing targets)
CREATE TABLE IF NOT EXISTS vulnerable_apps (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    url TEXT NOT NULL,
    vulnerability_types JSONB DEFAULT '[]',
    difficulty_level VARCHAR(20) DEFAULT 'beginner' CHECK (difficulty_level IN ('beginner', 'intermediate', 'advanced')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT true
);

-- User sessions table (for JWT token management)
CREATE TABLE IF NOT EXISTS user_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    ip_address INET,
    user_agent TEXT,
    is_revoked BOOLEAN DEFAULT false
);

-- Audit log table
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50),
    resource_id INTEGER,
    details JSONB DEFAULT '{}',
    ip_address INET,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Attack templates table (predefined attack scenarios)
CREATE TABLE IF NOT EXISTS attack_templates (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    attack_type VARCHAR(50) NOT NULL,
    description TEXT,
    payload_template TEXT NOT NULL,
    parameters JSONB DEFAULT '{}',
    difficulty_level VARCHAR(20) DEFAULT 'beginner',
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    usage_count INTEGER DEFAULT 0
);

-- Indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_attack_results_user_id ON attack_results(user_id);
CREATE INDEX IF NOT EXISTS idx_attack_results_timestamp ON attack_results(timestamp);
CREATE INDEX IF NOT EXISTS idx_attack_results_attack_type ON attack_results(attack_type);
CREATE INDEX IF NOT EXISTS idx_reports_attack_result_id ON reports(attack_result_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at ON user_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);

-- Triggers for updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert sample vulnerable applications
INSERT INTO vulnerable_apps (name, description, url, vulnerability_types, difficulty_level) VALUES
('DVWA - Damn Vulnerable Web Application', 'Deliberately vulnerable PHP/MySQL web application', 'http://localhost:8080/dvwa', '["sql_injection", "xss", "csrf", "brute_force"]', 'beginner'),
('WebGoat', 'Deliberately insecure web application for security education', 'http://localhost:8080/webgoat', '["sql_injection", "xss", "directory_traversal", "csrf"]', 'intermediate'),
('Mutillidae II', 'Deliberately vulnerable web application providing a target for web-application security enthusiasts', 'http://localhost:8080/mutillidae', '["sql_injection", "xss", "csrf", "directory_traversal", "file_upload"]', 'advanced'),
('Local Test App', 'Built-in vulnerable application for testing', 'http://localhost:5000/vulnerable', '["sql_injection", "xss", "csrf"]', 'beginner')
ON CONFLICT DO NOTHING;

-- Insert default admin user (password: admin123)
INSERT INTO users (username, email, password_hash, role) VALUES
('admin', 'admin@cyberattack-simulator.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj6hsGs2VhF6', 'admin')
ON CONFLICT DO NOTHING;

-- Insert sample attack templates
INSERT INTO attack_templates (name, attack_type, description, payload_template, parameters, difficulty_level) VALUES
('Basic SQL Injection', 'sql_injection', 'Simple SQL injection test with single quote', ''' OR ''1''=''1', '{"target_param": "id"}', 'beginner'),
('Union-based SQL Injection', 'sql_injection', 'Advanced SQL injection using UNION statements', ''' UNION SELECT NULL,NULL,version()--', '{"target_param": "search"}', 'intermediate'),
('Reflected XSS', 'xss', 'Basic reflected cross-site scripting attack', '<script>alert(''XSS'')</script>', '{"target_param": "search"}', 'beginner'),
('Stored XSS', 'xss', 'Persistent cross-site scripting attack', '<img src="x" onerror="alert(''Stored XSS'')"/>', '{"target_param": "comment"}', 'intermediate'),
('CSRF Attack', 'csrf', 'Cross-site request forgery attack', '<form action="{{target_url}}" method="POST"><input type="hidden" name="action" value="delete"/></form>', '{"method": "POST"}', 'intermediate'),
('Directory Traversal', 'directory_traversal', 'Path traversal attack to access system files', '../../../etc/passwd', '{"target_param": "file"}', 'beginner'),
('Brute Force Login', 'brute_force', 'Password brute force attack', 'admin:{{password}}', '{"target_param": "password", "wordlist": "common_passwords"}', 'beginner')
ON CONFLICT DO NOTHING;