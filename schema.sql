-- ============================================================================
-- ShieldURL Supabase PostgreSQL Database Schema
-- Database: postgres (Supabase Cloud)
-- ============================================================================

-- Drop tables if re-initializing cleanly (in order of foreign key dependencies)
DROP TABLE IF EXISTS api_keys CASCADE;
DROP TABLE IF EXISTS scan_history CASCADE;
DROP TABLE IF EXISTS domain_rules CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- 1. Users Table (Security Analysts & System Users)
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(100) DEFAULT 'Security Analyst',
    initials VARCHAR(10) DEFAULT 'SA',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Index for fast user lookup by email
CREATE INDEX idx_users_email ON users(email);

-- 2. Domain Override Rules (Whitelist & Blacklist)
CREATE TABLE domain_rules (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    domain VARCHAR(255) NOT NULL UNIQUE,
    type VARCHAR(50) NOT NULL CHECK (type IN ('whitelist', 'blacklist')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Index for domain lookup during security scans
CREATE INDEX idx_domain_rules_domain ON domain_rules(LOWER(domain));

-- 3. Scan History & Threat Intelligence Audit Logs
CREATE TABLE scan_history (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    url TEXT NOT NULL,
    domain VARCHAR(255) NOT NULL,
    score INTEGER NOT NULL CHECK (score >= 0 AND score <= 100),
    status VARCHAR(50) NOT NULL,
    risk_level VARCHAR(50) NOT NULL,
    checks_json JSONB DEFAULT '[]'::jsonb,
    metadata_json JSONB DEFAULT '{}'::jsonb,
    scan_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for analytical queries and KPI aggregation
CREATE INDEX idx_scan_history_domain ON scan_history(domain);
CREATE INDEX idx_scan_history_score ON scan_history(score);
CREATE INDEX idx_scan_history_date ON scan_history(scan_date DESC);

-- 4. Threat Intelligence API Keys Configuration
CREATE TABLE api_keys (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    vt_key TEXT DEFAULT '',
    gsb_key TEXT DEFAULT '',
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
