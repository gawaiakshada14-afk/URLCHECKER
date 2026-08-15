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
    status TEXT NOT NULL,
    risk_level TEXT NOT NULL,
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
    webhook_url TEXT DEFAULT '',
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- 5. ROW LEVEL SECURITY (RLS) & POLICY ENFORCEMENT
-- ============================================================================

-- Enable RLS on all public tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE domain_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;

-- Helper Function: Check user role (SECURITY DEFINER with fixed search_path)
CREATE OR REPLACE FUNCTION get_auth_user_role()
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_role TEXT;
BEGIN
  v_role := NULLIF(current_setting('request.jwt.claims', true)::json->>'role', '');
  IF v_role IS NOT NULL AND v_role <> 'authenticated' AND v_role <> 'anon' THEN
    RETURN v_role;
  END IF;

  SELECT u.role INTO v_role
  FROM public.users u
  WHERE LOWER(u.email) = LOWER(NULLIF(current_setting('request.jwt.claims', true)::json->>'email', ''))
     OR u.id = NULLIF(current_setting('app.current_user_id', true), '')::integer
  LIMIT 1;

  RETURN COALESCE(v_role, 'Security Analyst');
END;
$$;

-- Helper Function: Check if session belongs to Admin
CREATE OR REPLACE FUNCTION is_admin()
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  RETURN LOWER(get_auth_user_role()) IN ('admin', 'administrator');
END;
$$;

-- Helper Function: Retrieve active authenticated user ID
CREATE OR REPLACE FUNCTION get_auth_user_id()
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_id INTEGER;
BEGIN
  v_id := NULLIF(current_setting('app.current_user_id', true), '')::integer;
  IF v_id IS NOT NULL THEN
    RETURN v_id;
  END IF;

  SELECT u.id INTO v_id
  FROM public.users u
  WHERE LOWER(u.email) = LOWER(NULLIF(current_setting('request.jwt.claims', true)::json->>'email', ''))
  LIMIT 1;

  RETURN v_id;
END;
$$;

-- Revoke anon access
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM anon;

-- RLS Policies
DROP POLICY IF EXISTS "users_read_own_or_admin" ON users;
CREATE POLICY "users_read_own_or_admin" ON users FOR SELECT TO authenticated, service_role USING (id = get_auth_user_id() OR is_admin());

DROP POLICY IF EXISTS "rules_read_own_or_admin" ON domain_rules;
CREATE POLICY "rules_read_own_or_admin" ON domain_rules FOR SELECT TO authenticated, service_role USING (user_id = get_auth_user_id() OR is_admin());

DROP POLICY IF EXISTS "scans_read_own_or_admin" ON scan_history;
CREATE POLICY "scans_read_own_or_admin" ON scan_history FOR SELECT TO authenticated, service_role USING (user_id = get_auth_user_id() OR is_admin());

DROP POLICY IF EXISTS "admin_only_api_keys" ON api_keys;
CREATE POLICY "admin_only_api_keys" ON api_keys FOR ALL TO authenticated, service_role USING (is_admin()) WITH CHECK (is_admin());

