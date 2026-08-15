-- ============================================================================
-- ShieldURL Supabase PostgreSQL Hardening & RLS Security Migration
-- Migration Script: supabase_rls_hardening.sql
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. REVOKE PUBLIC & ANON PRIVILEGES
-- ----------------------------------------------------------------------------

-- Revoke default public execute privileges on all functions in public schema
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM anon;

-- ----------------------------------------------------------------------------
-- 2. ENABLE ROW LEVEL SECURITY (RLS) ON ALL TABLES
-- ----------------------------------------------------------------------------

ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.domain_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.api_keys ENABLE ROW LEVEL SECURITY;

-- Force RLS even for table owners to ensure no policy bypass
ALTER TABLE public.users FORCE ROW LEVEL SECURITY;
ALTER TABLE public.domain_rules FORCE ROW LEVEL SECURITY;
ALTER TABLE public.scan_history FORCE ROW LEVEL SECURITY;
ALTER TABLE public.api_keys FORCE ROW LEVEL SECURITY;

-- ----------------------------------------------------------------------------
-- 3. SECURE DATABASE HELPER FUNCTIONS (SECURITY DEFINER with fixed search_path)
-- ----------------------------------------------------------------------------

-- Function: Retrieve current authenticated user role from JWT claims or users table
CREATE OR REPLACE FUNCTION public.get_auth_user_role()
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_role TEXT;
BEGIN
  -- 1. Check JWT claim 'role' if populated by Supabase Auth
  v_role := NULLIF(current_setting('request.jwt.claims', true)::json->>'role', '');
  IF v_role IS NOT NULL AND v_role <> 'authenticated' AND v_role <> 'anon' THEN
    RETURN v_role;
  END IF;

  -- 2. Check current session user in public.users table via JWT sub/email or active session
  SELECT u.role INTO v_role
  FROM public.users u
  WHERE LOWER(u.email) = LOWER(NULLIF(current_setting('request.jwt.claims', true)::json->>'email', ''))
     OR u.id = NULLIF(current_setting('app.current_user_id', true), '')::integer
  LIMIT 1;

  RETURN COALESCE(v_role, 'Security Analyst');
END;
$$;

-- Function: Check if current user is an Admin
CREATE OR REPLACE FUNCTION public.is_admin()
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_role TEXT;
BEGIN
  v_role := public.get_auth_user_role();
  RETURN LOWER(v_role) IN ('admin', 'administrator');
END;
$$;

-- Function: Retrieve active authenticated user ID
CREATE OR REPLACE FUNCTION public.get_auth_user_id()
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

-- Grant EXECUTE strictly to authenticated users and service_role
GRANT EXECUTE ON FUNCTION public.get_auth_user_role() TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.is_admin() TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.get_auth_user_id() TO authenticated, service_role;

-- ----------------------------------------------------------------------------
-- 4. RLS POLICIES FOR 'users' TABLE
-- ----------------------------------------------------------------------------

DROP POLICY IF EXISTS "users_read_own_or_admin" ON public.users;
DROP POLICY IF EXISTS "users_update_own_profile" ON public.users;
DROP POLICY IF EXISTS "admin_manage_users" ON public.users;

-- Authenticated Analysts can view their own profile; Admins can view all users
CREATE POLICY "users_read_own_or_admin" ON public.users
  FOR SELECT
  TO authenticated, service_role
  USING (
    id = public.get_auth_user_id() OR public.is_admin()
  );

-- Users can update their own profile details (excluding role changes)
CREATE POLICY "users_update_own_profile" ON public.users
  FOR UPDATE
  TO authenticated, service_role
  USING (id = public.get_auth_user_id() OR public.is_admin())
  WITH CHECK (
    (id = public.get_auth_user_id() AND role = (SELECT role FROM public.users WHERE id = public.get_auth_user_id()))
    OR public.is_admin()
  );

-- Admins can insert or delete user records
CREATE POLICY "admin_manage_users" ON public.users
  FOR ALL
  TO authenticated, service_role
  USING (public.is_admin())
  WITH CHECK (public.is_admin());

-- ----------------------------------------------------------------------------
-- 5. RLS POLICIES FOR 'domain_rules' TABLE
-- ----------------------------------------------------------------------------

DROP POLICY IF EXISTS "rules_read_own_or_admin" ON public.domain_rules;
DROP POLICY IF EXISTS "rules_insert_own_or_admin" ON public.domain_rules;
DROP POLICY IF EXISTS "rules_delete_own_or_admin" ON public.domain_rules;

CREATE POLICY "rules_read_own_or_admin" ON public.domain_rules
  FOR SELECT
  TO authenticated, service_role
  USING (
    user_id = public.get_auth_user_id() OR public.is_admin()
  );

CREATE POLICY "rules_insert_own_or_admin" ON public.domain_rules
  FOR INSERT
  TO authenticated, service_role
  WITH CHECK (
    (user_id = public.get_auth_user_id()) OR public.is_admin()
  );

CREATE POLICY "rules_delete_own_or_admin" ON public.domain_rules
  FOR DELETE
  TO authenticated, service_role
  USING (
    user_id = public.get_auth_user_id() OR public.is_admin()
  );

-- ----------------------------------------------------------------------------
-- 6. RLS POLICIES FOR 'scan_history' TABLE
-- ----------------------------------------------------------------------------

DROP POLICY IF EXISTS "scans_read_own_or_admin" ON public.scan_history;
DROP POLICY IF EXISTS "scans_insert_own_or_admin" ON public.scan_history;
DROP POLICY IF EXISTS "scans_delete_own_or_admin" ON public.scan_history;

CREATE POLICY "scans_read_own_or_admin" ON public.scan_history
  FOR SELECT
  TO authenticated, service_role
  USING (
    user_id = public.get_auth_user_id() OR public.is_admin()
  );

CREATE POLICY "scans_insert_own_or_admin" ON public.scan_history
  FOR INSERT
  TO authenticated, service_role
  WITH CHECK (
    (user_id = public.get_auth_user_id()) OR public.is_admin()
  );

CREATE POLICY "scans_delete_own_or_admin" ON public.scan_history
  FOR DELETE
  TO authenticated, service_role
  USING (
    user_id = public.get_auth_user_id() OR public.is_admin()
  );

-- ----------------------------------------------------------------------------
-- 7. RLS POLICIES FOR 'api_keys' TABLE (Admin Only Access)
-- ----------------------------------------------------------------------------

DROP POLICY IF EXISTS "admin_only_api_keys" ON public.api_keys;

CREATE POLICY "admin_only_api_keys" ON public.api_keys
  FOR ALL
  TO authenticated, service_role
  USING (public.is_admin())
  WITH CHECK (public.is_admin());

-- ----------------------------------------------------------------------------
-- 8. GRANT SPECIFIC TABLE PERMISSIONS
-- ----------------------------------------------------------------------------

-- Deny all table privileges from anon role
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM anon;

-- Grant required table privileges to authenticated users & service_role
GRANT SELECT, INSERT, UPDATE, DELETE ON public.users TO authenticated, service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.domain_rules TO authenticated, service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.scan_history TO authenticated, service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.api_keys TO authenticated, service_role;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO authenticated, service_role;
