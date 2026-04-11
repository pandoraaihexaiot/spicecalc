-- ═══════════════════════════════════════════════════════════════════
-- SpiceCalc Database Schema for Supabase (COMPLETE)
-- Generated from live production database — April 2026
-- ═══════════════════════════════════════════════════════════════════
--
-- USAGE:
--   For FRESH installs: Run this entire file in Supabase SQL Editor
--   For UPGRADES: Do NOT run this — use individual migrations instead
--
-- ARCHITECTURE:
--   - PIN-based auth with bcrypt hashing (no Supabase Auth)
--   - Server-managed sessions via auth_sessions table
--   - All sensitive operations via SECURITY DEFINER RPCs
--   - RLS on all tables; anon role gets no direct access without session
--   - 5 user slots: Admin (1), Manager 1 (2), Manager 2 (3), Exec 1 (4), Exec 2 (5)
--   - Roles: admin, manager, user (execs)
--
-- ═══════════════════════════════════════════════════════════════════

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ═══ TABLES ═══

CREATE TABLE IF NOT EXISTS config (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  slot INT UNIQUE NOT NULL CHECK (slot BETWEEN 1 AND 5),
  name TEXT NOT NULL DEFAULT 'User',
  pin_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user', 'manager')),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ingredients (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  item_code TEXT UNIQUE NOT NULL,
  item_name TEXT DEFAULT '',
  description TEXT DEFAULT '',
  packaging_size TEXT DEFAULT '',
  price_per_kg DECIMAL(12,4) NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS formulas (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  product_code TEXT NOT NULL,
  product_name TEXT NOT NULL,
  batch_size DECIMAL(12,4) NOT NULL DEFAULT 100,
  version INT NOT NULL DEFAULT 1,
  version_note TEXT DEFAULT '',
  active BOOLEAN DEFAULT TRUE,
  input_mode TEXT DEFAULT 'kg' CHECK (input_mode IN ('kg', 'pct')),
  notes TEXT DEFAULT '',
  sensory JSONB DEFAULT '{}',
  approval_status TEXT DEFAULT 'draft' CHECK (approval_status IN ('draft', 'pending', 'approved', 'rejected')),
  created_by INT NOT NULL REFERENCES users(slot),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(product_code, version, created_by)
);

CREATE TABLE IF NOT EXISTS formula_ingredients (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  formula_id UUID NOT NULL REFERENCES formulas(id) ON DELETE CASCADE,
  item_code TEXT NOT NULL,
  qty DECIMAL(12,4) DEFAULT 0,
  pct DECIMAL(12,4) DEFAULT 0,
  sort_order INT DEFAULT 0,
  step TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS costings (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  formula_id UUID NOT NULL REFERENCES formulas(id) ON DELETE CASCADE,
  product_code TEXT DEFAULT '',
  product_name TEXT DEFAULT '',
  version INT DEFAULT 1,
  raw_per_kg DECIMAL(12,4) DEFAULT 0,
  wastage DECIMAL(12,4) DEFAULT 0,
  packaging DECIMAL(12,4) DEFAULT 0,
  outer_pkg DECIMAL(12,4) DEFAULT 0,
  labor DECIMAL(12,4) DEFAULT 0,
  shipping DECIMAL(12,4) DEFAULT 0,
  document DECIMAL(12,4) DEFAULT 0,
  lab DECIMAL(12,4) DEFAULT 0,
  other DECIMAL(12,4) DEFAULT 0,
  margin DECIMAL(12,4) DEFAULT 30,
  grammage DECIMAL(12,4) NOT NULL DEFAULT 1,
  label TEXT NOT NULL DEFAULT '',
  created_by INT NOT NULL REFERENCES users(slot),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS auth_sessions (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_slot INT NOT NULL,
  token TEXT UNIQUE NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '30 minutes')
);

CREATE TABLE IF NOT EXISTS login_attempts (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  ip_hint TEXT NOT NULL DEFAULT 'unknown',
  attempted_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS shared_formulas (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  formula_id UUID NOT NULL REFERENCES formulas(id) ON DELETE CASCADE,
  shared_by INT NOT NULL,
  shared_with INT NOT NULL,
  permission TEXT NOT NULL DEFAULT 'view' CHECK (permission IN ('view', 'edit')),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(formula_id, shared_with)
);

CREATE TABLE IF NOT EXISTS audit_log (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_slot INT NOT NULL DEFAULT 0,
  user_name TEXT NOT NULL DEFAULT 'System',
  action TEXT NOT NULL,
  entity TEXT NOT NULL,
  entity_id TEXT,
  detail TEXT DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS price_history (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  item_code TEXT NOT NULL,
  old_price DECIMAL(12,4) NOT NULL DEFAULT 0,
  new_price DECIMAL(12,4) NOT NULL DEFAULT 0,
  changed_by INT NOT NULL DEFAULT 0,
  changed_at TIMESTAMPTZ DEFAULT NOW()
);

-- ═══ HELPER FUNCTIONS ═══

CREATE OR REPLACE FUNCTION get_session_user_slot() RETURNS INTEGER LANGUAGE plpgsql STABLE SECURITY DEFINER AS $$
DECLARE v_token TEXT; v_slot INTEGER;
BEGIN
  BEGIN v_token := current_setting('request.headers', true)::json->>'x-session-token'; EXCEPTION WHEN OTHERS THEN RETURN NULL; END;
  IF v_token IS NULL OR v_token = '' THEN RETURN NULL; END IF;
  SELECT user_slot INTO v_slot FROM auth_sessions WHERE token = v_token AND expires_at > NOW();
  RETURN v_slot;
END; $$;

CREATE OR REPLACE FUNCTION get_session_role() RETURNS TEXT LANGUAGE plpgsql STABLE SECURITY DEFINER AS $$
DECLARE v_token TEXT; v_role TEXT;
BEGIN
  BEGIN v_token := current_setting('request.headers', true)::json->>'x-session-token'; EXCEPTION WHEN OTHERS THEN RETURN NULL; END;
  IF v_token IS NULL OR v_token = '' THEN RETURN NULL; END IF;
  SELECT role INTO v_role FROM auth_sessions WHERE token = v_token AND expires_at > NOW();
  RETURN v_role;
END; $$;

CREATE OR REPLACE FUNCTION has_valid_session() RETURNS BOOLEAN LANGUAGE plpgsql STABLE SECURITY DEFINER AS $$
DECLARE v_token TEXT; cnt INT;
BEGIN
  BEGIN v_token := current_setting('request.headers', true)::json->>'x-session-token'; EXCEPTION WHEN OTHERS THEN v_token := NULL; END;
  IF v_token IS NULL OR v_token = '' THEN RETURN FALSE; END IF;
  SELECT count(*) INTO cnt FROM auth_sessions WHERE token = v_token AND expires_at > NOW();
  RETURN cnt > 0;
END; $$;

CREATE OR REPLACE FUNCTION is_admin_or_manager() RETURNS BOOLEAN LANGUAGE plpgsql STABLE SECURITY DEFINER AS $$
BEGIN RETURN get_session_role() IN ('admin', 'manager'); END; $$;

-- ═══ AUTH RPCs ═══

CREATE OR REPLACE FUNCTION get_user_names() RETURNS JSON LANGUAGE plpgsql STABLE SECURITY DEFINER AS $$
DECLARE result JSON;
BEGIN
  SELECT json_agg(json_build_object('slot', slot, 'name', name, 'role', role) ORDER BY slot) INTO result FROM users;
  RETURN COALESCE(result, '[]'::json);
END; $$;

CREATE OR REPLACE FUNCTION verify_section1_pin(pin_input TEXT) RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE stored_hash TEXT; session_token TEXT; recent_attempts INT;
BEGIN
  SELECT count(*) INTO recent_attempts FROM login_attempts WHERE attempted_at > NOW() - INTERVAL '1 minute';
  IF recent_attempts >= 5 THEN RETURN json_build_object('ok', false, 'error', 'Too many attempts. Wait 1 minute.'); END IF;
  INSERT INTO login_attempts (ip_hint) VALUES ('s1_attempt');
  SELECT value INTO stored_hash FROM config WHERE key = 'section1_pin';
  IF stored_hash IS NULL THEN RETURN json_build_object('ok', false, 'error', 'Config not found'); END IF;
  IF stored_hash = crypt(pin_input, stored_hash) THEN
    session_token := encode(gen_random_bytes(32), 'hex');
    INSERT INTO auth_sessions (user_slot, token, role, expires_at) VALUES (0, session_token, 'section1', NOW() + INTERVAL '30 minutes');
    DELETE FROM login_attempts WHERE attempted_at < NOW() - INTERVAL '5 minutes';
    RETURN json_build_object('ok', true, 'token', session_token);
  ELSE RETURN json_build_object('ok', false, 'error', 'Incorrect PIN'); END IF;
END; $$;

CREATE OR REPLACE FUNCTION verify_user_pin(pin_input TEXT) RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE u RECORD; session_token TEXT; recent_attempts INT;
BEGIN
  SELECT count(*) INTO recent_attempts FROM login_attempts WHERE attempted_at > NOW() - INTERVAL '1 minute';
  IF recent_attempts >= 5 THEN RETURN json_build_object('ok', false, 'error', 'Too many attempts. Wait 1 minute.'); END IF;
  INSERT INTO login_attempts (ip_hint) VALUES ('user_attempt');
  SELECT slot, name, role, pin_hash INTO u FROM users WHERE pin_hash = crypt(pin_input, pin_hash);
  IF u.slot IS NULL THEN RETURN json_build_object('ok', false, 'error', 'Incorrect PIN'); END IF;
  session_token := encode(gen_random_bytes(32), 'hex');
  INSERT INTO auth_sessions (user_slot, token, role, expires_at) VALUES (u.slot, session_token, u.role, NOW() + INTERVAL '30 minutes');
  DELETE FROM login_attempts WHERE attempted_at < NOW() - INTERVAL '5 minutes';
  RETURN json_build_object('ok', true, 'token', session_token, 'slot', u.slot, 'name', u.name, 'role', u.role);
END; $$;

CREATE OR REPLACE FUNCTION refresh_session(session_token TEXT) RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN UPDATE auth_sessions SET expires_at = NOW() + INTERVAL '30 minutes' WHERE token = session_token AND expires_at > NOW(); RETURN FOUND; END; $$;

CREATE OR REPLACE FUNCTION destroy_session(session_token TEXT) RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN DELETE FROM auth_sessions WHERE token = session_token; RETURN FOUND; END; $$;

CREATE OR REPLACE FUNCTION cleanup_sessions() RETURNS INT LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE cnt INT;
BEGIN DELETE FROM auth_sessions WHERE expires_at < NOW(); GET DIAGNOSTICS cnt = ROW_COUNT; RETURN cnt; END; $$;

-- ═══ ADMIN RPCs ═══

CREATE OR REPLACE FUNCTION admin_get_users(session_token TEXT DEFAULT NULL) RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE v_caller_slot INTEGER; v_caller_role TEXT; result JSON;
BEGIN
  v_caller_slot := get_session_user_slot();
  IF v_caller_slot IS NULL AND session_token IS NOT NULL THEN SELECT user_slot, role INTO v_caller_slot, v_caller_role FROM auth_sessions WHERE token = session_token AND expires_at > NOW(); END IF;
  IF v_caller_slot IS NOT NULL AND v_caller_role IS NULL THEN SELECT role INTO v_caller_role FROM auth_sessions WHERE user_slot = v_caller_slot AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1; END IF;
  IF v_caller_role IS NULL OR v_caller_role != 'admin' THEN RETURN json_build_object('ok', false, 'error', 'Admin access required'); END IF;
  SELECT json_agg(json_build_object('slot', slot, 'name', name, 'role', role) ORDER BY slot) INTO result FROM users;
  RETURN json_build_object('ok', true, 'users', COALESCE(result, '[]'::json));
END; $$;

CREATE OR REPLACE FUNCTION admin_update_user(session_token TEXT DEFAULT NULL, target_slot INT DEFAULT NULL, new_name TEXT DEFAULT NULL, new_pin TEXT DEFAULT NULL) RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE v_caller_slot INTEGER; v_caller_role TEXT; dup_check INT;
BEGIN
  v_caller_slot := get_session_user_slot();
  IF v_caller_slot IS NULL AND session_token IS NOT NULL THEN SELECT user_slot, role INTO v_caller_slot, v_caller_role FROM auth_sessions WHERE token = session_token AND expires_at > NOW(); END IF;
  IF v_caller_slot IS NOT NULL AND v_caller_role IS NULL THEN SELECT role INTO v_caller_role FROM auth_sessions WHERE user_slot = v_caller_slot AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1; END IF;
  IF v_caller_role IS NULL OR v_caller_role != 'admin' THEN RETURN json_build_object('ok', false, 'error', 'Admin access required'); END IF;
  IF target_slot IS NULL OR new_name IS NULL THEN RETURN json_build_object('ok', false, 'error', 'Missing required parameters'); END IF;
  IF new_pin IS NOT NULL THEN
    IF length(new_pin) < 4 OR length(new_pin) > 6 THEN RETURN json_build_object('ok', false, 'error', 'PIN must be 4-6 digits'); END IF;
    SELECT slot INTO dup_check FROM users WHERE pin_hash = crypt(new_pin, pin_hash) AND slot != target_slot;
    IF dup_check IS NOT NULL THEN RETURN json_build_object('ok', false, 'error', 'PIN already in use'); END IF;
    UPDATE users SET name = new_name, pin_hash = crypt(new_pin, gen_salt('bf')), updated_at = NOW() WHERE slot = target_slot;
  ELSE UPDATE users SET name = new_name, updated_at = NOW() WHERE slot = target_slot; END IF;
  RETURN json_build_object('ok', true);
END; $$;

CREATE OR REPLACE FUNCTION admin_update_section1_pin(session_token TEXT DEFAULT NULL, new_pin TEXT DEFAULT NULL) RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE v_caller_slot INTEGER; v_caller_role TEXT;
BEGIN
  v_caller_slot := get_session_user_slot();
  IF v_caller_slot IS NULL AND session_token IS NOT NULL THEN SELECT user_slot, role INTO v_caller_slot, v_caller_role FROM auth_sessions WHERE token = session_token AND expires_at > NOW(); END IF;
  IF v_caller_slot IS NOT NULL AND v_caller_role IS NULL THEN SELECT role INTO v_caller_role FROM auth_sessions WHERE user_slot = v_caller_slot AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1; END IF;
  IF v_caller_role IS NULL OR v_caller_role != 'admin' THEN RETURN json_build_object('ok', false, 'error', 'Admin access required'); END IF;
  IF new_pin IS NULL THEN RETURN json_build_object('ok', false, 'error', 'Missing PIN'); END IF;
  IF length(new_pin) < 4 OR length(new_pin) > 6 THEN RETURN json_build_object('ok', false, 'error', 'PIN must be 4-6 digits'); END IF;
  UPDATE config SET value = crypt(new_pin, gen_salt('bf')), updated_at = NOW() WHERE key = 'section1_pin';
  RETURN json_build_object('ok', true);
END; $$;

-- ═══ FORMULA RPCs ═══

CREATE OR REPLACE FUNCTION save_formula_with_ingredients(
  p_formula_id UUID, p_product_code TEXT, p_product_name TEXT, p_batch_size DECIMAL, p_version INT, p_version_note TEXT,
  p_active BOOLEAN, p_input_mode TEXT, p_notes TEXT, p_sensory JSONB, p_created_by INT, p_ingredients JSONB, p_session_token TEXT DEFAULT NULL
) RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE v_formula_id UUID; v_is_update BOOLEAN := FALSE; v_existing RECORD; v_caller_slot INTEGER; v_caller_role TEXT; v_has_edit_share BOOLEAN := FALSE; v_is_shared_edit BOOLEAN := FALSE;
BEGIN
  IF p_session_token IS NOT NULL AND p_session_token != '' THEN SELECT user_slot INTO v_caller_slot FROM auth_sessions WHERE token = p_session_token AND expires_at > NOW(); END IF;
  IF v_caller_slot IS NULL THEN v_caller_slot := get_session_user_slot(); END IF;
  IF v_caller_slot IS NULL THEN v_caller_slot := p_created_by; END IF;
  IF v_caller_slot IS NULL THEN RETURN json_build_object('ok', false, 'error', 'Not authenticated'); END IF;
  SELECT role INTO v_caller_role FROM users WHERE slot = v_caller_slot;
  IF v_caller_role IS NULL THEN RETURN json_build_object('ok', false, 'error', 'Invalid user'); END IF;
  IF p_formula_id IS NOT NULL THEN
    SELECT id, created_by INTO v_existing FROM formulas WHERE id = p_formula_id;
    IF v_existing.id IS NOT NULL THEN
      IF v_existing.created_by != v_caller_slot THEN
        IF v_caller_role IN ('manager', 'admin') THEN NULL;
        ELSE
          SELECT EXISTS (SELECT 1 FROM shared_formulas WHERE formula_id = p_formula_id AND shared_with = v_caller_slot AND permission = 'edit') INTO v_has_edit_share;
          IF NOT v_has_edit_share THEN RETURN json_build_object('ok', false, 'error', 'Cannot edit another user''s formula'); END IF;
          v_is_shared_edit := TRUE;
        END IF;
      END IF;
      v_is_update := TRUE; v_formula_id := p_formula_id;
    END IF;
  END IF;
  IF v_is_update THEN
    IF v_is_shared_edit THEN
      UPDATE formulas SET product_code=p_product_code, product_name=p_product_name, batch_size=p_batch_size, version=p_version, version_note=p_version_note, input_mode=p_input_mode, notes=p_notes, sensory=p_sensory, updated_at=NOW() WHERE id = v_formula_id;
    ELSE
      UPDATE formulas SET product_code=p_product_code, product_name=p_product_name, batch_size=p_batch_size, version=p_version, version_note=p_version_note, active=p_active, input_mode=p_input_mode, notes=p_notes, sensory=p_sensory, updated_at=NOW() WHERE id = v_formula_id;
    END IF;
  ELSE
    INSERT INTO formulas (product_code, product_name, batch_size, version, version_note, active, input_mode, notes, sensory, created_by, approval_status)
    VALUES (p_product_code, p_product_name, p_batch_size, p_version, p_version_note, p_active, p_input_mode, p_notes, p_sensory, v_caller_slot, 'draft') RETURNING id INTO v_formula_id;
  END IF;
  DELETE FROM formula_ingredients WHERE formula_id = v_formula_id;
  INSERT INTO formula_ingredients (formula_id, item_code, qty, pct, sort_order, step)
  SELECT v_formula_id, ing->>'item_code', (ing->>'qty')::decimal, (ing->>'pct')::decimal, (ing->>'sort_order')::int, COALESCE(ing->>'step', '') FROM jsonb_array_elements(p_ingredients) AS ing;
  IF p_active AND NOT v_is_shared_edit THEN
    UPDATE formulas SET active = FALSE WHERE product_code = p_product_code AND created_by = (SELECT created_by FROM formulas WHERE id = v_formula_id) AND id != v_formula_id;
  END IF;
  RETURN json_build_object('ok', true, 'id', v_formula_id);
END; $$;

CREATE OR REPLACE FUNCTION update_approval_status(p_formula_id UUID, p_status TEXT, p_reason TEXT DEFAULT NULL) RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE v_slot INTEGER; v_role TEXT; v_existing RECORD;
BEGIN
  v_slot := get_session_user_slot(); v_role := get_session_role();
  IF v_slot IS NULL THEN RETURN json_build_object('ok', false, 'error', 'Not authenticated'); END IF;
  SELECT id, created_by, approval_status INTO v_existing FROM formulas WHERE id = p_formula_id;
  IF v_existing.id IS NULL THEN RETURN json_build_object('ok', false, 'error', 'Formula not found'); END IF;
  IF p_status NOT IN ('draft', 'pending', 'approved', 'rejected') THEN RETURN json_build_object('ok', false, 'error', 'Invalid status'); END IF;
  IF p_status = 'pending' AND v_existing.created_by != v_slot AND v_role NOT IN ('admin', 'manager') THEN RETURN json_build_object('ok', false, 'error', 'Only the owner or manager can submit for review'); END IF;
  IF p_status IN ('approved', 'rejected') AND v_role NOT IN ('admin', 'manager') THEN RETURN json_build_object('ok', false, 'error', 'Only managers can approve or reject'); END IF;
  UPDATE formulas SET approval_status = p_status, updated_at = NOW() WHERE id = p_formula_id;
  RETURN json_build_object('ok', true);
END; $$;

CREATE OR REPLACE FUNCTION set_formula_active(p_formula_id UUID, p_active BOOLEAN) RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE v_slot INTEGER; v_role TEXT; v_existing RECORD;
BEGIN
  v_slot := get_session_user_slot(); v_role := get_session_role();
  IF v_slot IS NULL THEN RETURN json_build_object('ok', false, 'error', 'Not authenticated'); END IF;
  SELECT id, created_by, product_code INTO v_existing FROM formulas WHERE id = p_formula_id;
  IF v_existing.id IS NULL THEN RETURN json_build_object('ok', false, 'error', 'Formula not found'); END IF;
  IF v_existing.created_by != v_slot AND v_role NOT IN ('admin', 'manager') THEN RETURN json_build_object('ok', false, 'error', 'Only the owner or manager can change active status'); END IF;
  UPDATE formulas SET active = p_active, updated_at = NOW() WHERE id = p_formula_id;
  IF p_active THEN UPDATE formulas SET active = FALSE WHERE product_code = v_existing.product_code AND created_by = v_existing.created_by AND id != p_formula_id; END IF;
  RETURN json_build_object('ok', true);
END; $$;

CREATE OR REPLACE FUNCTION update_formula_name(p_product_code TEXT, p_new_name TEXT, p_created_by INT DEFAULT NULL) RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE v_slot INTEGER; v_role TEXT; v_count INT;
BEGIN
  v_slot := get_session_user_slot(); v_role := get_session_role();
  IF v_slot IS NULL THEN RETURN json_build_object('ok', false, 'error', 'Not authenticated'); END IF;
  IF p_new_name IS NULL OR trim(p_new_name) = '' THEN RETURN json_build_object('ok', false, 'error', 'Name cannot be empty'); END IF;
  IF v_role IN ('admin', 'manager') THEN
    IF p_created_by IS NOT NULL THEN UPDATE formulas SET product_name = trim(p_new_name), updated_at = NOW() WHERE lower(product_code) = lower(p_product_code) AND created_by = p_created_by;
    ELSE UPDATE formulas SET product_name = trim(p_new_name), updated_at = NOW() WHERE lower(product_code) = lower(p_product_code); END IF;
  ELSE UPDATE formulas SET product_name = trim(p_new_name), updated_at = NOW() WHERE lower(product_code) = lower(p_product_code) AND created_by = v_slot; END IF;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN json_build_object('ok', true, 'updated', v_count);
END; $$;

-- ═══ SHARING RPCs ═══

CREATE OR REPLACE FUNCTION share_formula(p_formula_id UUID, p_shared_with INT, p_permission TEXT DEFAULT 'view') RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE v_slot INTEGER; v_role TEXT; v_owner INTEGER;
BEGIN
  v_slot := get_session_user_slot(); v_role := get_session_role();
  IF v_slot IS NULL THEN RETURN json_build_object('ok', false, 'error', 'Not authenticated'); END IF;
  SELECT created_by INTO v_owner FROM formulas WHERE id = p_formula_id;
  IF v_owner IS NULL THEN RETURN json_build_object('ok', false, 'error', 'Formula not found'); END IF;
  IF v_role NOT IN ('admin', 'manager') AND v_owner != v_slot THEN RETURN json_build_object('ok', false, 'error', 'Only the owner or a manager can share this formula'); END IF;
  IF p_shared_with = v_owner THEN RETURN json_build_object('ok', false, 'error', 'Cannot share with the formula owner'); END IF;
  IF p_permission NOT IN ('view', 'edit') THEN RETURN json_build_object('ok', false, 'error', 'Permission must be view or edit'); END IF;
  INSERT INTO shared_formulas (formula_id, shared_by, shared_with, permission) VALUES (p_formula_id, v_slot, p_shared_with, p_permission)
  ON CONFLICT (formula_id, shared_with) DO UPDATE SET permission = p_permission, shared_by = v_slot;
  RETURN json_build_object('ok', true);
END; $$;

CREATE OR REPLACE FUNCTION unshare_formula(p_formula_id UUID, p_shared_with INT) RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE v_slot INTEGER; v_role TEXT;
BEGIN
  v_slot := get_session_user_slot(); v_role := get_session_role();
  IF v_slot IS NULL THEN RETURN json_build_object('ok', false, 'error', 'Not authenticated'); END IF;
  IF v_role IN ('admin', 'manager') THEN DELETE FROM shared_formulas WHERE formula_id = p_formula_id AND shared_with = p_shared_with;
  ELSE DELETE FROM shared_formulas WHERE formula_id = p_formula_id AND shared_with = p_shared_with AND shared_by = v_slot; END IF;
  RETURN json_build_object('ok', true);
END; $$;

CREATE OR REPLACE FUNCTION get_formula_shares(p_formula_id UUID) RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE v_slot INTEGER; v_role TEXT; v_owner INTEGER; v_shares JSON;
BEGIN
  v_slot := get_session_user_slot(); v_role := get_session_role();
  IF v_slot IS NULL THEN RETURN json_build_object('ok', false, 'error', 'Not authenticated'); END IF;
  SELECT created_by INTO v_owner FROM formulas WHERE id = p_formula_id;
  IF v_owner IS NULL THEN RETURN json_build_object('ok', false, 'error', 'Formula not found'); END IF;
  IF v_role NOT IN ('admin', 'manager') AND v_owner != v_slot THEN
    IF NOT EXISTS (SELECT 1 FROM shared_formulas WHERE formula_id = p_formula_id AND shared_with = v_slot) THEN RETURN json_build_object('ok', false, 'error', 'Access denied'); END IF;
  END IF;
  SELECT json_agg(json_build_object('shared_with', sf.shared_with, 'shared_by', sf.shared_by, 'permission', sf.permission, 'user_name', u.name))
  INTO v_shares FROM shared_formulas sf JOIN users u ON u.slot = sf.shared_with WHERE sf.formula_id = p_formula_id;
  RETURN json_build_object('ok', true, 'shares', COALESCE(v_shares, '[]'::json));
END; $$;

-- ═══ DEFAULT DATA ═══

INSERT INTO config (key, value) VALUES ('section1_pin', crypt('100100', gen_salt('bf'))) ON CONFLICT (key) DO NOTHING;

INSERT INTO users (slot, name, pin_hash, role) VALUES
  (1, 'Admin',     crypt('123456', gen_salt('bf')), 'admin'),
  (2, 'Manager 1', crypt('222222', gen_salt('bf')), 'manager'),
  (3, 'Manager 2', crypt('333333', gen_salt('bf')), 'manager'),
  (4, 'Exec 1',    crypt('444444', gen_salt('bf')), 'user'),
  (5, 'Exec 2',    crypt('555555', gen_salt('bf')), 'user')
ON CONFLICT (slot) DO NOTHING;

INSERT INTO ingredients (item_code, item_name, description, packaging_size, price_per_kg) VALUES
  ('SP001', 'Paprika',       'Sweet Hungarian',  '25kg', 12.50),
  ('SP002', 'Garlic Powder', 'Dehydrated fine',  '20kg', 18.00),
  ('SP003', 'Onion Powder',  'White onion',      '25kg',  9.75),
  ('SP004', 'Black Pepper',  'Ground fine',      '20kg', 22.00),
  ('SP005', 'Salt',          'Fine table salt',  '50kg',  1.20),
  ('SP006', 'Cumin',         'Ground cumin',     '20kg', 15.50)
ON CONFLICT (item_code) DO NOTHING;

-- ═══ ROW LEVEL SECURITY ═══

ALTER TABLE config ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE ingredients ENABLE ROW LEVEL SECURITY;
ALTER TABLE formulas ENABLE ROW LEVEL SECURITY;
ALTER TABLE formula_ingredients ENABLE ROW LEVEL SECURITY;
ALTER TABLE costings ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE login_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE shared_formulas ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE price_history ENABLE ROW LEVEL SECURITY;

-- Tables with NO policies (RLS enabled = locked from anon): config, users, auth_sessions, login_attempts

CREATE POLICY "ingredients_select" ON ingredients FOR SELECT USING (has_valid_session());
CREATE POLICY "ingredients_insert" ON ingredients FOR INSERT WITH CHECK (has_valid_session() AND (is_admin_or_manager() OR get_session_role() = 'section1'));
CREATE POLICY "ingredients_update" ON ingredients FOR UPDATE USING (has_valid_session() AND (is_admin_or_manager() OR get_session_role() = 'section1'));
CREATE POLICY "ingredients_delete" ON ingredients FOR DELETE USING (has_valid_session() AND (is_admin_or_manager() OR get_session_role() = 'section1'));

CREATE POLICY "formulas_select" ON formulas FOR SELECT USING (has_valid_session() AND (is_admin_or_manager() OR created_by = get_session_user_slot() OR id IN (SELECT formula_id FROM shared_formulas WHERE shared_with = get_session_user_slot())));
CREATE POLICY "formulas_insert" ON formulas FOR INSERT WITH CHECK (has_valid_session());
CREATE POLICY "formulas_update" ON formulas FOR UPDATE USING (has_valid_session() AND (is_admin_or_manager() OR created_by = get_session_user_slot() OR id IN (SELECT formula_id FROM shared_formulas WHERE shared_with = get_session_user_slot() AND permission = 'edit')));
CREATE POLICY "formulas_delete" ON formulas FOR DELETE USING (has_valid_session() AND (is_admin_or_manager() OR created_by = get_session_user_slot()));

CREATE POLICY "fi_select" ON formula_ingredients FOR SELECT USING (has_valid_session() AND (is_admin_or_manager() OR formula_id IN (SELECT id FROM formulas WHERE created_by = get_session_user_slot()) OR formula_id IN (SELECT formula_id FROM shared_formulas WHERE shared_with = get_session_user_slot())));
CREATE POLICY "fi_insert" ON formula_ingredients FOR INSERT WITH CHECK (has_valid_session() AND (is_admin_or_manager() OR formula_id IN (SELECT id FROM formulas WHERE created_by = get_session_user_slot()) OR formula_id IN (SELECT formula_id FROM shared_formulas WHERE shared_with = get_session_user_slot() AND permission = 'edit')));
CREATE POLICY "fi_update" ON formula_ingredients FOR UPDATE USING (has_valid_session() AND (is_admin_or_manager() OR formula_id IN (SELECT id FROM formulas WHERE created_by = get_session_user_slot()) OR formula_id IN (SELECT formula_id FROM shared_formulas WHERE shared_with = get_session_user_slot() AND permission = 'edit')));
CREATE POLICY "fi_delete" ON formula_ingredients FOR DELETE USING (has_valid_session() AND (is_admin_or_manager() OR formula_id IN (SELECT id FROM formulas WHERE created_by = get_session_user_slot())));

CREATE POLICY "costings_select" ON costings FOR SELECT USING (has_valid_session() AND (is_admin_or_manager() OR created_by = get_session_user_slot()));
CREATE POLICY "costings_insert" ON costings FOR INSERT WITH CHECK (has_valid_session() AND created_by = get_session_user_slot());
CREATE POLICY "costings_update" ON costings FOR UPDATE USING (has_valid_session() AND (is_admin_or_manager() OR created_by = get_session_user_slot()));
CREATE POLICY "costings_delete" ON costings FOR DELETE USING (has_valid_session() AND (is_admin_or_manager() OR created_by = get_session_user_slot()));

CREATE POLICY "shared_formulas_select" ON shared_formulas FOR SELECT USING (has_valid_session() AND (is_admin_or_manager() OR shared_by = get_session_user_slot() OR shared_with = get_session_user_slot()));
CREATE POLICY "shared_formulas_insert" ON shared_formulas FOR INSERT WITH CHECK (has_valid_session() AND (is_admin_or_manager() OR shared_by = get_session_user_slot()));
CREATE POLICY "shared_formulas_update" ON shared_formulas FOR UPDATE USING (has_valid_session() AND (is_admin_or_manager() OR shared_by = get_session_user_slot()));
CREATE POLICY "shared_formulas_delete" ON shared_formulas FOR DELETE USING (has_valid_session() AND (is_admin_or_manager() OR shared_by = get_session_user_slot()));

CREATE POLICY "audit_select" ON audit_log FOR SELECT USING (has_valid_session());
CREATE POLICY "audit_insert" ON audit_log FOR INSERT WITH CHECK (has_valid_session() AND (user_slot = get_session_user_slot() OR user_slot = 0));

CREATE POLICY "ph_select" ON price_history FOR SELECT USING (has_valid_session());
CREATE POLICY "ph_insert" ON price_history FOR INSERT WITH CHECK (has_valid_session());

-- ═══ INDEXES ═══

CREATE INDEX IF NOT EXISTS idx_ingredients_code ON ingredients(item_code);
CREATE INDEX IF NOT EXISTS idx_formulas_creator ON formulas(created_by);
CREATE INDEX IF NOT EXISTS idx_formulas_code ON formulas(product_code);
CREATE INDEX IF NOT EXISTS idx_fi_formula ON formula_ingredients(formula_id);
CREATE INDEX IF NOT EXISTS idx_costings_formula ON costings(formula_id);
CREATE INDEX IF NOT EXISTS idx_costings_creator ON costings(created_by);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON auth_sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON auth_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_log(entity, entity_id);
CREATE INDEX IF NOT EXISTS idx_ph_item ON price_history(item_code);
CREATE INDEX IF NOT EXISTS idx_ph_date ON price_history(changed_at DESC);

-- ═══ CRON JOB ═══
-- Enable pg_cron in Supabase Dashboard > Database > Extensions, then run:
-- SELECT cron.schedule('cleanup-expired-sessions', '0 * * * *', 'DELETE FROM public.auth_sessions WHERE expires_at < now()');
