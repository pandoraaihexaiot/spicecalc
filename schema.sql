-- SpiceCalc Database Schema for Supabase (HARDENED)
-- Run this in Supabase SQL Editor (Dashboard → SQL Editor → New Query)
--
-- MIGRATION NOTES:
-- If upgrading from the old schema, run schema_migrate.sql instead.
-- This script is for FRESH installs only.

-- ═══ ENABLE REQUIRED EXTENSIONS ═══
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ═══ TABLES ═══

-- 1. Config table (app settings like section1 PIN)
CREATE TABLE IF NOT EXISTS config (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Users table (5 user slots) — PINs stored as bcrypt hashes
CREATE TABLE IF NOT EXISTS users (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  slot INT UNIQUE NOT NULL CHECK (slot BETWEEN 1 AND 5),
  name TEXT NOT NULL DEFAULT 'User',
  pin_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user')),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. Ingredients master
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

-- 4. Formulas
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
  created_by INT NOT NULL REFERENCES users(slot),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(product_code, version, created_by)
);

-- 5. Formula ingredients (child rows)
CREATE TABLE IF NOT EXISTS formula_ingredients (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  formula_id UUID NOT NULL REFERENCES formulas(id) ON DELETE CASCADE,
  item_code TEXT NOT NULL,
  qty DECIMAL(12,4) DEFAULT 0,
  pct DECIMAL(12,4) DEFAULT 0,
  sort_order INT DEFAULT 0
);

-- 6. Costings
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
  grammage DECIMAL(12,4) DEFAULT 1,
  label TEXT DEFAULT '',
  created_by INT NOT NULL REFERENCES users(slot),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 7. Auth sessions — server-managed session tokens
CREATE TABLE IF NOT EXISTS auth_sessions (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_slot INT NOT NULL,
  token TEXT UNIQUE NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '30 minutes')
);

-- ═══ SERVER-SIDE RPC FUNCTIONS ═══

-- Verify section1 PIN (shared ingredients PIN)
CREATE OR REPLACE FUNCTION verify_section1_pin(pin_input TEXT)
RETURNS JSON
LANGUAGE plpgsql SECURITY DEFINER
AS $$
DECLARE
  stored_hash TEXT;
  session_token TEXT;
BEGIN
  SELECT value INTO stored_hash FROM config WHERE key = 'section1_pin';
  IF stored_hash IS NULL THEN
    RETURN json_build_object('ok', false, 'error', 'Config not found');
  END IF;

  IF stored_hash = crypt(pin_input, stored_hash) THEN
    session_token := encode(gen_random_bytes(32), 'hex');
    INSERT INTO auth_sessions (user_slot, token, role, expires_at)
    VALUES (0, session_token, 'section1', NOW() + INTERVAL '30 minutes');
    RETURN json_build_object('ok', true, 'token', session_token);
  ELSE
    RETURN json_build_object('ok', false, 'error', 'Incorrect PIN');
  END IF;
END;
$$;

-- Verify user PIN — returns session token + user info (never exposes PIN)
CREATE OR REPLACE FUNCTION verify_user_pin(pin_input TEXT)
RETURNS JSON
LANGUAGE plpgsql SECURITY DEFINER
AS $$
DECLARE
  u RECORD;
  session_token TEXT;
BEGIN
  SELECT slot, name, role, pin_hash INTO u
  FROM users
  WHERE pin_hash = crypt(pin_input, pin_hash);

  IF u.slot IS NULL THEN
    RETURN json_build_object('ok', false, 'error', 'Incorrect PIN');
  END IF;

  session_token := encode(gen_random_bytes(32), 'hex');
  INSERT INTO auth_sessions (user_slot, token, role, expires_at)
  VALUES (u.slot, session_token, u.role, NOW() + INTERVAL '30 minutes');

  RETURN json_build_object(
    'ok', true,
    'token', session_token,
    'slot', u.slot,
    'name', u.name,
    'role', u.role
  );
END;
$$;

-- Refresh session (extend expiry on activity)
CREATE OR REPLACE FUNCTION refresh_session(session_token TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER
AS $$
BEGIN
  UPDATE auth_sessions
  SET expires_at = NOW() + INTERVAL '30 minutes'
  WHERE token = session_token AND expires_at > NOW();
  RETURN FOUND;
END;
$$;

-- Logout / destroy session
CREATE OR REPLACE FUNCTION destroy_session(session_token TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER
AS $$
BEGIN
  DELETE FROM auth_sessions WHERE token = session_token;
  RETURN FOUND;
END;
$$;

-- Cleanup expired sessions (call periodically or via cron)
CREATE OR REPLACE FUNCTION cleanup_sessions()
RETURNS INT
LANGUAGE plpgsql SECURITY DEFINER
AS $$
DECLARE
  cnt INT;
BEGIN
  DELETE FROM auth_sessions WHERE expires_at < NOW();
  GET DIAGNOSTICS cnt = ROW_COUNT;
  RETURN cnt;
END;
$$;

-- Admin: update user name and PIN
CREATE OR REPLACE FUNCTION admin_update_user(
  session_token TEXT,
  target_slot INT,
  new_name TEXT,
  new_pin TEXT DEFAULT NULL
)
RETURNS JSON
LANGUAGE plpgsql SECURITY DEFINER
AS $$
DECLARE
  caller_role TEXT;
  dup_check INT;
BEGIN
  SELECT role INTO caller_role FROM auth_sessions
  WHERE token = session_token AND expires_at > NOW();
  IF caller_role IS NULL OR caller_role != 'admin' THEN
    RETURN json_build_object('ok', false, 'error', 'Admin access required');
  END IF;

  IF new_pin IS NOT NULL THEN
    IF length(new_pin) < 4 OR length(new_pin) > 6 THEN
      RETURN json_build_object('ok', false, 'error', 'PIN must be 4-6 digits');
    END IF;
    -- Check for duplicate PIN
    SELECT slot INTO dup_check FROM users
    WHERE pin_hash = crypt(new_pin, pin_hash) AND slot != target_slot;
    IF dup_check IS NOT NULL THEN
      RETURN json_build_object('ok', false, 'error', 'PIN already in use');
    END IF;
    UPDATE users SET name = new_name, pin_hash = crypt(new_pin, gen_salt('bf')), updated_at = NOW()
    WHERE slot = target_slot;
  ELSE
    UPDATE users SET name = new_name, updated_at = NOW() WHERE slot = target_slot;
  END IF;

  RETURN json_build_object('ok', true);
END;
$$;

-- Admin: update section1 PIN
CREATE OR REPLACE FUNCTION admin_update_section1_pin(session_token TEXT, new_pin TEXT)
RETURNS JSON
LANGUAGE plpgsql SECURITY DEFINER
AS $$
DECLARE
  caller_role TEXT;
BEGIN
  SELECT role INTO caller_role FROM auth_sessions
  WHERE token = session_token AND expires_at > NOW();
  IF caller_role IS NULL OR caller_role != 'admin' THEN
    RETURN json_build_object('ok', false, 'error', 'Admin access required');
  END IF;
  IF length(new_pin) < 4 OR length(new_pin) > 6 THEN
    RETURN json_build_object('ok', false, 'error', 'PIN must be 4-6 digits');
  END IF;
  UPDATE config SET value = crypt(new_pin, gen_salt('bf')), updated_at = NOW()
  WHERE key = 'section1_pin';
  RETURN json_build_object('ok', true);
END;
$$;

-- Admin: get users list (names + slots only, NEVER PINs)
CREATE OR REPLACE FUNCTION admin_get_users(session_token TEXT)
RETURNS JSON
LANGUAGE plpgsql SECURITY DEFINER
AS $$
DECLARE
  caller_role TEXT;
  result JSON;
BEGIN
  SELECT role INTO caller_role FROM auth_sessions
  WHERE token = session_token AND expires_at > NOW();
  IF caller_role IS NULL OR caller_role != 'admin' THEN
    RETURN json_build_object('ok', false, 'error', 'Admin access required');
  END IF;
  SELECT json_agg(json_build_object('slot', slot, 'name', name, 'role', role) ORDER BY slot)
  INTO result FROM users;
  RETURN json_build_object('ok', true, 'users', COALESCE(result, '[]'::json));
END;
$$;

-- Transactional formula save (atomic delete+insert for ingredients)
CREATE OR REPLACE FUNCTION save_formula_with_ingredients(
  p_formula_id UUID,
  p_product_code TEXT,
  p_product_name TEXT,
  p_batch_size DECIMAL,
  p_version INT,
  p_version_note TEXT,
  p_active BOOLEAN,
  p_input_mode TEXT,
  p_notes TEXT,
  p_sensory JSONB,
  p_created_by INT,
  p_ingredients JSONB
)
RETURNS JSON
LANGUAGE plpgsql SECURITY DEFINER
AS $$
DECLARE
  v_formula_id UUID;
  v_is_update BOOLEAN := FALSE;
  v_existing RECORD;
BEGIN
  -- Check if this is an update
  IF p_formula_id IS NOT NULL THEN
    SELECT id, created_by INTO v_existing FROM formulas WHERE id = p_formula_id;
    IF v_existing.id IS NOT NULL THEN
      IF v_existing.created_by != p_created_by THEN
        RETURN json_build_object('ok', false, 'error', 'Cannot edit another user''s formula');
      END IF;
      v_is_update := TRUE;
      v_formula_id := p_formula_id;
    END IF;
  END IF;

  IF v_is_update THEN
    UPDATE formulas SET
      product_code = p_product_code,
      product_name = p_product_name,
      batch_size = p_batch_size,
      version = p_version,
      version_note = p_version_note,
      active = p_active,
      input_mode = p_input_mode,
      notes = p_notes,
      sensory = p_sensory,
      updated_at = NOW()
    WHERE id = v_formula_id;
  ELSE
    INSERT INTO formulas (product_code, product_name, batch_size, version, version_note, active, input_mode, notes, sensory, created_by)
    VALUES (p_product_code, p_product_name, p_batch_size, p_version, p_version_note, p_active, p_input_mode, p_notes, p_sensory, p_created_by)
    RETURNING id INTO v_formula_id;
  END IF;

  -- Atomically replace ingredients within same transaction
  DELETE FROM formula_ingredients WHERE formula_id = v_formula_id;

  INSERT INTO formula_ingredients (formula_id, item_code, qty, pct, sort_order)
  SELECT v_formula_id, ing->>'item_code', (ing->>'qty')::decimal, (ing->>'pct')::decimal, (ing->>'sort_order')::int
  FROM jsonb_array_elements(p_ingredients) AS ing;

  -- Deactivate other versions if this one is active
  IF p_active THEN
    UPDATE formulas SET active = FALSE
    WHERE product_code = p_product_code
      AND created_by = p_created_by
      AND id != v_formula_id;
  END IF;

  RETURN json_build_object('ok', true, 'id', v_formula_id);
END;
$$;

-- ═══ INSERT DEFAULT DATA ═══

-- Default Section 1 PIN (hashed) — default PIN: 100100
INSERT INTO config (key, value) VALUES ('section1_pin', crypt('100100', gen_salt('bf')))
ON CONFLICT (key) DO NOTHING;

-- Default 5 users (PINs hashed with bcrypt)
INSERT INTO users (slot, name, pin_hash, role) VALUES
  (1, 'Admin', crypt('123456', gen_salt('bf')), 'admin'),
  (2, 'User 2', crypt('222222', gen_salt('bf')), 'user'),
  (3, 'User 3', crypt('333333', gen_salt('bf')), 'user'),
  (4, 'User 4', crypt('444444', gen_salt('bf')), 'user'),
  (5, 'User 5', crypt('555555', gen_salt('bf')), 'user')
ON CONFLICT (slot) DO NOTHING;

-- Sample ingredients
INSERT INTO ingredients (item_code, item_name, description, packaging_size, price_per_kg) VALUES
  ('SP001', 'Paprika', 'Sweet Hungarian', '25kg', 12.50),
  ('SP002', 'Garlic Powder', 'Dehydrated fine', '20kg', 18.00),
  ('SP003', 'Onion Powder', 'White onion', '25kg', 9.75),
  ('SP004', 'Black Pepper', 'Ground fine', '20kg', 22.00),
  ('SP005', 'Salt', 'Fine table salt', '50kg', 1.20),
  ('SP006', 'Cumin', 'Ground cumin', '20kg', 15.50)
ON CONFLICT (item_code) DO NOTHING;

-- ═══ ROW LEVEL SECURITY ═══

ALTER TABLE config ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE ingredients ENABLE ROW LEVEL SECURITY;
ALTER TABLE formulas ENABLE ROW LEVEL SECURITY;
ALTER TABLE formula_ingredients ENABLE ROW LEVEL SECURITY;
ALTER TABLE costings ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_sessions ENABLE ROW LEVEL SECURITY;

-- Config: read-only (PIN is hashed, safe to read; writes go through RPC)
CREATE POLICY "config_select" ON config FOR SELECT USING (true);

-- Users: NO direct access — all operations through SECURITY DEFINER RPCs
-- (no policy = no access for anon role)

-- Ingredients: full access (shared resource, protected by app-level PIN)
CREATE POLICY "ingredients_select" ON ingredients FOR SELECT USING (true);
CREATE POLICY "ingredients_insert" ON ingredients FOR INSERT WITH CHECK (true);
CREATE POLICY "ingredients_update" ON ingredients FOR UPDATE USING (true);
CREATE POLICY "ingredients_delete" ON ingredients FOR DELETE USING (true);

-- Formulas: read all, write all (ownership enforced in save_formula_with_ingredients RPC)
CREATE POLICY "formulas_select" ON formulas FOR SELECT USING (true);
CREATE POLICY "formulas_insert" ON formulas FOR INSERT WITH CHECK (true);
CREATE POLICY "formulas_update" ON formulas FOR UPDATE USING (true);
CREATE POLICY "formulas_delete" ON formulas FOR DELETE USING (true);

-- Formula ingredients: managed through RPC for writes, readable by all
CREATE POLICY "fi_select" ON formula_ingredients FOR SELECT USING (true);
CREATE POLICY "fi_insert" ON formula_ingredients FOR INSERT WITH CHECK (true);
CREATE POLICY "fi_update" ON formula_ingredients FOR UPDATE USING (true);
CREATE POLICY "fi_delete" ON formula_ingredients FOR DELETE USING (true);

-- Costings: full access (ownership enforced at app level)
CREATE POLICY "costings_select" ON costings FOR SELECT USING (true);
CREATE POLICY "costings_insert" ON costings FOR INSERT WITH CHECK (true);
CREATE POLICY "costings_update" ON costings FOR UPDATE USING (true);
CREATE POLICY "costings_delete" ON costings FOR DELETE USING (true);

-- Auth sessions: NO direct access (managed by SECURITY DEFINER RPCs only)
-- (no policy = no access for anon role)

-- ═══ INDEXES ═══
CREATE INDEX IF NOT EXISTS idx_ingredients_code ON ingredients(item_code);
CREATE INDEX IF NOT EXISTS idx_formulas_creator ON formulas(created_by);
CREATE INDEX IF NOT EXISTS idx_formulas_code ON formulas(product_code);
CREATE INDEX IF NOT EXISTS idx_fi_formula ON formula_ingredients(formula_id);
CREATE INDEX IF NOT EXISTS idx_costings_formula ON costings(formula_id);
CREATE INDEX IF NOT EXISTS idx_costings_creator ON costings(created_by);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON auth_sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON auth_sessions(expires_at);
