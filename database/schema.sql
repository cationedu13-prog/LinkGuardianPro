-- ============================================================
-- LinkGuardian Pro – Supabase PostgreSQL Schema
-- Run this entire file in Supabase → SQL Editor → New Query
-- ============================================================

-- ── 1. Users ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id                   TEXT PRIMARY KEY,
  email                TEXT UNIQUE NOT NULL,
  full_name            TEXT,
  password_hash        TEXT NOT NULL,
  plan                 TEXT NOT NULL DEFAULT 'free',
  plan_expiry          TIMESTAMPTZ,
  join_date            TIMESTAMPTZ DEFAULT NOW(),
  last_login           TIMESTAMPTZ,
  telegram_chat_id     TEXT,
  whatsapp_number      TEXT,
  reset_token          TEXT,
  reset_token_expiry   TIMESTAMPTZ
);

-- ── 2. Links ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS links (
  id                TEXT PRIMARY KEY,
  user_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name              TEXT NOT NULL,
  url               TEXT NOT NULL,
  platform          TEXT DEFAULT 'generic',
  frequency         TEXT DEFAULT 'twice_daily',
  status            TEXT DEFAULT 'pending',
  is_active         BOOLEAN DEFAULT TRUE,
  created_at        TIMESTAMPTZ DEFAULT NOW(),
  last_checked      TIMESTAMPTZ,
  response_time     INTEGER,
  layer_used        TEXT,
  error_message     TEXT,
  last_status_change TIMESTAMPTZ,
  alert_sent        BOOLEAN DEFAULT FALSE
);

-- ── 3. Check History ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS check_history (
  id            TEXT PRIMARY KEY,
  link_id       TEXT NOT NULL REFERENCES links(id) ON DELETE CASCADE,
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status        TEXT NOT NULL,
  response_time INTEGER,
  layer_used    TEXT,
  error_message TEXT,
  checked_at    TIMESTAMPTZ DEFAULT NOW()
);

-- ── 4. Alerts ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  link_id     TEXT REFERENCES links(id) ON DELETE SET NULL,
  alert_type  TEXT NOT NULL,
  channel     TEXT NOT NULL DEFAULT 'telegram',
  message     TEXT,
  sent_at     TIMESTAMPTZ DEFAULT NOW(),
  success     BOOLEAN DEFAULT FALSE
);

-- ── 5. Payments (stub – for future use) ──────────────────────
CREATE TABLE IF NOT EXISTS payments (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  amount      NUMERIC(10,2),
  currency    TEXT DEFAULT 'INR',
  plan        TEXT,
  status      TEXT DEFAULT 'pending',
  gateway     TEXT,
  gateway_id  TEXT,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ── 6. Sessions (reference table – Flask manages actual sessions) ──
CREATE TABLE IF NOT EXISTS sessions (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  expires_at TIMESTAMPTZ
);

-- ── 7. Rate Limits (for future Redis-less rate limiting) ──────
CREATE TABLE IF NOT EXISTS rate_limits (
  ip           TEXT PRIMARY KEY,
  count        INTEGER DEFAULT 1,
  window_start TIMESTAMPTZ DEFAULT NOW()
);

-- ── Indexes for performance ───────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_links_user_id        ON links(user_id);
CREATE INDEX IF NOT EXISTS idx_links_is_active       ON links(is_active);
CREATE INDEX IF NOT EXISTS idx_check_history_link_id ON check_history(link_id);
CREATE INDEX IF NOT EXISTS idx_check_history_user_id ON check_history(user_id);
CREATE INDEX IF NOT EXISTS idx_check_history_checked ON check_history(checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_user_id        ON alerts(user_id);

-- ── Auto-delete check history older than 90 days ─────────────
-- Run this once. Supabase does not support pg_cron on free tier,
-- so this is handled by the cron endpoint in app.py instead.
-- (Optional) If you have pg_cron enabled:
-- SELECT cron.schedule('cleanup-history', '0 3 * * *',
--   $$DELETE FROM check_history WHERE checked_at < NOW() - INTERVAL '90 days'$$);

-- ── Row Level Security (RLS) – disable for service_role backend ──
-- Our backend uses service_role key which bypasses RLS.
-- Enable RLS only if you plan to use anon key in frontend directly.
ALTER TABLE users          DISABLE ROW LEVEL SECURITY;
ALTER TABLE links          DISABLE ROW LEVEL SECURITY;
ALTER TABLE check_history  DISABLE ROW LEVEL SECURITY;
ALTER TABLE alerts         DISABLE ROW LEVEL SECURITY;
ALTER TABLE payments       DISABLE ROW LEVEL SECURITY;
ALTER TABLE sessions       DISABLE ROW LEVEL SECURITY;
ALTER TABLE rate_limits    DISABLE ROW LEVEL SECURITY;
