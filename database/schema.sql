-- ============================================================
-- AffiGuard – Supabase PostgreSQL Schema
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
  reset_token_expiry   TIMESTAMPTZ,
  -- ── Referral columns (added) ────────────────────────────
  referral_code        TEXT UNIQUE,
  referred_by          TEXT REFERENCES users(id) ON DELETE SET NULL,
  total_referrals      INTEGER DEFAULT 0,
  free_months_earned   INTEGER DEFAULT 0,
  free_months_remaining INTEGER DEFAULT 0
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

-- ── 8. Feedback ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS feedback (
  id          TEXT PRIMARY KEY,
  name        TEXT,
  email       TEXT,
  message     TEXT NOT NULL,
  rating      INTEGER CHECK (rating >= 1 AND rating <= 5),
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ── Referral columns migration (existing DB ke liye) ─────────
-- Agar table already exist karta hai to ye run karo:
ALTER TABLE users ADD COLUMN IF NOT EXISTS referral_code        TEXT UNIQUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS referred_by          TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS total_referrals      INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS free_months_earned   INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS free_months_remaining INTEGER DEFAULT 0;

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
ALTER TABLE feedback       DISABLE ROW LEVEL SECURITY;



-- ── 9. Coupons ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS coupons (
  id          TEXT PRIMARY KEY,
  code        TEXT UNIQUE NOT NULL,
  type        TEXT NOT NULL DEFAULT 'free_months',  -- free_months | plan_upgrade | percent_off
  value       INTEGER NOT NULL DEFAULT 1,            -- months count / percent
  plan_grant  TEXT,                                  -- plan to assign on redeem
  max_uses    INTEGER DEFAULT 1,
  uses        INTEGER DEFAULT 0,
  expires_at  TIMESTAMPTZ,
  note        TEXT,
  is_active   BOOLEAN DEFAULT TRUE,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_coupons_code ON coupons(code);
ALTER TABLE coupons DISABLE ROW LEVEL SECURITY;

-- ── SEC-04 FIX: Atomic rate-limit increment (eliminates race condition) ───────
-- Replaces the multi-step SELECT → UPDATE pattern in Python which had a TOCTOU
-- race window. This function does a single atomic INSERT … ON CONFLICT upsert.
-- Returns TRUE if the caller is over the limit, FALSE if they may proceed.
CREATE OR REPLACE FUNCTION increment_rate_limit(ip TEXT, limit_hour INTEGER)
RETURNS BOOLEAN LANGUAGE plpgsql AS $$
DECLARE
  current_count INTEGER;
BEGIN
  -- Reset window if expired, then increment; insert on first request.
  INSERT INTO rate_limits (ip, count, window_start)
  VALUES (ip, 1, NOW())
  ON CONFLICT (ip) DO UPDATE
    SET count        = CASE
                         WHEN rate_limits.window_start < NOW() - INTERVAL '1 hour'
                         THEN 1
                         ELSE rate_limits.count + 1
                       END,
        window_start = CASE
                         WHEN rate_limits.window_start < NOW() - INTERVAL '1 hour'
                         THEN NOW()
                         ELSE rate_limits.window_start
                       END
  RETURNING count INTO current_count;

  RETURN current_count > limit_hour;
END;
$$;

-- ── SEC-07 FIX: Atomic referral counter + reward logic ───────────────────────
-- Replaces the read-modify-write sequence in Python which had a race window
-- when two referrals fired concurrently. All arithmetic happens in one UPDATE.
CREATE OR REPLACE FUNCTION increment_referral_and_award(user_id TEXT)
RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE
  new_total       INTEGER;
  current_earned  INTEGER;
  months_to_add   INTEGER;
  base_expiry     TIMESTAMPTZ;
BEGIN
  UPDATE users
  SET total_referrals = total_referrals + 1
  WHERE id = user_id
  RETURNING total_referrals, free_months_earned
    INTO new_total, current_earned;

  -- Milestone: 10 referrals → 2 free months total, 5 referrals → 1 free month total
  IF new_total >= 10 AND current_earned < 2 THEN
    months_to_add := 2 - current_earned;
    UPDATE users
    SET free_months_earned    = 2,
        free_months_remaining = free_months_remaining + months_to_add,
        plan_expiry           = COALESCE(
                                  GREATEST(plan_expiry, NOW()),
                                  NOW()
                                ) + (months_to_add || ' months')::INTERVAL,
        plan                  = CASE WHEN plan IN ('free','hobby') THEN 'popular' ELSE plan END
    WHERE id = user_id;

  ELSIF new_total >= 5 AND current_earned < 1 THEN
    UPDATE users
    SET free_months_earned    = 1,
        free_months_remaining = free_months_remaining + 1,
        plan_expiry           = COALESCE(
                                  GREATEST(plan_expiry, NOW()),
                                  NOW()
                                ) + INTERVAL '1 month',
        plan                  = CASE WHEN plan IN ('free','hobby') THEN 'popular' ELSE plan END
    WHERE id = user_id;
  END IF;
END;
$$;
