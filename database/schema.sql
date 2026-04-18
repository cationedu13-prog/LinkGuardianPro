-- ============================================================
-- LinkGuardian Pro – Supabase PostgreSQL Schema
-- Run this in your Supabase SQL Editor
-- ============================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================
-- USERS TABLE
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email           TEXT UNIQUE NOT NULL,
    full_name       TEXT,
    password_hash   TEXT NOT NULL,
    plan            TEXT NOT NULL DEFAULT 'free'
                        CHECK (plan IN ('free','pro','business','agency')),
    plan_expiry     TIMESTAMPTZ,          -- NULL = never expires (free tier)
    join_date       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    telegram_chat_id TEXT,                -- for alerts
    whatsapp_number TEXT,                 -- optional future feature
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    last_login      TIMESTAMPTZ
);

-- ============================================================
-- LINKS TABLE
-- ============================================================
CREATE TABLE IF NOT EXISTS links (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    url             TEXT NOT NULL,
    platform        TEXT NOT NULL DEFAULT 'generic'
                        CHECK (platform IN ('generic','amazon','flipkart','shopify','etsy','custom')),
    frequency       TEXT NOT NULL DEFAULT 'twice_daily'
                        CHECK (frequency IN ('twice_daily','hourly','daily')),
    status          TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('active','broken','out_of_stock','error','pending')),
    last_checked    TIMESTAMPTZ,
    last_status_change TIMESTAMPTZ,
    response_time   INTEGER,              -- milliseconds
    layer_used      TEXT,                 -- layer1/layer2/layer3
    error_message   TEXT,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    alert_sent      BOOLEAN NOT NULL DEFAULT FALSE  -- prevent duplicate alerts
);

-- ============================================================
-- CHECK HISTORY TABLE  (rolling 90-day window)
-- ============================================================
CREATE TABLE IF NOT EXISTS check_history (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    link_id         UUID NOT NULL REFERENCES links(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status          TEXT NOT NULL,
    response_time   INTEGER,
    layer_used      TEXT,
    error_message   TEXT,
    checked_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- ALERTS TABLE  (log of every alert sent)
-- ============================================================
CREATE TABLE IF NOT EXISTS alerts (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    link_id         UUID REFERENCES links(id) ON DELETE SET NULL,
    alert_type      TEXT NOT NULL
                        CHECK (alert_type IN ('broken','out_of_stock','error','plan_expiry','plan_expired')),
    channel         TEXT NOT NULL CHECK (channel IN ('telegram','whatsapp','email')),
    message         TEXT,
    sent_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    success         BOOLEAN NOT NULL DEFAULT TRUE
);

-- ============================================================
-- PAYMENTS TABLE  (stub – extend for Stripe/Razorpay)
-- ============================================================
CREATE TABLE IF NOT EXISTS payments (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    plan            TEXT NOT NULL,
    amount          NUMERIC(10,2) NOT NULL,
    currency        TEXT NOT NULL DEFAULT 'INR',
    gateway         TEXT NOT NULL CHECK (gateway IN ('stripe','razorpay','manual')),
    gateway_payment_id TEXT,
    status          TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending','success','failed','refunded')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ
);

-- ============================================================
-- SESSIONS TABLE  (simple server-side session tracking)
-- ============================================================
CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT PRIMARY KEY,     -- session token (UUID string)
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    ip_address      TEXT
);

-- ============================================================
-- RATE LIMIT TABLE  (free checker – IP-based)
-- ============================================================
CREATE TABLE IF NOT EXISTS rate_limits (
    ip_address      TEXT NOT NULL,
    endpoint        TEXT NOT NULL,
    request_count   INTEGER NOT NULL DEFAULT 1,
    window_start    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (ip_address, endpoint)
);

-- ============================================================
-- INDEXES
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_links_user_id        ON links(user_id);
CREATE INDEX IF NOT EXISTS idx_links_is_active       ON links(is_active);
CREATE INDEX IF NOT EXISTS idx_check_history_link    ON check_history(link_id);
CREATE INDEX IF NOT EXISTS idx_check_history_checked ON check_history(checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_user_id        ON alerts(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id      ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires      ON sessions(expires_at);

-- ============================================================
-- ROW LEVEL SECURITY (RLS)  – enable after testing
-- ============================================================
-- ALTER TABLE users     ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE links     ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE check_history ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE alerts    ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE payments  ENABLE ROW LEVEL SECURITY;

-- ============================================================
-- PLAN LIMITS VIEW
-- ============================================================
CREATE OR REPLACE VIEW plan_limits AS
SELECT 'free'     AS plan, 5   AS max_links, 'twice_daily' AS max_frequency UNION ALL
SELECT 'pro'      AS plan, 20  AS max_links, 'hourly'      AS max_frequency UNION ALL
SELECT 'business' AS plan, 100 AS max_links, 'hourly'      AS max_frequency UNION ALL
SELECT 'agency'   AS plan, 500 AS max_links, 'hourly'      AS max_frequency;

-- ============================================================
-- CLEANUP FUNCTION  (run weekly via pg_cron or manually)
-- ============================================================
CREATE OR REPLACE FUNCTION cleanup_old_data() RETURNS void AS $$
BEGIN
    -- Delete check history older than 90 days
    DELETE FROM check_history WHERE checked_at < NOW() - INTERVAL '90 days';
    -- Delete expired sessions
    DELETE FROM sessions WHERE expires_at < NOW();
    -- Delete old rate limit records
    DELETE FROM rate_limits WHERE window_start < NOW() - INTERVAL '1 hour';
END;
$$ LANGUAGE plpgsql;
