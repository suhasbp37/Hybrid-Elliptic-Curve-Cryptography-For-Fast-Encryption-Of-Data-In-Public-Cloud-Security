-- ICAT KMS & Cryptographic Auth schema patch:
-- 1. app_users table for self-contained PBKDF2-HMAC password auth + signed public keys
-- 2. user_public_keys table for legacy key compatibility
-- Run in Supabase SQL Editor. Safe to re-run multiple times (idempotent).

CREATE TABLE IF NOT EXISTS app_users (
    email               TEXT PRIMARY KEY,
    password_salt       TEXT NOT NULL,
    password_hash       TEXT NOT NULL,
    x25519_pub          TEXT NOT NULL,
    mlkem_pub           TEXT NOT NULL,
    ed25519_verify_key  TEXT NOT NULL,
    key_signature       TEXT NOT NULL,   -- Ed25519 signature over f"{email}|{x25519_pub}|{mlkem_pub}"
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE app_users ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "app_users_select" ON app_users;
CREATE POLICY "app_users_select" ON app_users FOR SELECT USING (true);

DROP POLICY IF EXISTS "app_users_insert" ON app_users;
CREATE POLICY "app_users_insert" ON app_users FOR INSERT WITH CHECK (true);

DROP POLICY IF EXISTS "app_users_update" ON app_users;
CREATE POLICY "app_users_update" ON app_users FOR UPDATE USING (true);


CREATE TABLE IF NOT EXISTS user_public_keys (
    email               TEXT PRIMARY KEY,
    x25519_pub          TEXT NOT NULL,
    mlkem_pub           TEXT NOT NULL,
    ed25519_verify_key  TEXT NOT NULL,
    key_signature       TEXT NOT NULL,
    registered_at       TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE user_public_keys ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "public_keys_select" ON user_public_keys;
CREATE POLICY "public_keys_select" ON user_public_keys FOR SELECT USING (true);

DROP POLICY IF EXISTS "public_keys_upsert" ON user_public_keys;
CREATE POLICY "public_keys_upsert" ON user_public_keys FOR ALL USING (true);
