-- Run once in Supabase SQL Editor to create the required table and storage bucket.

-- 1. files_metadata table (recreate to ensure all phase 2 columns exist)
DROP TABLE IF EXISTS files_metadata CASCADE;

CREATE TABLE files_metadata (
    file_id          TEXT PRIMARY KEY,
    original_filename TEXT NOT NULL,
    owner_email      TEXT NOT NULL,
    receiver_email   TEXT NOT NULL,
    version          INTEGER NOT NULL DEFAULT 1,
    sender_x25519_pub TEXT NOT NULL,
    mlkem_ciphertext  TEXT NOT NULL,
    fragment_manifest JSONB NOT NULL,
    version_chain_hash TEXT NOT NULL DEFAULT '',
    prev_version_hash  TEXT NOT NULL DEFAULT '',
    manifest_merkle_root TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ DEFAULT NOW(),
    updated_at       TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Enable RLS (optional, we enforce ACL in app layer)
ALTER TABLE files_metadata ENABLE ROW LEVEL SECURITY;

-- 3. Storage bucket (create via Supabase Dashboard or API)
-- INSERT INTO storage.buckets (id, name, public) VALUES ('encrypted-fragments', 'encrypted-fragments', false);
