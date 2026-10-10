-- Bondam Run: accounts. Run with `wrangler d1 migrations apply` (the deploy script does this).
-- Later migrations (0002_..., 0003_...) will add leaderboard, progress and challenges
-- tables that reference users(id).

CREATE TABLE IF NOT EXISTS users (
  id             TEXT PRIMARY KEY,            -- random 128-bit id (hex), never reused
  username       TEXT NOT NULL,               -- as typed, shown to other players
  username_lc    TEXT NOT NULL UNIQUE,        -- lower-case copy: case-insensitive uniqueness
  pw_salt        TEXT NOT NULL,               -- random per-user salt (hex)
  pw_hash        TEXT NOT NULL,               -- HMAC(pepper, salt:client_hash) (hex)
  pw_algo        TEXT NOT NULL DEFAULT 'h1',  -- lets us upgrade the scheme later without a reset
  token_version  INTEGER NOT NULL DEFAULT 0,  -- bump to sign a user out everywhere
  created_at     INTEGER NOT NULL,            -- unix seconds
  last_login_at  INTEGER
);

-- Failed-login / registration counters (brute-force protection).
CREATE TABLE IF NOT EXISTS throttle (
  key        TEXT PRIMARY KEY,                -- e.g. "login:u:alice", "login:ip:1.2.3.4"
  n          INTEGER NOT NULL,
  win_start  INTEGER NOT NULL
);
