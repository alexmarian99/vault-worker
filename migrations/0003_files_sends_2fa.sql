-- Attachments (files in R2 under attachments/<cipher>/<id>), Sends, and TOTP two-factor.
CREATE TABLE attachments (
  id TEXT PRIMARY KEY,
  cipher_id TEXT NOT NULL REFERENCES ciphers(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  file_name TEXT NOT NULL,             -- encrypted by the client
  file_size INTEGER NOT NULL,
  akey TEXT,                           -- the file's key, wrapped by the client
  uploaded INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX attachments_user ON attachments(user_id);

CREATE TABLE sends (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type INTEGER NOT NULL,               -- 0 text, 1 file
  name TEXT NOT NULL,
  notes TEXT,
  data TEXT NOT NULL,
  akey TEXT NOT NULL,
  password_hash TEXT,
  password_salt TEXT,
  max_access_count INTEGER,
  access_count INTEGER NOT NULL DEFAULT 0,
  expiration_date TEXT,
  deletion_date TEXT NOT NULL,
  disabled INTEGER NOT NULL DEFAULT 0,
  hide_email INTEGER NOT NULL DEFAULT 0,
  emails TEXT,
  revision_date TEXT NOT NULL
);
CREATE INDEX sends_user ON sends(user_id);

CREATE TABLE twofactors (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type INTEGER NOT NULL,               -- 0 authenticator (TOTP)
  data TEXT NOT NULL,                  -- the base32 secret
  enabled INTEGER NOT NULL DEFAULT 0,
  last_used INTEGER NOT NULL DEFAULT 0, -- last accepted 30 s step, so a code can't be replayed
  PRIMARY KEY (user_id, type)
);

ALTER TABLE users ADD COLUMN totp_recover TEXT;
ALTER TABLE devices ADD COLUMN twofactor_remember TEXT;
