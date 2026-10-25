-- Users, their devices (one refresh token each), folders and ciphers.
-- Everything a client sends is already encrypted; the server never sees plaintext.
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  name TEXT,
  password_hash TEXT NOT NULL,        -- server-side PBKDF2 of the client's master password hash
  password_salt TEXT NOT NULL,
  password_hint TEXT,
  akey TEXT NOT NULL,                 -- user key wrapped by the master key
  private_key TEXT,
  public_key TEXT,
  kdf INTEGER NOT NULL,
  kdf_iterations INTEGER NOT NULL,
  kdf_memory INTEGER,
  kdf_parallelism INTEGER,
  security_stamp TEXT NOT NULL,
  avatar_color TEXT,
  equivalent_domains TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  revision_date INTEGER NOT NULL
);

CREATE TABLE devices (
  id TEXT PRIMARY KEY,                -- the client's device identifier
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT,
  type INTEGER,
  refresh_token TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE folders (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE ciphers (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  folder_id TEXT,
  type INTEGER NOT NULL,
  name TEXT,
  notes TEXT,
  key TEXT,
  reprompt INTEGER NOT NULL DEFAULT 0,
  favorite INTEGER NOT NULL DEFAULT 0,
  data TEXT NOT NULL,                 -- the type-specific object (login, card, ...), as sent
  fields TEXT,
  password_history TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  deleted_at TEXT,
  archived_at TEXT
);
CREATE INDEX ciphers_user ON ciphers(user_id);
CREATE INDEX folders_user ON folders(user_id);
CREATE INDEX devices_user ON devices(user_id);
