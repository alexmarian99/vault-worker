-- Vaultwarden (SQLite) schema, tables only, no data. Used by test/import.mjs.
CREATE TABLE __diesel_schema_migrations (
       version VARCHAR(50) PRIMARY KEY NOT NULL,
       run_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE archives (
    user_uuid   CHAR(36) NOT NULL REFERENCES users (uuid) ON DELETE CASCADE,
    cipher_uuid CHAR(36) NOT NULL REFERENCES ciphers (uuid) ON DELETE CASCADE,
    archived_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_uuid, cipher_uuid)
);
CREATE TABLE attachments (
  id          TEXT    NOT NULL PRIMARY KEY,
  cipher_uuid TEXT    NOT NULL REFERENCES ciphers (uuid),
  file_name   TEXT    NOT NULL,
  file_size   INTEGER NOT NULL

, akey TEXT);
CREATE TABLE "auth_requests" (
    uuid                        TEXT NOT NULL PRIMARY KEY,
    user_uuid                   TEXT NOT NULL,
    organization_uuid           TEXT,
    request_device_identifier   TEXT NOT NULL,
    device_type                 INTEGER NOT NULL,
    request_ip                  TEXT NOT NULL,
    response_device_id          TEXT,
    access_code                 TEXT NOT NULL,
    public_key                  TEXT NOT NULL,
    enc_key                     TEXT,
    master_password_hash        TEXT,
    approved                    BOOLEAN,
    creation_date               DATETIME NOT NULL,
    response_date               DATETIME,
    authentication_date         DATETIME,
    FOREIGN KEY (user_uuid) REFERENCES users (uuid),
    FOREIGN KEY (organization_uuid) REFERENCES organizations (uuid)
);
CREATE TABLE "ciphers"(
  uuid              TEXT     NOT NULL PRIMARY KEY,
  created_at        DATETIME NOT NULL,
  updated_at        DATETIME NOT NULL,
  user_uuid         TEXT     REFERENCES users(uuid),
  organization_uuid TEXT     REFERENCES organizations(uuid),
  atype             INTEGER  NOT NULL,
  name              TEXT     NOT NULL,
  notes             TEXT,
  fields            TEXT,
  data              TEXT     NOT NULL,
  password_history  TEXT,
  deleted_at        DATETIME
, reprompt INTEGER, "key" TEXT);
CREATE TABLE ciphers_collections (
  cipher_uuid       TEXT NOT NULL REFERENCES ciphers (uuid),
  collection_uuid TEXT NOT NULL REFERENCES collections (uuid),
  PRIMARY KEY (cipher_uuid, collection_uuid)
);
CREATE TABLE collections (
  uuid     TEXT NOT NULL PRIMARY KEY,
  org_uuid TEXT NOT NULL REFERENCES organizations (uuid),
  name     TEXT NOT NULL
, external_id TEXT);
CREATE TABLE collections_groups (
  collections_uuid                  TEXT NOT NULL REFERENCES collections (uuid),
  groups_uuid                       TEXT NOT NULL REFERENCES groups (uuid),
  read_only                         BOOLEAN NOT NULL,
  hide_passwords                    BOOLEAN NOT NULL, manage BOOLEAN NOT NULL DEFAULT 0,
  UNIQUE (collections_uuid, groups_uuid)
);
CREATE TABLE "devices" (
	uuid	TEXT NOT NULL,
	created_at	DATETIME NOT NULL,
	updated_at	DATETIME NOT NULL,
	user_uuid	TEXT NOT NULL,
	name	TEXT NOT NULL,
	atype	INTEGER NOT NULL,
	push_token	TEXT,
	refresh_token	TEXT NOT NULL,
	twofactor_remember	TEXT, push_uuid TEXT,
	PRIMARY KEY(uuid, user_uuid),
	FOREIGN KEY(user_uuid) REFERENCES users(uuid)
);
CREATE TABLE emergency_access (
  uuid                      TEXT     NOT NULL PRIMARY KEY,
  grantor_uuid              TEXT     REFERENCES users (uuid),
  grantee_uuid              TEXT     REFERENCES users (uuid),
  email                     TEXT,
  key_encrypted             TEXT,
  atype                     INTEGER  NOT NULL,
  status                    INTEGER  NOT NULL,
  wait_time_days            INTEGER  NOT NULL,
  recovery_initiated_at     DATETIME,
  last_notification_at      DATETIME,
  updated_at                DATETIME NOT NULL,
  created_at                DATETIME NOT NULL
);
CREATE TABLE event (
  uuid               TEXT        NOT NULL PRIMARY KEY,
  event_type         INTEGER     NOT NULL,
  user_uuid          TEXT,
  org_uuid           TEXT,
  cipher_uuid        TEXT,
  collection_uuid    TEXT,
  group_uuid         TEXT,
  org_user_uuid      TEXT,
  act_user_uuid      TEXT,
  device_type        INTEGER,
  ip_address         TEXT,
  event_date         DATETIME    NOT NULL,
  policy_uuid        TEXT,
  provider_uuid      TEXT,
  provider_user_uuid TEXT,
  provider_org_uuid  TEXT,
  UNIQUE (uuid)
);
CREATE TABLE favorites (
  user_uuid   TEXT NOT NULL REFERENCES users(uuid),
  cipher_uuid TEXT NOT NULL REFERENCES ciphers(uuid),

  PRIMARY KEY (user_uuid, cipher_uuid)
);
CREATE TABLE folders (
  uuid       TEXT     NOT NULL PRIMARY KEY,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  user_uuid  TEXT     NOT NULL REFERENCES users (uuid),
  name       TEXT     NOT NULL
);
CREATE TABLE folders_ciphers (
  cipher_uuid TEXT NOT NULL REFERENCES ciphers (uuid),
  folder_uuid TEXT NOT NULL REFERENCES folders (uuid),

  PRIMARY KEY (cipher_uuid, folder_uuid)
);
CREATE TABLE groups (
  uuid                              TEXT NOT NULL PRIMARY KEY,
  organizations_uuid                TEXT NOT NULL REFERENCES organizations (uuid),
  name                              TEXT NOT NULL,
  access_all                        BOOLEAN NOT NULL,
  external_id                       TEXT NULL,
  creation_date                     TIMESTAMP NOT NULL,
  revision_date                     TIMESTAMP NOT NULL
);
CREATE TABLE groups_users (
  groups_uuid                       TEXT NOT NULL REFERENCES groups (uuid),
  users_organizations_uuid          TEXT NOT NULL REFERENCES users_organizations (uuid),
  UNIQUE (groups_uuid, users_organizations_uuid)
);
CREATE TABLE invitations (
    email   TEXT NOT NULL PRIMARY KEY
);
CREATE TABLE org_policies (
  uuid      TEXT     NOT NULL PRIMARY KEY,
  org_uuid  TEXT     NOT NULL REFERENCES organizations (uuid),
  atype     INTEGER  NOT NULL,
  enabled   BOOLEAN  NOT NULL,
  data      TEXT     NOT NULL,

  UNIQUE (org_uuid, atype)
);
CREATE TABLE organization_api_key (
	uuid            TEXT NOT NULL,
    org_uuid	    TEXT NOT NULL,
    atype           INTEGER NOT NULL,
    api_key         TEXT NOT NULL,
	revision_date   DATETIME NOT NULL,
	PRIMARY KEY(uuid, org_uuid),
	FOREIGN KEY(org_uuid) REFERENCES organizations(uuid)
);
CREATE TABLE organizations (
  uuid          TEXT NOT NULL PRIMARY KEY,
  name          TEXT NOT NULL,
  billing_email TEXT NOT NULL
, private_key TEXT, public_key TEXT);
CREATE TABLE sends (
  uuid              TEXT NOT NULL   PRIMARY KEY,
  user_uuid         TEXT            REFERENCES users (uuid),
  organization_uuid TEXT            REFERENCES organizations (uuid),

  name              TEXT    NOT NULL,
  notes             TEXT,

  atype             INTEGER NOT NULL,
  data              TEXT    NOT NULL,
  akey               TEXT    NOT NULL,
  password_hash     BLOB,
  password_salt     BLOB,
  password_iter     INTEGER,

  max_access_count  INTEGER,
  access_count      INTEGER NOT NULL,

  creation_date     DATETIME NOT NULL,
  revision_date     DATETIME NOT NULL,
  expiration_date   DATETIME,
  deletion_date     DATETIME NOT NULL,

  disabled          BOOLEAN NOT NULL
, hide_email BOOLEAN);
CREATE TABLE sso_auth (
    state               TEXT NOT NULL PRIMARY KEY,
    client_challenge    TEXT NOT NULL,
    nonce               TEXT NOT NULL,
    redirect_uri        TEXT NOT NULL,
    code_response       TEXT,
    auth_response       TEXT,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
, binding_hash TEXT, code_response_error TEXT);
CREATE TABLE sso_users (
  user_uuid           CHAR(36) NOT NULL PRIMARY KEY,
  identifier          TEXT NOT NULL UNIQUE,
  created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

  FOREIGN KEY(user_uuid) REFERENCES users(uuid) ON UPDATE CASCADE ON DELETE CASCADE
);
CREATE TABLE twofactor (
  uuid      TEXT     NOT NULL PRIMARY KEY,
  user_uuid TEXT     NOT NULL REFERENCES users (uuid),
  atype      INTEGER  NOT NULL,
  enabled   BOOLEAN  NOT NULL,
  data      TEXT     NOT NULL, last_used INTEGER NOT NULL DEFAULT 0,

  UNIQUE (user_uuid, atype)
);
CREATE TABLE twofactor_duo_ctx (
    state      TEXT    NOT NULL,
    user_email TEXT    NOT NULL,
    nonce      TEXT    NOT NULL,
    exp        INTEGER NOT NULL,

    PRIMARY KEY (state)
);
CREATE TABLE twofactor_incomplete (
  user_uuid   TEXT     NOT NULL REFERENCES users(uuid),
  device_uuid TEXT     NOT NULL,
  device_name TEXT     NOT NULL,
  login_time  DATETIME NOT NULL,
  ip_address  TEXT     NOT NULL, device_type INTEGER NOT NULL DEFAULT 14,

  PRIMARY KEY (user_uuid, device_uuid)
);
CREATE TABLE users (
  uuid                TEXT     NOT NULL PRIMARY KEY,
  created_at          DATETIME NOT NULL,
  updated_at          DATETIME NOT NULL,
  email               TEXT     NOT NULL UNIQUE,
  name                TEXT     NOT NULL,
  password_hash       BLOB     NOT NULL,
  salt                BLOB     NOT NULL,
  password_iterations INTEGER  NOT NULL,
  password_hint       TEXT,
  akey                 TEXT     NOT NULL,
  private_key         TEXT,
  public_key          TEXT,
  totp_secret         TEXT,
  totp_recover        TEXT,
  security_stamp      TEXT     NOT NULL,
  equivalent_domains  TEXT     NOT NULL,
  excluded_globals    TEXT     NOT NULL
, client_kdf_type INTEGER NOT NULL DEFAULT 0, client_kdf_iter INTEGER NOT NULL DEFAULT 100000, verified_at DATETIME DEFAULT NULL, last_verifying_at DATETIME DEFAULT NULL, login_verify_count INTEGER NOT NULL DEFAULT 0, email_new TEXT DEFAULT NULL, email_new_token TEXT DEFAULT NULL, enabled BOOLEAN NOT NULL DEFAULT 1, stamp_exception TEXT DEFAULT NULL, api_key TEXT, avatar_color TEXT, client_kdf_memory INTEGER DEFAULT NULL, client_kdf_parallelism INTEGER DEFAULT NULL, external_id TEXT, key_id TEXT);
CREATE TABLE users_collections (
  user_uuid       TEXT NOT NULL REFERENCES users (uuid),
  collection_uuid TEXT NOT NULL REFERENCES collections (uuid), read_only BOOLEAN NOT NULL DEFAULT 0, hide_passwords BOOLEAN NOT NULL DEFAULT 0, manage BOOLEAN NOT NULL DEFAULT 0,
  PRIMARY KEY (user_uuid, collection_uuid)
);
CREATE TABLE users_organizations (
  uuid       TEXT    NOT NULL PRIMARY KEY,
  user_uuid  TEXT    NOT NULL REFERENCES users (uuid),
  org_uuid   TEXT    NOT NULL REFERENCES organizations (uuid),

  access_all BOOLEAN NOT NULL,
  akey        TEXT    NOT NULL,
  status     INTEGER NOT NULL,
  atype       INTEGER NOT NULL, reset_password_key TEXT, "external_id" TEXT, invited_by_email TEXT DEFAULT NULL,

  UNIQUE (user_uuid, org_uuid)
);
