-- Clients (2026+) assign an id to the user key once and post it back.
ALTER TABLE users ADD COLUMN key_id TEXT;
