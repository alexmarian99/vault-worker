-- Server-side PBKDF2 rounds per user: accounts imported from Vaultwarden keep its 600000,
-- so their existing master password hash still verifies.
ALTER TABLE users ADD COLUMN password_iterations INTEGER NOT NULL DEFAULT 100000;
