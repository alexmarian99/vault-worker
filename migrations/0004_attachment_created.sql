-- When an upload slot was handed out, so the cleanup can drop slots whose upload never came.
ALTER TABLE attachments ADD COLUMN created_at TEXT;
