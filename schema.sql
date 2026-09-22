CREATE TABLE IF NOT EXISTS issued (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL,
  key TEXT NOT NULL,
  hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_issued_ip ON issued(ip, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_issued_hash ON issued(hash);
