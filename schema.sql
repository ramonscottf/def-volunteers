-- def-volunteers D1 schema
-- Unified volunteer registry across all Davis Education Foundation events.

CREATE TABLE IF NOT EXISTS volunteers (
  id TEXT PRIMARY KEY,
  event_slug TEXT NOT NULL,
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  email TEXT NOT NULL,
  phone TEXT,
  organization TEXT,
  group_type TEXT,
  group_size INTEGER DEFAULT 1,
  shirt_size TEXT,
  role TEXT,
  location TEXT,
  shift TEXT,
  arrival_time TEXT,
  early_arrival INTEGER DEFAULT 0,
  experience TEXT,
  hear_about TEXT,
  sms_opt_in INTEGER DEFAULT 0,
  notes TEXT,
  status TEXT DEFAULT 'pending',
  event_data TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_vol_event ON volunteers(event_slug);
CREATE INDEX IF NOT EXISTS idx_vol_email ON volunteers(email);
CREATE INDEX IF NOT EXISTS idx_vol_status ON volunteers(status);
CREATE INDEX IF NOT EXISTS idx_vol_created ON volunteers(created_at);

CREATE TABLE IF NOT EXISTS events (
  slug TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  tagline TEXT,
  description TEXT,
  event_date TEXT,
  venue TEXT,
  signup_url TEXT,
  hero_image TEXT,
  icon TEXT,
  accent_color TEXT,
  active INTEGER DEFAULT 1,
  show_on_hub INTEGER DEFAULT 1,
  capacity INTEGER,
  display_order INTEGER DEFAULT 0,
  config TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS blasts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_slug TEXT,
  type TEXT NOT NULL,
  subject TEXT,
  message TEXT,
  recipient_count INTEGER,
  filter_snapshot TEXT,
  sent_at TEXT DEFAULT (datetime('now')),
  sent_by TEXT
);

CREATE TABLE IF NOT EXISTS assignments (
  id TEXT PRIMARY KEY,
  event_slug TEXT NOT NULL,
  volunteer_id TEXT NOT NULL,
  nomination_id TEXT,
  role_detail TEXT,
  assigned_at TEXT DEFAULT (datetime('now')),
  checked_out INTEGER DEFAULT 0,
  checkout_at TEXT,
  FOREIGN KEY (volunteer_id) REFERENCES volunteers(id)
);
