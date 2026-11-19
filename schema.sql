CREATE TABLE IF NOT EXISTS groups (id TEXT PRIMARY KEY, name TEXT NOT NULL, parent TEXT NOT NULL DEFAULT '', leaders TEXT NOT NULL DEFAULT '[]', updated_at INTEGER NOT NULL, deleted INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS members (id TEXT PRIMARY KEY, name TEXT NOT NULL, phone TEXT NOT NULL DEFAULT '', group_id TEXT NOT NULL DEFAULT '', subgroup_id TEXT NOT NULL DEFAULT '', role TEXT NOT NULL DEFAULT 'member', joined_meeting TEXT, created_at INTEGER, updated_at INTEGER NOT NULL, deleted INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS meetings (id TEXT PRIMARY KEY, title TEXT NOT NULL, date TEXT NOT NULL, created_at INTEGER NOT NULL, ended_at INTEGER, total_at_end INTEGER, updated_at INTEGER NOT NULL, deleted INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS checkins (meeting_id TEXT NOT NULL, member_id TEXT NOT NULL, at INTEGER, updated_at INTEGER NOT NULL, deleted INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (meeting_id, member_id));
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT, updated_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS groups_u ON groups(updated_at);
CREATE INDEX IF NOT EXISTS members_u ON members(updated_at);
CREATE INDEX IF NOT EXISTS meetings_u ON meetings(updated_at);
CREATE INDEX IF NOT EXISTS checkins_u ON checkins(updated_at);
