package db

import (
	"database/sql"
	"fmt"
)

const schema = `
CREATE TABLE IF NOT EXISTS known_dlls (
    id INTEGER PRIMARY KEY,
    dll_name TEXT NOT NULL,
    source TEXT NOT NULL,
    package_name TEXT,
    version TEXT,
    hash TEXT,
    UNIQUE(dll_name, source, version, hash)
);
CREATE INDEX IF NOT EXISTS idx_dll_name ON known_dlls(dll_name);
CREATE INDEX IF NOT EXISTS idx_dll_hash ON known_dlls(hash);

CREATE TABLE IF NOT EXISTS known_jars (
    id INTEGER PRIMARY KEY,
    dll_name TEXT NOT NULL,
    source TEXT NOT NULL,
    package_name TEXT,
    version TEXT,
    hash TEXT,
    UNIQUE(dll_name, source, version, hash)
);
CREATE INDEX IF NOT EXISTS idx_jar_name ON known_jars(dll_name);
CREATE INDEX IF NOT EXISTS idx_jar_hash ON known_jars(hash);

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
`

func Migrate(db *sql.DB) error {
	_, err := db.Exec(schema)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}
