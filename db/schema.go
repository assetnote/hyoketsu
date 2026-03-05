package db

import (
	"database/sql"
	"fmt"
	"strings"
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

	// Add columns if upgrading from old schema (known_dlls)
	db.Exec("ALTER TABLE known_dlls ADD COLUMN hash TEXT")
	db.Exec("ALTER TABLE known_dlls ADD COLUMN version TEXT")

	// Handle known_dlls_old from prior unique-constraint migration
	var oldExists bool
	db.QueryRow(`SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='known_dlls_old'`).Scan(&oldExists)
	if oldExists {
		// Move maven rows to known_jars, rest to known_dlls, drop old
		db.Exec(`INSERT OR IGNORE INTO known_jars (dll_name, source, package_name, version, hash)
			SELECT dll_name, source, package_name, version, hash FROM known_dlls_old WHERE source = 'maven'`)
		db.Exec(`INSERT OR IGNORE INTO known_dlls (dll_name, source, package_name, version, hash)
			SELECT dll_name, source, package_name, version, hash FROM known_dlls_old WHERE source != 'maven'`)
		db.Exec("DROP TABLE known_dlls_old")
	}

	// Migrate unique constraint (legacy schemas used package_name in unique key)
	var tableSql string
	row := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='known_dlls'`)
	if row.Scan(&tableSql) == nil {
		needsMigration := strings.Contains(tableSql, "UNIQUE(dll_name, source, package_name")
		if needsMigration {
			db.Exec("ALTER TABLE known_dlls RENAME TO known_dlls_migrate")
			db.Exec(schema)
			db.Exec(`INSERT OR IGNORE INTO known_jars (dll_name, source, package_name, version, hash)
				SELECT dll_name, source, package_name, version, hash FROM known_dlls_migrate WHERE source = 'maven'`)
			db.Exec(`INSERT OR IGNORE INTO known_dlls (dll_name, source, package_name, version, hash)
				SELECT dll_name, source, package_name, version, hash FROM known_dlls_migrate WHERE source != 'maven'`)
			db.Exec("DROP TABLE known_dlls_migrate")
			return nil
		}
	}

	// Split: move maven rows from known_dlls to known_jars if they still exist there
	var mavenCount int
	db.QueryRow(`SELECT COUNT(*) FROM known_dlls WHERE source = 'maven'`).Scan(&mavenCount)
	if mavenCount > 0 {
		db.Exec(`INSERT OR IGNORE INTO known_jars (dll_name, source, package_name, version, hash)
			SELECT dll_name, source, package_name, version, hash FROM known_dlls WHERE source = 'maven'`)
		db.Exec(`DELETE FROM known_dlls WHERE source = 'maven'`)
	}

	return nil
}
