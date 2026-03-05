package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

type Store struct {
	DB *sql.DB
}

type DLLMatch struct {
	DLLName     string `json:"dll_name"`
	Source      string `json:"source"`
	PackageName string `json:"package_name"`
	Version     string `json:"version,omitempty"`
	Hash        string `json:"hash,omitempty"`
}

type SourceStats struct {
	Source string
	Count  int
}

func DefaultDBPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".hyoketsu", "hyoketsu.db")
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	// Enable WAL mode for better concurrent write performance
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("set WAL mode: %w", err)
	}
	// Wait up to 30s for locks instead of failing immediately
	if _, err := db.Exec("PRAGMA busy_timeout=30000"); err != nil {
		db.Close()
		return nil, fmt.Errorf("set busy timeout: %w", err)
	}
	// Memory-map the DB so the OS can cache pages efficiently (up to 1GB)
	db.Exec("PRAGMA mmap_size=1073741824")
	// Increase page cache to 256MB (negative = KB)
	db.Exec("PRAGMA cache_size=-262144")
	if err := Migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{DB: db}, nil
}

func (s *Store) Close() error {
	return s.DB.Close()
}

// BeginBulkImport sets PRAGMAs for fast bulk inserts. Call EndBulkImport when done.
func (s *Store) BeginBulkImport() error {
	for _, pragma := range []string{
		"PRAGMA synchronous=OFF",
		"PRAGMA cache_size=-64000", // 64MB
		"PRAGMA temp_store=MEMORY",
	} {
		if _, err := s.DB.Exec(pragma); err != nil {
			return fmt.Errorf("set %s: %w", pragma, err)
		}
	}
	return nil
}

// EndBulkImport restores safe PRAGMAs after bulk insert.
func (s *Store) EndBulkImport() {
	s.DB.Exec("PRAGMA synchronous=NORMAL")
	s.DB.Exec("PRAGMA cache_size=-2000")
}

// IsFileImported checks if a JSONL file has already been imported.
func (s *Store) IsFileImported(filename string) bool {
	var count int
	s.DB.QueryRow(`SELECT COUNT(*) FROM metadata WHERE key = ?`, "imported:"+filename).Scan(&count)
	return count > 0
}

// MarkFileImported records that a JSONL file has been imported.
func (s *Store) MarkFileImported(filename string) error {
	_, err := s.DB.Exec(
		`INSERT OR IGNORE INTO metadata (key, value) VALUES (?, '1')`, "imported:"+filename,
	)
	return err
}

func tableForType(fileType string) string {
	if fileType == "jar" {
		return "known_jars"
	}
	return "known_dlls"
}

func (s *Store) InsertDLLBatch(entries []DLLMatch) error {
	return s.insertBatch("known_dlls", entries)
}

func (s *Store) InsertJARBatch(entries []DLLMatch) error {
	return s.insertBatch("known_jars", entries)
}

func (s *Store) insertBatch(table string, entries []DLLMatch) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(fmt.Sprintf(`INSERT OR IGNORE INTO %s (dll_name, source, package_name, version, hash) VALUES (?, ?, ?, ?, ?)`, table))
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, e := range entries {
		if _, err := stmt.Exec(e.DLLName, e.Source, e.PackageName, nullIfEmpty(e.Version), nullIfEmpty(e.Hash)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func (s *Store) Lookup(dllName string, fileType string) ([]DLLMatch, error) {
	table := tableForType(fileType)
	rows, err := s.DB.Query(
		fmt.Sprintf(`SELECT dll_name, source, package_name, version, hash FROM %s WHERE dll_name = ?`, table), dllName,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanMatches(rows)
}

func (s *Store) LookupByHash(hash string, fileType string) ([]DLLMatch, error) {
	table := tableForType(fileType)
	rows, err := s.DB.Query(
		fmt.Sprintf(`SELECT dll_name, source, package_name, version, hash FROM %s WHERE hash = ?`, table), hash,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanMatches(rows)
}

// BatchLookupByHash looks up multiple hashes at once, returning a map from hash to matches.
func (s *Store) BatchLookupByHash(hashes []string, fileType string) (map[string][]DLLMatch, error) {
	if len(hashes) == 0 {
		return nil, nil
	}
	table := tableForType(fileType)
	result := make(map[string][]DLLMatch, len(hashes))

	// SQLite has a variable limit; batch in groups of 500
	for i := 0; i < len(hashes); i += 500 {
		end := i + 500
		if end > len(hashes) {
			end = len(hashes)
		}
		batch := hashes[i:end]
		placeholders := make([]string, len(batch))
		args := make([]interface{}, len(batch))
		for j, h := range batch {
			placeholders[j] = "?"
			args[j] = h
		}
		query := fmt.Sprintf(`SELECT dll_name, source, package_name, version, hash FROM %s WHERE hash IN (%s)`,
			table, strings.Join(placeholders, ","))
		rows, err := s.DB.Query(query, args...)
		if err != nil {
			return nil, err
		}
		matches, err := scanMatches(rows)
		rows.Close()
		if err != nil {
			return nil, err
		}
		for _, m := range matches {
			result[m.Hash] = append(result[m.Hash], m)
		}
	}
	return result, nil
}

// BatchLookupByName looks up multiple filenames at once, returning a map from name to matches.
func (s *Store) BatchLookupByName(names []string, fileType string) (map[string][]DLLMatch, error) {
	if len(names) == 0 {
		return nil, nil
	}
	table := tableForType(fileType)
	result := make(map[string][]DLLMatch, len(names))

	for i := 0; i < len(names); i += 500 {
		end := i + 500
		if end > len(names) {
			end = len(names)
		}
		batch := names[i:end]
		placeholders := make([]string, len(batch))
		args := make([]interface{}, len(batch))
		for j, n := range batch {
			placeholders[j] = "?"
			args[j] = n
		}
		query := fmt.Sprintf(`SELECT dll_name, source, package_name, version, hash FROM %s WHERE dll_name IN (%s)`,
			table, strings.Join(placeholders, ","))
		rows, err := s.DB.Query(query, args...)
		if err != nil {
			return nil, err
		}
		matches, err := scanMatches(rows)
		rows.Close()
		if err != nil {
			return nil, err
		}
		for _, m := range matches {
			result[m.DLLName] = append(result[m.DLLName], m)
		}
	}
	return result, nil
}

// HasPackageVersion checks if we already have entries for a given package+version.
func (s *Store) HasPackageVersion(source, packageName, version string) bool {
	table := "known_dlls"
	if source == "maven" {
		table = "known_jars"
	}
	var count int
	s.DB.QueryRow(
		fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE source = ? AND package_name = ? AND version = ?`, table),
		source, packageName, version,
	).Scan(&count)
	return count > 0
}

func (s *Store) NuGetPackagesWithoutHash() ([]DLLMatch, error) {
	rows, err := s.DB.Query(
		`SELECT DISTINCT package_name, version FROM known_dlls WHERE source = 'nuget' AND (hash IS NULL OR hash = '') AND version IS NOT NULL AND version != ''`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var results []DLLMatch
	for rows.Next() {
		var m DLLMatch
		if err := rows.Scan(&m.PackageName, &m.Version); err != nil {
			return nil, err
		}
		results = append(results, m)
	}
	return results, rows.Err()
}

// UpdateHash sets the hash for a specific dll entry.
func (s *Store) UpdateHash(dllName, source, packageName, hash string) error {
	table := "known_dlls"
	if source == "maven" {
		table = "known_jars"
	}
	_, err := s.DB.Exec(
		fmt.Sprintf(`UPDATE %s SET hash = ? WHERE dll_name = ? AND source = ? AND package_name = ?`, table),
		hash, dllName, source, packageName,
	)
	return err
}

func scanMatches(rows *sql.Rows) ([]DLLMatch, error) {
	var matches []DLLMatch
	for rows.Next() {
		var m DLLMatch
		var pkg, version, hash sql.NullString
		if err := rows.Scan(&m.DLLName, &m.Source, &pkg, &version, &hash); err != nil {
			return nil, err
		}
		if pkg.Valid {
			m.PackageName = pkg.String
		}
		if version.Valid {
			m.Version = version.String
		}
		if hash.Valid {
			m.Hash = hash.String
		}
		matches = append(matches, m)
	}
	return matches, rows.Err()
}

func (s *Store) Stats() ([]SourceStats, error) {
	rows, err := s.DB.Query(
		`SELECT source, COUNT(*) FROM known_dlls GROUP BY source
		 UNION ALL
		 SELECT source, COUNT(*) FROM known_jars GROUP BY source
		 ORDER BY source`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	// Aggregate in case same source appears in both tables
	m := make(map[string]int)
	var order []string
	for rows.Next() {
		var source string
		var count int
		if err := rows.Scan(&source, &count); err != nil {
			return nil, err
		}
		if _, exists := m[source]; !exists {
			order = append(order, source)
		}
		m[source] += count
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var stats []SourceStats
	for _, src := range order {
		stats = append(stats, SourceStats{Source: src, Count: m[src]})
	}
	return stats, nil
}

func (s *Store) TotalCount() (int, error) {
	var dllCount, jarCount int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM known_dlls`).Scan(&dllCount); err != nil {
		return 0, err
	}
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM known_jars`).Scan(&jarCount); err != nil {
		return 0, err
	}
	return dllCount + jarCount, nil
}

func (s *Store) GetCursor() (string, error) {
	return s.GetCursorKey("catalog_cursor")
}

func (s *Store) SetCursor(cursor string) error {
	return s.SetCursorKey("catalog_cursor", cursor)
}

func (s *Store) GetCursorKey(key string) (string, error) {
	var value string
	err := s.DB.QueryRow(`SELECT value FROM metadata WHERE key = ?`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

func (s *Store) SetCursorKey(key, value string) error {
	_, err := s.DB.Exec(
		`INSERT INTO metadata (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value,
	)
	return err
}
