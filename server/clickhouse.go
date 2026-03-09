package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/ClickHouse/clickhouse-go/v2"
)

type CHStore struct {
	db *sql.DB
}

type LookupRequest struct {
	Filename string `json:"filename"`
	Hash     string `json:"hash"`
	Type     string `json:"type"` // "dll" or "jar"
}

type LookupResult struct {
	Filename    string `json:"filename"`
	Status      string `json:"status"`       // "Known" or "Unknown"
	MatchedBy   string `json:"matched_by"`   // "filename", "hash", or ""
	Source      string `json:"source"`        // "nuget", "maven", etc.
	PackageName string `json:"package_name"`
}

func NewCHStore(dsn string) (*CHStore, error) {
	db, err := sql.Open("clickhouse", dsn)
	if err != nil {
		return nil, fmt.Errorf("open clickhouse: %w", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping clickhouse: %w", err)
	}
	return &CHStore{db: db}, nil
}

func (s *CHStore) Close() error {
	return s.db.Close()
}

func (s *CHStore) CreateSchema(ctx context.Context) error {
	for _, table := range []string{"known_dlls", "known_jars"} {
		_, err := s.db.ExecContext(ctx, fmt.Sprintf(`
			CREATE TABLE IF NOT EXISTS %s (
				dll_name String,
				source LowCardinality(String),
				package_name String,
				version String,
				hash String
			) ENGINE = MergeTree()
			ORDER BY (dll_name, hash)
			SETTINGS index_granularity = 8192
		`, table))
		if err != nil {
			return fmt.Errorf("create %s: %w", table, err)
		}
	}
	return nil
}

func chTableForType(fileType string) string {
	if fileType == "jar" {
		return "known_jars"
	}
	return "known_dlls"
}

// BulkLookup does a two-phase lookup: first by hash, then by filename for unmatched.
// Requests are split by type so each query hits the appropriate table.
func (s *CHStore) BulkLookup(ctx context.Context, requests []LookupRequest) ([]LookupResult, error) {
	results := make([]LookupResult, len(requests))
	for i, r := range requests {
		results[i] = LookupResult{
			Filename: r.Filename,
			Status:   "Unknown",
		}
	}

	if len(requests) == 0 {
		return results, nil
	}

	// Split indices by table type
	dllIndices := make([]int, 0)
	jarIndices := make([]int, 0)
	for i, r := range requests {
		if r.Type == "jar" {
			jarIndices = append(jarIndices, i)
		} else {
			dllIndices = append(dllIndices, i)
		}
	}

	// Process each type against its table
	for _, group := range []struct {
		table   string
		indices []int
	}{
		{"known_dlls", dllIndices},
		{"known_jars", jarIndices},
	} {
		if len(group.indices) == 0 {
			continue
		}

		// Phase 1: hash lookup
		hashIdx := make(map[string][]int)
		for _, i := range group.indices {
			if requests[i].Hash != "" {
				hashIdx[requests[i].Hash] = append(hashIdx[requests[i].Hash], i)
			}
		}

		uniqueHashes := make([]string, 0, len(hashIdx))
		for h := range hashIdx {
			uniqueHashes = append(uniqueHashes, h)
		}

		if len(uniqueHashes) > 0 {
			hashMatches, err := s.queryByHashes(ctx, group.table, uniqueHashes)
			if err != nil {
				return nil, fmt.Errorf("hash lookup (%s): %w", group.table, err)
			}
			for _, m := range hashMatches {
				for _, idx := range hashIdx[m.Hash] {
					results[idx] = LookupResult{
						Filename:    requests[idx].Filename,
						Status:      "Known",
						MatchedBy:   "hash",
						Source:      m.Source,
						PackageName: m.PackageName,
					}
				}
			}
		}

		// Phase 2: filename lookup for unmatched
		filenameIdx := make(map[string][]int)
		for _, i := range group.indices {
			if results[i].Status == "Unknown" {
				lower := strings.ToLower(requests[i].Filename)
				filenameIdx[lower] = append(filenameIdx[lower], i)
			}
		}

		uniqueFilenames := make([]string, 0, len(filenameIdx))
		for f := range filenameIdx {
			uniqueFilenames = append(uniqueFilenames, f)
		}

		if len(uniqueFilenames) > 0 {
			fnMatches, err := s.queryByFilenames(ctx, group.table, uniqueFilenames)
			if err != nil {
				return nil, fmt.Errorf("filename lookup (%s): %w", group.table, err)
			}
			for _, m := range fnMatches {
				for _, idx := range filenameIdx[m.DLLName] {
					results[idx] = LookupResult{
						Filename:    requests[idx].Filename,
						Status:      "Known",
						MatchedBy:   "filename",
						Source:      m.Source,
						PackageName: m.PackageName,
					}
				}
			}
		}
	}

	return results, nil
}

type chMatch struct {
	DLLName     string
	Source      string
	PackageName string
	Hash        string
}

const queryChunkSize = 2000

func (s *CHStore) queryByFilenames(ctx context.Context, table string, filenames []string) ([]chMatch, error) {
	var all []chMatch
	for i := 0; i < len(filenames); i += queryChunkSize {
		end := i + queryChunkSize
		if end > len(filenames) {
			end = len(filenames)
		}
		chunk := filenames[i:end]

		placeholders := make([]string, len(chunk))
		args := make([]interface{}, len(chunk))
		for j, f := range chunk {
			placeholders[j] = "?"
			args[j] = f
		}

		query := fmt.Sprintf(
			`SELECT dll_name, source, package_name FROM %s WHERE dll_name IN (%s) LIMIT 1 BY dll_name`,
			table, strings.Join(placeholders, ","),
		)

		rows, err := s.db.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var m chMatch
			if err := rows.Scan(&m.DLLName, &m.Source, &m.PackageName); err != nil {
				rows.Close()
				return nil, err
			}
			all = append(all, m)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return all, nil
}

func (s *CHStore) queryByHashes(ctx context.Context, table string, hashes []string) ([]chMatch, error) {
	var all []chMatch
	for i := 0; i < len(hashes); i += queryChunkSize {
		end := i + queryChunkSize
		if end > len(hashes) {
			end = len(hashes)
		}
		chunk := hashes[i:end]

		placeholders := make([]string, len(chunk))
		args := make([]interface{}, len(chunk))
		for j, h := range chunk {
			placeholders[j] = "?"
			args[j] = h
		}

		query := fmt.Sprintf(
			`SELECT dll_name, source, package_name, hash FROM %s WHERE hash != '' AND hash IN (%s) LIMIT 1 BY hash`,
			table, strings.Join(placeholders, ","),
		)

		rows, err := s.db.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var m chMatch
			if err := rows.Scan(&m.DLLName, &m.Source, &m.PackageName, &m.Hash); err != nil {
				rows.Close()
				return nil, err
			}
			all = append(all, m)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return all, nil
}

func (s *CHStore) Stats(ctx context.Context) (map[string]int64, error) {
	stats := make(map[string]int64)
	for _, table := range []string{"known_dlls", "known_jars"} {
		rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`SELECT source, count() FROM %s GROUP BY source`, table))
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var source string
			var count int64
			if err := rows.Scan(&source, &count); err != nil {
				rows.Close()
				return nil, err
			}
			stats[source] += count
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return stats, nil
}
