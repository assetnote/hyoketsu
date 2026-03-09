package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"

	_ "modernc.org/sqlite"
)

const importBatchSize = 50000

func flushBatch(ctx context.Context, ch *CHStore, table string, batch [][]interface{}, total int) error {
	if len(batch) == 0 {
		return nil
	}
	tx, err := ch.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, fmt.Sprintf(`INSERT INTO %s (dll_name, source, package_name, version, hash) VALUES (?, ?, ?, ?, ?)`, table))
	if err != nil {
		return fmt.Errorf("prepare: %w", err)
	}
	defer stmt.Close()

	for _, row := range batch {
		if _, err := stmt.ExecContext(ctx, row...); err != nil {
			return fmt.Errorf("insert: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	log.Printf("imported %d rows into %s...", total, table)
	return nil
}

func importFromSQLite(ctx context.Context, ch *CHStore, sqlitePath string) error {
	sdb, err := sql.Open("sqlite", sqlitePath)
	if err != nil {
		return fmt.Errorf("open sqlite: %w", err)
	}
	defer sdb.Close()

	// Import from both tables if they exist
	for _, src := range []struct {
		table string
		dest  string
	}{
		{"known_dlls", "known_dlls"},
		{"known_jars", "known_jars"},
	} {
		// Check if source table exists
		var name string
		err := sdb.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, src.table).Scan(&name)
		if err != nil {
			continue // table doesn't exist, skip
		}

		rows, err := sdb.Query(fmt.Sprintf(`SELECT dll_name, source, package_name, version, hash FROM %s`, src.table))
		if err != nil {
			return fmt.Errorf("query sqlite %s: %w", src.table, err)
		}

		batch := make([][]interface{}, 0, importBatchSize)
		total := 0

		for rows.Next() {
			var dllName, source string
			var packageName, version, hash sql.NullString

			if err := rows.Scan(&dllName, &source, &packageName, &version, &hash); err != nil {
				rows.Close()
				return fmt.Errorf("scan row: %w", err)
			}

			pkg := ""
			if packageName.Valid {
				pkg = packageName.String
			}
			ver := ""
			if version.Valid {
				ver = version.String
			}
			h := ""
			if hash.Valid {
				h = hash.String
			}

			batch = append(batch, []interface{}{dllName, source, pkg, ver, h})
			total++

			if len(batch) >= importBatchSize {
				if err := flushBatch(ctx, ch, src.dest, batch, total); err != nil {
					rows.Close()
					return err
				}
				batch = batch[:0]
			}
		}

		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("iterate rows: %w", err)
		}
		rows.Close()

		if err := flushBatch(ctx, ch, src.dest, batch, total); err != nil {
			return err
		}

		log.Printf("sqlite import from %s complete: %d total rows -> %s", src.table, total, src.dest)
	}

	return nil
}

type jsonlEntry struct {
	DLLName     string `json:"dll_name"`
	Source      string `json:"source"`
	PackageName string `json:"package_name"`
	Version     string `json:"version"`
	Hash        string `json:"hash"`
}

func tableForSource(source string) string {
	if source == "maven" {
		return "known_jars"
	}
	return "known_dlls"
}

func importFromJSONLDir(ctx context.Context, ch *CHStore, dir string) error {
	files, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil {
		return fmt.Errorf("glob %s: %w", dir, err)
	}
	sort.Strings(files)

	dllBatch := make([][]interface{}, 0, importBatchSize)
	jarBatch := make([][]interface{}, 0, importBatchSize)
	dllTotal := 0
	jarTotal := 0

	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			return fmt.Errorf("open %s: %w", f, err)
		}

		scanner := bufio.NewScanner(fh)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
		for scanner.Scan() {
			var e jsonlEntry
			if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
				fh.Close()
				return fmt.Errorf("parse %s: %w", f, err)
			}

			row := []interface{}{e.DLLName, e.Source, e.PackageName, e.Version, e.Hash}
			if e.Source == "maven" {
				jarBatch = append(jarBatch, row)
				jarTotal++
				if len(jarBatch) >= importBatchSize {
					if err := flushBatch(ctx, ch, "known_jars", jarBatch, jarTotal); err != nil {
						fh.Close()
						return err
					}
					jarBatch = jarBatch[:0]
				}
			} else {
				dllBatch = append(dllBatch, row)
				dllTotal++
				if len(dllBatch) >= importBatchSize {
					if err := flushBatch(ctx, ch, "known_dlls", dllBatch, dllTotal); err != nil {
						fh.Close()
						return err
					}
					dllBatch = dllBatch[:0]
				}
			}
		}
		fh.Close()
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("read %s: %w", f, err)
		}
	}

	if err := flushBatch(ctx, ch, "known_dlls", dllBatch, dllTotal); err != nil {
		return err
	}
	if err := flushBatch(ctx, ch, "known_jars", jarBatch, jarTotal); err != nil {
		return err
	}

	log.Printf("jsonl import from %s complete: %d dlls, %d jars", dir, dllTotal, jarTotal)
	return nil
}

// importNuGetData loads hash data into a map, then imports crawl entries
// with hashes merged in. NuGet data always goes to known_dlls.
func importNuGetData(ctx context.Context, ch *CHStore, dataDir string) error {
	crawlDir := filepath.Join(dataDir, "crawl")
	hashDir := filepath.Join(dataDir, "hashes")

	// Phase 1: build hash lookup from hash files
	hashMap := make(map[string]string)
	if _, err := os.Stat(hashDir); err == nil {
		files, _ := filepath.Glob(filepath.Join(hashDir, "*.jsonl"))
		sort.Strings(files)
		for _, f := range files {
			fh, err := os.Open(f)
			if err != nil {
				continue
			}
			sc := bufio.NewScanner(fh)
			sc.Buffer(make([]byte, 1024*1024), 1024*1024)
			for sc.Scan() {
				var e jsonlEntry
				if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
					continue
				}
				if e.Hash != "" {
					key := e.DLLName + "|" + e.PackageName + "|" + e.Version
					hashMap[key] = e.Hash
				}
			}
			fh.Close()
		}
		log.Printf("loaded %d hashes from %s", len(hashMap), hashDir)
	}

	// Phase 2: import crawl entries, merging hashes where available
	if _, err := os.Stat(crawlDir); err != nil {
		return fmt.Errorf("crawl dir not found: %s", crawlDir)
	}

	files, err := filepath.Glob(filepath.Join(crawlDir, "*.jsonl"))
	if err != nil {
		return fmt.Errorf("glob %s: %w", crawlDir, err)
	}
	sort.Strings(files)

	batch := make([][]interface{}, 0, importBatchSize)
	total := 0
	withHash := 0

	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			return fmt.Errorf("open %s: %w", f, err)
		}

		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1024*1024), 1024*1024)
		for sc.Scan() {
			var e jsonlEntry
			if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
				fh.Close()
				return fmt.Errorf("parse %s: %w", f, err)
			}

			if e.Hash == "" {
				key := e.DLLName + "|" + e.PackageName + "|" + e.Version
				if h, ok := hashMap[key]; ok {
					e.Hash = h
					withHash++
				}
			}

			batch = append(batch, []interface{}{e.DLLName, e.Source, e.PackageName, e.Version, e.Hash})
			total++

			if len(batch) >= importBatchSize {
				if err := flushBatch(ctx, ch, "known_dlls", batch, total); err != nil {
					fh.Close()
					return err
				}
				batch = batch[:0]
			}
		}
		fh.Close()
		if err := sc.Err(); err != nil {
			return fmt.Errorf("read %s: %w", f, err)
		}
	}

	if err := flushBatch(ctx, ch, "known_dlls", batch, total); err != nil {
		return err
	}

	log.Printf("nuget import complete: %d rows (%d with hash)", total, withHash)
	return nil
}
