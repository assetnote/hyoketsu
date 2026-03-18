package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"hyoketsu/db"

	"github.com/spf13/cobra"
)

var importCmd = &cobra.Command{
	Use:   "import",
	Short: "Step 3/3: Import JSONL into the SQLite database",
	Long:  "Reads JSONL files from " + nugetCrawlDir + "/ and " + nugetHashDir + "/, merges hashes, and bulk-inserts into SQLite",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := db.Open(getDBPath())
		if err != nil {
			return err
		}
		defer store.Close()

		if err := runNugetImport(store); err != nil {
			return err
		}
		printNugetPipeline(3)
		return nil
	},
}

const importBatchSize = 50000

func runNugetImport(store *db.Store) error {
	if err := store.BeginBulkImport(); err != nil {
		return fmt.Errorf("begin bulk import: %w", err)
	}
	defer store.EndBulkImport()

	// First load hashed entries (these have hashes, take priority)
	hashed := make(map[string]db.DLLMatch) // key: dll_name+package_name+version
	hashFiles, _ := filepath.Glob(filepath.Join(nugetHashDir, "hashed_*.jsonl"))
	fmt.Printf("Loading %d hash files...\n", len(hashFiles))
	for _, f := range hashFiles {
		err := streamJSONLFile(f, func(e db.DLLMatch) {
			key := e.DLLName + "|" + e.PackageName + "|" + e.Version
			hashed[key] = e
		})
		if err != nil {
			continue
		}
	}
	fmt.Printf("Loaded %d hashed entries\n", len(hashed))

	// Then load crawl entries, preferring hashed versions
	crawlFiles, _ := filepath.Glob(filepath.Join(nugetCrawlDir, "page_*.jsonl"))
	fmt.Printf("Loading %d crawl files...\n", len(crawlFiles))

	var batch []db.DLLMatch
	var pendingFiles []string // files whose entries are in the current batch
	total := 0
	skipped := 0

	flushBatch := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := store.InsertDLLBatch(batch); err != nil {
			return fmt.Errorf("insert batch: %w", err)
		}
		total += len(batch)
		fmt.Printf("Imported %d entries\n", total)
		for _, name := range pendingFiles {
			store.MarkFileImported(name)
		}
		batch = batch[:0]
		pendingFiles = pendingFiles[:0]
		return nil
	}

	for _, f := range crawlFiles {
		base := filepath.Base(f)
		if store.IsFileImported(base) {
			skipped++
			continue
		}

		streamJSONLFile(f, func(e db.DLLMatch) {
			key := e.DLLName + "|" + e.PackageName + "|" + e.Version
			if h, ok := hashed[key]; ok {
				e.Hash = h.Hash
				delete(hashed, key)
			}
			batch = append(batch, e)
		})
		pendingFiles = append(pendingFiles, base)

		if len(batch) >= importBatchSize {
			if err := flushBatch(); err != nil {
				return err
			}
		}
	}

	if skipped > 0 {
		fmt.Printf("Skipped %d already-imported crawl files\n", skipped)
	}

	// Flush remaining crawl entries
	if err := flushBatch(); err != nil {
		return err
	}

	// Insert any remaining hashed entries not in crawl files
	for _, e := range hashed {
		batch = append(batch, e)
		if len(batch) >= importBatchSize {
			if err := store.InsertDLLBatch(batch); err != nil {
				return fmt.Errorf("insert hashed batch: %w", err)
			}
			total += len(batch)
			batch = batch[:0]
		}
	}

	if len(batch) > 0 {
		if err := store.InsertDLLBatch(batch); err != nil {
			return fmt.Errorf("insert final batch: %w", err)
		}
		total += len(batch)
	}

	// Update cursor from crawl
	cursorData, err := os.ReadFile(filepath.Join(nugetCrawlDir, "cursor.txt"))
	if err == nil && len(cursorData) > 0 {
		store.SetCursor(string(cursorData))
	}

	fmt.Printf("Imported %d NuGet entries.\n", total)
	return nil
}

func streamJSONLFile(path string, fn func(db.DLLMatch)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	for dec.More() {
		var e db.DLLMatch
		if err := dec.Decode(&e); err != nil {
			break
		}
		fn(e)
	}
	return nil
}
