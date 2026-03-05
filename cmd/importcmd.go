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
		store, err := db.Open(db.DefaultDBPath())
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

func runNugetImport(store *db.Store) error {
	// First load hashed entries (these have hashes, take priority)
	hashed := make(map[string]db.DLLMatch) // key: dll_name+package_name+version
	hashFiles, _ := filepath.Glob(filepath.Join(nugetHashDir, "hashed_*.jsonl"))
	fmt.Printf("Loading %d hash files...\n", len(hashFiles))
	for _, f := range hashFiles {
		entries, err := readJSONLFile(f)
		if err != nil {
			continue
		}
		for _, e := range entries {
			key := e.DLLName + "|" + e.PackageName + "|" + e.Version
			hashed[key] = e
		}
	}
	fmt.Printf("Loaded %d hashed entries\n", len(hashed))

	// Then load crawl entries, preferring hashed versions
	crawlFiles, _ := filepath.Glob(filepath.Join(nugetCrawlDir, "page_*.jsonl"))
	fmt.Printf("Loading %d crawl files...\n", len(crawlFiles))

	var batch []db.DLLMatch
	total := 0
	for _, f := range crawlFiles {
		entries, err := readJSONLFile(f)
		if err != nil {
			continue
		}
		for _, e := range entries {
			key := e.DLLName + "|" + e.PackageName + "|" + e.Version
			if h, ok := hashed[key]; ok {
				e.Hash = h.Hash
				delete(hashed, key)
			}
			batch = append(batch, e)
			if len(batch) >= 5000 {
				if err := store.InsertDLLBatch(batch); err != nil {
					return fmt.Errorf("insert batch: %w", err)
				}
				total += len(batch)
				fmt.Printf("Imported %d entries\n", total)
				batch = batch[:0]
			}
		}
	}

	// Insert any remaining hashed entries not in crawl files
	for _, e := range hashed {
		batch = append(batch, e)
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

func readJSONLFile(path string) ([]db.DLLMatch, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var entries []db.DLLMatch
	dec := json.NewDecoder(f)
	for dec.More() {
		var e db.DLLMatch
		if err := dec.Decode(&e); err != nil {
			break
		}
		entries = append(entries, e)
	}
	return entries, nil
}
