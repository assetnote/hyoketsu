package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"hyoketsu/db"
	"hyoketsu/scanner"

	"github.com/spf13/cobra"
)

var (
	extractDotnetOnly bool
	extractDedup      bool
	extractFlat       bool
)

var extractCmd = &cobra.Command{
	Use:   "extract <source> <dest>",
	Short: "Copy unknown files to a separate directory for decompilation",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		source := cleanPath(args[0])
		dest := cleanPath(args[1])

		store, err := db.Open(getDBPath())
		if err != nil {
			return err
		}
		defer store.Close()

		results, err := scanner.Scan(store, source)
		if err != nil {
			return err
		}

		var extracted, skippedKnown, skippedDupe int

		for _, r := range results {
			if r.Status == "Known" {
				skippedKnown++
				continue
			}
			if extractDotnetOnly && !r.IsDotNet {
				continue
			}
			if extractDedup && r.Duplicate {
				skippedDupe++
				continue
			}

			var destPath string
			if extractFlat {
				destPath = filepath.Join(dest, r.Filename)
			} else {
				// Preserve subdirectory structure relative to source
				rel, err := filepath.Rel(source, r.Path)
				if err != nil {
					rel = r.Filename
				}
				destPath = filepath.Join(dest, rel)
			}

			if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
				return fmt.Errorf("create directory: %w", err)
			}

			if err := copyFile(r.Path, destPath); err != nil {
				return fmt.Errorf("copy %s: %w", r.Filename, err)
			}
			extracted++
		}

		fmt.Printf("%d files extracted, %d skipped (known), %d skipped (duplicate)\n",
			extracted, skippedKnown, skippedDupe)
		return nil
	},
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

func init() {
	extractCmd.Flags().BoolVar(&extractDotnetOnly, "dotnet-only", false, "Only extract .NET assemblies (skip native DLLs)")
	extractCmd.Flags().BoolVar(&extractDedup, "dedup", false, "Skip duplicate files (by SHA256 hash)")
	extractCmd.Flags().BoolVar(&extractFlat, "flat", false, "Flatten into single directory (default: preserve subdirectory structure)")
}
