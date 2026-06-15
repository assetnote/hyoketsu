package cmd

import (
	"path/filepath"
	"strings"

	"hyoketsu/db"

	"github.com/spf13/cobra"
)

var dbPath string

var rootCmd = &cobra.Command{
	Use:   "hyoketsu",
	Short: "Identify DLL and JAR files against a database of known .NET, NuGet, and Windows libraries",
}

func Execute() error {
	return rootCmd.Execute()
}

// cleanPath strips stray double-quotes and normalises separators on Windows.
// PowerShell wraps space-containing paths in double-quotes when invoking a
// native executable. A trailing backslash (e.g. "C:\path with spaces\") then
// escapes the closing quote, so CommandLineToArgvW delivers the path with a
// literal trailing " character. Trimming quotes and calling filepath.Clean
// produces the intended path regardless of how the shell passed it.
func cleanPath(p string) string {
	p = strings.Trim(p, `"`)
	return filepath.Clean(p)
}

func getDBPath() string {
	if dbPath != "" {
		return dbPath
	}
	return db.DefaultDBPath()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&dbPath, "db", "", "Path to hyoketsu database file (skips auto-download)")

	scanGroup := &cobra.Group{ID: "scan", Title: "Scanning"}
	dbGroup := &cobra.Group{ID: "db", Title: "Database"}

	rootCmd.AddGroup(scanGroup, dbGroup)

	scanCmd.GroupID = "scan"
	extractCmd.GroupID = "scan"
	updateCmd.GroupID = "scan"

	crawlMavenCmd.GroupID = "db"
	crawlNugetCmd.GroupID = "db"
	hashBackfillCmd.GroupID = "db"
	importCmd.GroupID = "db"

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(extractCmd)
	rootCmd.AddCommand(updateCmd)
	rootCmd.AddCommand(statsCmd)
	rootCmd.AddCommand(crawlMavenCmd)
	rootCmd.AddCommand(crawlNugetCmd)
	rootCmd.AddCommand(hashBackfillCmd)
	rootCmd.AddCommand(importCmd)
}
