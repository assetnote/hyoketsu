package cmd

import (
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
