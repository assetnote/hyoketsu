package cmd

import (
	"fmt"

	"hyoketsu/db"

	"github.com/spf13/cobra"
)

var crawlMavenCmd = &cobra.Command{
	Use:   "crawl-maven",
	Short: "Crawl Maven Central and insert JARs into the database",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := db.Open(db.DefaultDBPath())
		if err != nil {
			return err
		}
		defer store.Close()

		if err := runMavenCrawl(store); err != nil {
			return err
		}

		total, _ := store.TotalCount()
		fmt.Printf("Done. %d entries in database.\n", total)
		return nil
	},
}
