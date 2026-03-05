package cmd

import (
	"fmt"

	"hyoketsu/db"
	"hyoketsu/nuget"

	"github.com/spf13/cobra"
)

var crawlNugetWorkers int

var crawlNugetCmd = &cobra.Command{
	Use:   "crawl-nuget",
	Short: "Step 1/3: Crawl NuGet catalog to JSONL",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := db.Open(db.DefaultDBPath())
		if err != nil {
			return err
		}
		defer store.Close()

		client := nuget.NewClient(store, crawlNugetWorkers)
		if err := runNugetCrawl(store, client); err != nil {
			return err
		}
		fmt.Printf("[NuGet] JSONL files in %s/\n", nugetCrawlDir)
		return nil
	},
}

func init() {
	crawlNugetCmd.Flags().IntVar(&crawlNugetWorkers, "workers", 128, "Number of concurrent workers")
}
