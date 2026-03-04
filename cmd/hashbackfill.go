package cmd

import (
	"hyoketsu/db"
	"hyoketsu/nuget"

	"github.com/spf13/cobra"
)

var hashWorkers int

var hashBackfillCmd = &cobra.Command{
	Use:   "hash-backfill",
	Short: "Step 2/3: Download nupkgs, compute SHA256 hashes",
	Long:  "Reads crawl JSONL files from " + nugetCrawlDir + "/, downloads nupkgs, hashes DLLs, writes results to " + nugetHashDir + "/",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := db.Open(db.DefaultDBPath())
		if err != nil {
			return err
		}
		defer store.Close()

		client := nuget.NewClient(store, hashWorkers)
		return runNugetHash(client)
	},
}

func init() {
	hashBackfillCmd.Flags().IntVar(&hashWorkers, "workers", 128, "Number of concurrent workers")
}
