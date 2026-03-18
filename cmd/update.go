package cmd

import (
	"fmt"
	"strings"

	"hyoketsu/db"
	"hyoketsu/maven"
	"hyoketsu/nuget"

	"github.com/spf13/cobra"
)

var updateBuild bool
var updateWorkers int

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Download or build the latest database",
	Long: `Updates the local database.

By default, downloads the pre-built database from the Assetnote CDN.
Use --build to crawl package registries and build the database from scratch.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if updateBuild {
			return buildFromScratch()
		}
		return downloadRemoteDB()
	},
}

func downloadRemoteDB() error {
	targetPath := getDBPath()

	date, err := fetchRemoteDBDate()
	if err != nil {
		return fmt.Errorf("could not check for remote database: %w", err)
	}

	fmt.Printf("Pre-built database available (built %s).\n", date)
	fmt.Printf("Downloading to %s...\n", targetPath)
	return downloadDatabase(targetPath)
}

func buildFromScratch() error {
	store, err := db.Open(getDBPath())
	if err != nil {
		return err
	}
	defer store.Close()

	if err := runMavenCrawl(store); err != nil {
		return err
	}

	fmt.Println()
	nugetClient := nuget.NewClient(store, updateWorkers)

	if err := runNugetCrawl(store, nugetClient); err != nil {
		return err
	}

	if err := runNugetHash(nugetClient); err != nil {
		return err
	}

	fmt.Println("[NuGet] Importing into database...")
	if err := runNugetImport(store); err != nil {
		return err
	}
	printNugetPipeline(3)

	total, _ := store.TotalCount()
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("Done. %d entries in database.\n", total)
	return nil
}

func runMavenCrawl(store *db.Store) error {
	fmt.Println("[Maven] Crawling Maven Central...")
	mavenClient := maven.NewClient(store)
	if err := mavenClient.Crawl(func(count int) {
		fmt.Printf("\r[Maven] %d artifacts indexed", count)
	}); err != nil {
		return fmt.Errorf("[Maven] %w", err)
	}
	fmt.Println()
	fmt.Println("[Maven] Done.")
	return nil
}

func runNugetCrawl(store *db.Store, client *nuget.Client) error {
	cursor, err := store.GetCursor()
	if err != nil {
		return fmt.Errorf("get nuget cursor: %w", err)
	}
	if cursor != "" {
		fmt.Printf("[NuGet] Resuming from cursor: %s\n", cursor)
	} else {
		fmt.Println("[NuGet] Starting full catalog crawl...")
	}

	newCursor, err := client.Crawl(cursor, nugetCrawlDir, func(page, total int) {
		if total == 0 {
			fmt.Println("[NuGet] Catalog is up to date.")
		}
	})
	if err != nil {
		fmt.Printf("[NuGet] Crawl stopped at cursor %s due to error: %v\n", newCursor, err)
		return err
	}
	fmt.Println("[NuGet] Crawl complete.")
	printNugetPipeline(1)
	return nil
}

func runNugetHash(client *nuget.Client) error {
	fmt.Println("[NuGet] Downloading nupkgs and computing hashes...")
	err := client.HashBackfill(nugetCrawlDir, nugetHashDir, func(done, total int) {
		fmt.Printf("[NuGet Hash] %d/%d packages\n", done, total)
	})
	if err != nil {
		return err
	}
	printNugetPipeline(2)
	return nil
}

func init() {
	updateCmd.Flags().BoolVar(&updateBuild, "build", false, "Build database from scratch instead of downloading")
	updateCmd.Flags().IntVar(&updateWorkers, "workers", 128, "Number of concurrent workers (used with --build)")
}
