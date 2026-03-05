package cmd

import "fmt"

const (
	nugetCrawlDir = "data/nuget/crawl"
	nugetHashDir  = "data/nuget/hashes"
)

var nugetPipelineSteps = []struct {
	cmd  string
	desc string
}{
	{"crawl-nuget", "Crawl NuGet catalog to JSONL"},
	{"hash-backfill", "Download nupkgs, compute SHA256 hashes"},
	{"import", "Merge JSONL data into SQLite"},
}

// printNugetPipeline prints a visual pipeline status after a NuGet step completes.
// completedStep is 1-indexed (1 = update done, 2 = hash-backfill done, 3 = import done).
func printNugetPipeline(completedStep int) {
	fmt.Println()
	fmt.Println("NuGet pipeline:")
	for i, s := range nugetPipelineSteps {
		step := i + 1
		marker := "  "
		if step <= completedStep {
			marker = "done"
		}
		fmt.Printf("  [%-4s]  %-16s  %s\n", marker, s.cmd, s.desc)
	}
	if completedStep < len(nugetPipelineSteps) {
		next := nugetPipelineSteps[completedStep]
		fmt.Printf("\nNext: ./hyoketsu %s\n", next.cmd)
	}
	fmt.Println()
}
