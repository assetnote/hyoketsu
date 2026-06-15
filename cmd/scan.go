package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"

	"hyoketsu/db"
	"hyoketsu/scanner"

	"github.com/spf13/cobra"
)

var (
	jsonOutput  bool
	unknownOnly bool
	knownOnly   bool
	dotnetOnly  bool
	dedup       bool
	remoteURL   string
)

var scanCmd = &cobra.Command{
	Use:   "scan <path>",
	Short: "Identify DLLs and JARs against the known database",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := cleanPath(args[0])
		if remoteURL != "" {
			return scanRemote(target)
		}
		return scanLocal(target)
	},
}

func scanLocal(target string) error {
	if dbPath == "" {
		if err := ensureDatabase(); err != nil {
			return err
		}
	}

	store, err := db.Open(getDBPath())
	if err != nil {
		return err
	}
	defer store.Close()

	results, err := scanner.Scan(store, target)
	if err != nil {
		return err
	}

	return displayResults(results)
}

// remoteLookupRequest mirrors the server's expected request body.
type remoteLookupRequest struct {
	Files []remoteLookupFile `json:"files"`
}

type remoteLookupFile struct {
	Filename string `json:"filename"`
	Hash     string `json:"hash"`
	Type     string `json:"type"`
}

type remoteLookupResponse struct {
	Results []struct {
		Filename    string `json:"filename"`
		Status      string `json:"status"`
		MatchedBy   string `json:"matched_by"`
		Source      string `json:"source"`
		PackageName string `json:"package_name"`
	} `json:"results"`
	Stats struct {
		Known   int `json:"known"`
		Unknown int `json:"unknown"`
		Total   int `json:"total"`
	} `json:"stats"`
}

func remoteLookup(files []remoteLookupFile) (*remoteLookupResponse, error) {
	req := remoteLookupRequest{Files: files}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	url := strings.TrimRight(remoteURL, "/") + "/lookup"
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("remote lookup: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %s", resp.Status)
	}

	var lookupResp remoteLookupResponse
	if err := json.NewDecoder(resp.Body).Decode(&lookupResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &lookupResp, nil
}

func scanRemote(target string) error {
	files, err := scanner.CollectFiles(target)
	if err != nil {
		return err
	}

	req := make([]remoteLookupFile, len(files))
	results := make([]scanner.Result, len(files))
	for i := range files {
		scanner.HashFile(&files[i])
		req[i] = remoteLookupFile{
			Filename: strings.ToLower(files[i].Filename),
			Hash:     files[i].Hash,
			Type:     files[i].Type,
		}
		results[i] = scanner.Result{
			Filename: files[i].Filename,
			Path:     files[i].Path,
			Type:     files[i].Type,
			IsDotNet: files[i].IsDotNet,
			Hash:     files[i].Hash,
			Status:   "Unknown",
		}
	}

	resp, err := remoteLookup(req)
	if err != nil {
		return err
	}
	for i := range results {
		if i < len(resp.Results) {
			sr := resp.Results[i]
			results[i].Status = sr.Status
			results[i].MatchedBy = sr.MatchedBy
			results[i].Source = sr.Source
			results[i].PackageName = sr.PackageName
		}
	}

	seenHashes := make(map[string]bool)
	for i := range results {
		if results[i].Hash != "" {
			if seenHashes[results[i].Hash] {
				results[i].Duplicate = true
			} else {
				seenHashes[results[i].Hash] = true
			}
		}
	}

	return displayResults(results)
}

func displayResults(results []scanner.Result) error {
	unfiltered := results
	var filtered []scanner.Result
	for _, r := range results {
		if unknownOnly && r.Status != "Unknown" {
			continue
		}
		if dotnetOnly && !r.IsDotNet {
			continue
		}
		if dedup && r.Duplicate {
			continue
		}
		if knownOnly && r.Status != "Known" {
			continue
		}
		filtered = append(filtered, r)
	}
	results = filtered

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "FILENAME\tTYPE\tDOTNET\tSTATUS\tMATCHED BY\tSOURCE\tPACKAGE\tHASH")
	for _, r := range results {
		pkg := r.PackageName
		if pkg == "" {
			pkg = "-"
		}
		src := r.Source
		if src == "" {
			src = "-"
		}
		matched := "-"
		switch r.MatchedBy {
		case "hash":
			matched = "exact hash"
		case "filename":
			matched = "name only"
		case "runtime":
			matched = "runtime"
		}
		dotnet := "-"
		if r.Type == "dll" {
			if r.IsDotNet {
				dotnet = "yes"
			} else {
				dotnet = "no"
			}
		}
		sha := "-"
		if r.Hash != "" {
			sha = r.Hash[:12]
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.Filename, r.Type, dotnet, r.Status, matched, src, pkg, sha)
	}
	w.Flush()

	fmt.Println()
	known, unknown := 0, 0
	byHash, byName, byRuntime := 0, 0, 0
	for _, r := range unfiltered {
		if r.Status == "Known" {
			known++
			switch r.MatchedBy {
			case "hash":
				byHash++
			case "filename":
				byName++
			case "runtime":
				byRuntime++
			}
		} else {
			unknown++
		}
	}
	total := known + unknown
	if len(results) < total {
		fmt.Printf("%d known, %d unknown out of %d total files (showing %d)\n", known, unknown, total, len(results))
	} else {
		fmt.Printf("%d known, %d unknown out of %d total files\n", known, unknown, total)
	}
	if known > 0 {
		fmt.Printf("  matched by: %d hash, %d filename, %d runtime\n", byHash, byName, byRuntime)
	}
	return nil
}

func ensureDatabase() error {
	defaultPath := db.DefaultDBPath()
	if info, err := os.Stat(defaultPath); err == nil {
		if info.Size() == 0 {
			return fmt.Errorf("database file %s is empty; delete it and run 'hyoketsu update' to re-download", defaultPath)
		}
		const minDBSize = 10 << 30 // 10 GB
		if info.Size() < minDBSize {
			return fmt.Errorf("database file %s is only %d MB which is smaller than expected (>10 GB) and may be corrupt; delete it and run 'hyoketsu update' to re-download", defaultPath, info.Size()/(1<<20))
		}
		return nil
	}

	date, err := fetchRemoteDBDate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "No local database found at %s\n", defaultPath)
		fmt.Fprintf(os.Stderr, "Could not check for remote database: %v\n", err)
		return fmt.Errorf("no database available; run 'hyoketsu update' to download or build one")
	}

	fmt.Printf("No local database found at %s\n", defaultPath)
	fmt.Printf("A pre-built database from the Assetnote team is available (built %s).\n", date)
	fmt.Print("Would you like to download it? [y/N]: ")

	reader := bufio.NewReader(os.Stdin)
	answer, _ := reader.ReadString('\n')
	answer = strings.ToLower(strings.TrimSpace(answer))
	if answer != "y" && answer != "yes" {
		return fmt.Errorf("no database available; run 'hyoketsu update' to download or build one")
	}

	return downloadDatabase(defaultPath)
}

func init() {
	scanCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results as JSON")
	scanCmd.Flags().BoolVar(&unknownOnly, "unknown-only", false, "Show only unknown files")
	scanCmd.Flags().BoolVar(&knownOnly, "known-only", false, "Show only known files")
	scanCmd.Flags().BoolVar(&dotnetOnly, "dotnet-only", false, "Show only .NET assemblies")
	scanCmd.Flags().BoolVar(&dedup, "dedup", false, "Hide duplicate files (by SHA256 hash)")
	scanCmd.Flags().StringVar(&remoteURL, "remote", "", "Remote server URL (e.g. http://host:8080)")
	scanCmd.MarkFlagsMutuallyExclusive("unknown-only", "known-only")
}
