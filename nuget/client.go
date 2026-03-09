package nuget

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"hyoketsu/db"
)

const (
	catalogIndexURL = "https://api.nuget.org/v3/catalog0/index.json"
	defaultWorkers  = 32
	maxRetries      = 5
)

type CatalogIndex struct {
	Items []CatalogPage `json:"items"`
}

type CatalogPage struct {
	ID              string `json:"@id"`
	CommitTimeStamp string `json:"commitTimeStamp"`
	Count           int    `json:"count"`
}

type CatalogPageContent struct {
	Items []CatalogLeaf `json:"items"`
}

type CatalogLeaf struct {
	ID              string `json:"@id"`
	Type            string `json:"@type"`
	NuGetID         string `json:"nuget:id"`
	NuGetVersion    string `json:"nuget:version"`
	CommitTimeStamp string `json:"commitTimeStamp"`
}

type CatalogLeafDetail struct {
	PackageID      string         `json:"id"`
	Version        string         `json:"version"`
	PackageEntries []PackageEntry `json:"packageEntries"`
}

type PackageEntry struct {
	FullName string `json:"fullName"`
	Name     string `json:"name"`
}

type Client struct {
	HTTP    *http.Client
	Workers int
	store   *db.Store

	requestCount atomic.Int64
	retryCount   atomic.Int64
	errorCount   atomic.Int64
}

func NewClient(store *db.Store, workers int) *Client {
	if workers <= 0 {
		workers = defaultWorkers
	}
	transport := &http.Transport{
		MaxIdleConns:        workers * 2,
		MaxIdleConnsPerHost: workers * 2,
		IdleConnTimeout:     90 * time.Second,
	}
	return &Client{
		HTTP:    &http.Client{Timeout: 30 * time.Second, Transport: transport},
		Workers: workers,
		store:   store,
	}
}

func (c *Client) doRequest(req *http.Request) (*http.Response, error) {
	for attempt := range maxRetries {
		c.requestCount.Add(1)
		resp, err := c.HTTP.Do(req)
		if err != nil {
			c.retryCount.Add(1)
			time.Sleep(backoffDuration(attempt))
			req = req.Clone(req.Context())
			continue
		}

		if resp.StatusCode == 429 || resp.StatusCode == 503 {
			resp.Body.Close()
			c.retryCount.Add(1)

			wait := backoffDuration(attempt)
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if secs, err := strconv.Atoi(ra); err == nil {
					wait = time.Duration(secs) * time.Second
				}
			}

			time.Sleep(wait)
			req = req.Clone(req.Context())
			continue
		}

		return resp, nil
	}
	c.errorCount.Add(1)
	return nil, fmt.Errorf("request failed after %d retries: %s", maxRetries, req.URL)
}

func backoffDuration(attempt int) time.Duration {
	base := time.Duration(1<<uint(attempt)) * 500 * time.Millisecond
	jitter := time.Duration(rand.Int63n(int64(base) / 2))
	return base + jitter
}

func (c *Client) fetchJSON(url string, v interface{}) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	resp, err := c.doRequest(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

type leafInfo struct {
	url string
	id  string
}

// Crawl downloads the entire NuGet catalog and writes DLL entries as JSONL files.
// Phase 1: download all page JSONs in parallel to collect leaf URLs.
// Phase 2: fetch all leaves in parallel with full worker pool.
func (c *Client) Crawl(cursor string, outDir string, progress func(page, total int)) (string, error) {
	os.MkdirAll(outDir, 0755)

	var index CatalogIndex
	if err := c.fetchJSON(catalogIndexURL, &index); err != nil {
		return cursor, fmt.Errorf("fetch catalog index: %w", err)
	}

	// Filter pages after cursor
	var pages []CatalogPage
	for _, p := range index.Items {
		if cursor == "" || p.CommitTimeStamp > cursor {
			pages = append(pages, p)
		}
	}

	if len(pages) == 0 {
		if progress != nil {
			progress(0, 0)
		}
		return cursor, nil
	}

	// Phase 1: download ALL page JSONs in parallel to collect leaf URLs
	fmt.Printf("[NuGet] Downloading %d catalog pages in parallel...\n", len(pages))
	startTime := time.Now()

	type pageResult struct {
		leaves []leafInfo
		cursor string
		err    error
	}

	pageResults := make([]pageResult, len(pages))
	var wg sync.WaitGroup
	pageCh := make(chan int, len(pages))
	for i := range pages {
		pageCh <- i
	}
	close(pageCh)

	pageWorkers := c.Workers
	if pageWorkers > 64 {
		pageWorkers = 64 // don't need too many for page downloads
	}
	for w := 0; w < pageWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range pageCh {
				var content CatalogPageContent
				if err := c.fetchJSON(pages[i].ID, &content); err != nil {
					pageResults[i] = pageResult{err: err}
					continue
				}

				seen := make(map[string]bool)
				var leaves []leafInfo
				for _, leaf := range content.Items {
					if !strings.Contains(leaf.Type, "PackageDetails") {
						continue
					}
					key := strings.ToLower(leaf.NuGetID) + "@" + strings.ToLower(leaf.NuGetVersion)
					if seen[key] {
						continue
					}
					seen[key] = true
					leaves = append(leaves, leafInfo{
						url: leaf.ID,
						id:  strings.ToLower(leaf.NuGetID),
					})
				}
				pageResults[i] = pageResult{leaves: leaves, cursor: pages[i].CommitTimeStamp}
			}
		}()
	}
	wg.Wait()

	// Collect all leaves and find latest cursor
	var allLeaves []leafInfo
	latestCursor := cursor
	for _, pr := range pageResults {
		if pr.err != nil {
			continue
		}
		allLeaves = append(allLeaves, pr.leaves...)
		if pr.cursor > latestCursor {
			latestCursor = pr.cursor
		}
	}

	elapsed := time.Since(startTime)
	fmt.Printf("[NuGet] Pages done in %s. %d unique leaves to fetch.\n", elapsed.Round(time.Second), len(allLeaves))

	// Phase 2: fetch ALL leaves in parallel, write results to JSONL
	fmt.Printf("[NuGet] Fetching %d leaves with %d workers...\n", len(allLeaves), c.Workers)
	startTime = time.Now()

	var mu sync.Mutex
	var batch []db.DLLMatch
	batchNum := 0
	totalEntries := 0
	var processed atomic.Int64

	flushBatch := func() {
		if len(batch) == 0 {
			return
		}
		outFile := filepath.Join(outDir, fmt.Sprintf("page_%05d.jsonl", batchNum))
		writeJSONL(outFile, batch)
		totalEntries += len(batch)
		batchNum++
		batch = nil
	}

	leafCh := make(chan leafInfo, len(allLeaves))
	for _, l := range allLeaves {
		leafCh <- l
	}
	close(leafCh)

	for w := 0; w < c.Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for l := range leafCh {
				dlls := c.extractDLLsFromLeaf(l.url, l.id)
				if len(dlls) > 0 {
					mu.Lock()
					batch = append(batch, dlls...)
					if len(batch) >= 5000 {
						flushBatch()
					}
					mu.Unlock()
				}
				n := processed.Add(1)
				if n%10000 == 0 {
					elapsed := time.Since(startTime)
					rps := float64(n) / elapsed.Seconds()
					fmt.Printf("[NuGet] %d/%d leaves (%.0f/s) | %d entries | %d retries | %d errors\n",
						n, len(allLeaves), rps, totalEntries, c.retryCount.Load(), c.errorCount.Load())
				}
			}
		}()
	}
	wg.Wait()

	// Flush remaining
	mu.Lock()
	flushBatch()
	mu.Unlock()

	// Save cursor
	os.WriteFile(filepath.Join(outDir, "cursor.txt"), []byte(latestCursor), 0644)

	elapsed = time.Since(startTime)
	fmt.Printf("[NuGet] Done. %d entries from %d leaves in %s\n", totalEntries, len(allLeaves), elapsed.Round(time.Second))

	return latestCursor, nil
}

func writeJSONL(path string, entries []db.DLLMatch) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, e := range entries {
		enc.Encode(e)
	}
	return nil
}

func (c *Client) extractDLLsFromLeaf(leafURL, packageID string) []db.DLLMatch {
	var detail CatalogLeafDetail
	if err := c.fetchJSON(leafURL, &detail); err != nil {
		return nil
	}

	version := strings.ToLower(detail.Version)
	seen := make(map[string]bool)
	var entries []db.DLLMatch
	for _, e := range detail.PackageEntries {
		fullName := strings.ToLower(e.FullName)
		if !strings.HasSuffix(fullName, ".dll") || !strings.HasPrefix(fullName, "lib/") {
			continue
		}
		base := strings.ToLower(path.Base(e.FullName))
		if seen[base] {
			continue
		}
		seen[base] = true
		entries = append(entries, db.DLLMatch{
			DLLName:     base,
			Source:      "nuget",
			PackageName: packageID,
			Version:     version,
		})
	}
	return entries
}

// HashBackfill reads crawl JSONL files, downloads nupkgs, hashes DLLs, writes to outDir.
func (c *Client) HashBackfill(inDir, outDir string, progress func(done, total int)) error {
	os.MkdirAll(outDir, 0755)

	type pkgVer struct{ id, ver string }
	pkgSet := make(map[pkgVer]bool)

	files, _ := filepath.Glob(filepath.Join(inDir, "page_*.jsonl"))
	for _, f := range files {
		entries, err := readJSONL(f)
		if err != nil {
			continue
		}
		for _, e := range entries {
			pkgSet[pkgVer{e.PackageName, e.Version}] = true
		}
	}

	totalAll := len(pkgSet)

	// Skip already-hashed packages
	hashedFiles, _ := filepath.Glob(filepath.Join(outDir, "hashed_*.jsonl"))
	for _, f := range hashedFiles {
		entries, err := readJSONL(f)
		if err != nil {
			continue
		}
		for _, e := range entries {
			delete(pkgSet, pkgVer{e.PackageName, e.Version})
		}
	}

	var packages []pkgVer
	for pv := range pkgSet {
		packages = append(packages, pv)
	}

	alreadyDone := totalAll - len(packages)
	total := totalAll
	if total == 0 {
		fmt.Println("No packages to hash")
		return nil
	}

	var done atomic.Int64
	var mu sync.Mutex
	batchNum := len(hashedFiles)
	var batchEntries []db.DLLMatch

	flushBatch := func() {
		if len(batchEntries) == 0 {
			return
		}
		outFile := filepath.Join(outDir, fmt.Sprintf("hashed_%05d.jsonl", batchNum))
		writeJSONL(outFile, batchEntries)
		batchNum++
		batchEntries = nil
	}

	var wg sync.WaitGroup
	work := make(chan pkgVer, total)
	for _, p := range packages {
		work <- p
	}
	close(work)

	for w := 0; w < c.Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pkg := range work {
				hashed := c.hashPackageDLLs(pkg.id, pkg.ver)
				if len(hashed) > 0 {
					mu.Lock()
					batchEntries = append(batchEntries, hashed...)
					if len(batchEntries) >= 5000 {
						flushBatch()
					}
					mu.Unlock()
				}
				n := done.Add(1)
				if progress != nil && n%100 == 0 {
					progress(alreadyDone+int(n), total)
				}
			}
		}()
	}
	wg.Wait()

	mu.Lock()
	flushBatch()
	mu.Unlock()

	if progress != nil {
		progress(total, total)
	}
	return nil
}

func readJSONL(path string) ([]db.DLLMatch, error) {
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

func (c *Client) hashPackageDLLs(packageID, version string) []db.DLLMatch {
	nupkgURL := fmt.Sprintf("https://api.nuget.org/v3-flatcontainer/%s/%s/%s.%s.nupkg",
		packageID, version, packageID, version)

	req, err := http.NewRequest("GET", nupkgURL, nil)
	if err != nil {
		return nil
	}
	resp, err := c.doRequest(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil
	}

	seen := make(map[string]bool)
	var results []db.DLLMatch
	for _, f := range zr.File {
		name := strings.ToLower(f.Name)
		if !strings.HasSuffix(name, ".dll") || !strings.HasPrefix(name, "lib/") {
			continue
		}
		base := strings.ToLower(path.Base(f.Name))
		if seen[base] {
			continue
		}
		seen[base] = true
		hash := hashZipEntry(f)
		results = append(results, db.DLLMatch{
			DLLName:     base,
			Source:      "nuget",
			PackageName: packageID,
			Version:     version,
			Hash:        hash,
		})
	}
	return results
}

func hashZipEntry(f *zip.File) string {
	rc, err := f.Open()
	if err != nil {
		return ""
	}
	defer rc.Close()
	h := sha256.New()
	if _, err := io.Copy(h, rc); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
