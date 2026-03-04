package cmd

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const (
	hyoketsuIndexURL = "https://wordlists-cdn.assetnote.io/hyoketsu/"
	hyoketsuDBURL    = "https://wordlists-cdn.assetnote.io/hyoketsu/hyoketsu.db"
)

func fetchRemoteDBDate() (string, error) {
	resp, err := http.Get(hyoketsuIndexURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// nginx autoindex format: <a href="hyoketsu.db">hyoketsu.db</a>  DD-Mon-YYYY HH:MM  size
	re := regexp.MustCompile(`hyoketsu\.db</a>\s+(\d{2}-\w{3}-\d{4})`)
	matches := re.FindSubmatch(body)
	if matches == nil {
		return "", fmt.Errorf("hyoketsu.db not found in remote index")
	}

	t, err := time.Parse("02-Jan-2006", string(matches[1]))
	if err != nil {
		return string(matches[1]), nil
	}
	return t.Format("January 2, 2006"), nil
}

func downloadDatabase(dbPath string) error {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	resp, err := http.Get(hyoketsuDBURL)
	if err != nil {
		return fmt.Errorf("download database: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %s", resp.Status)
	}

	tmpPath := dbPath + ".download"
	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}

	var reader io.Reader = resp.Body
	size := resp.ContentLength
	if size > 0 {
		fmt.Printf("Downloading database (%.0f MB)...\n", float64(size)/(1024*1024))
		reader = &progressReader{reader: resp.Body, total: size}
	} else {
		fmt.Println("Downloading database...")
	}

	if _, err := io.Copy(f, reader); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("download interrupted: %w", err)
	}
	f.Close()

	if err := os.Rename(tmpPath, dbPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("move database into place: %w", err)
	}

	fmt.Println("\nDatabase downloaded successfully.")
	return nil
}

type progressReader struct {
	reader  io.Reader
	total   int64
	current int64
	lastPct int
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	pr.current += int64(n)
	pct := int(float64(pr.current) / float64(pr.total) * 100)
	if pct != pr.lastPct {
		fmt.Printf("\r  %d%% (%d / %d MB)", pct, pr.current/(1024*1024), pr.total/(1024*1024))
		pr.lastPct = pct
	}
	return n, err
}
