package scanner

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"hyoketsu/db"
	"hyoketsu/hasher"
	"hyoketsu/pe"
)

type Result struct {
	Filename    string `json:"filename"`
	Path        string `json:"path"`
	Type        string `json:"type"`
	IsDotNet    bool   `json:"is_dotnet"`
	Hash        string `json:"hash"`
	Status      string `json:"status"`
	MatchedBy   string `json:"matched_by"`
	Source      string `json:"source"`
	PackageName string `json:"package_name"`
	Duplicate   bool   `json:"duplicate"`
}

type FileInfo struct {
	Filename string `json:"filename"`
	Path     string `json:"path"`
	Type     string `json:"type"`
	IsDotNet bool   `json:"is_dotnet"`
	Hash     string `json:"hash"`
}

func CollectFiles(target string) ([]FileInfo, error) {
	info, err := os.Stat(target)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return collectSingle(target)
	}

	var files []FileInfo
	err = filepath.WalkDir(target, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		lower := strings.ToLower(d.Name())
		if !strings.HasSuffix(lower, ".dll") && !strings.HasSuffix(lower, ".jar") {
			return nil
		}

		f := FileInfo{
			Filename: d.Name(),
			Path:     p,
		}
		if strings.HasSuffix(lower, ".dll") {
			f.Type = "dll"
		} else {
			f.Type = "jar"
		}
		files = append(files, f)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

func collectSingle(target string) ([]FileInfo, error) {
	filename := filepath.Base(target)
	lower := strings.ToLower(filename)
	f := FileInfo{
		Filename: filename,
		Path:     target,
	}
	if strings.HasSuffix(lower, ".dll") {
		f.Type = "dll"
	} else {
		f.Type = "jar"
	}
	return []FileInfo{f}, nil
}

func HashFile(f *FileInfo) {
	if f.Hash != "" {
		return
	}
	if f.Type == "jar" {
		h, err := hasher.HashFileSHA1(f.Path)
		if err == nil {
			f.Hash = h
		}
	} else {
		h, err := hasher.HashFileSHA256(f.Path)
		if err == nil {
			f.Hash = h
		}
	}
}

// hashFilesParallel hashes all files using a worker pool.
func hashFilesParallel(files []FileInfo) {
	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8
	}
	if len(files) < workers {
		workers = len(files)
	}

	var wg sync.WaitGroup
	ch := make(chan int, len(files))
	for i := range files {
		ch <- i
	}
	close(ch)

	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := range ch {
				HashFile(&files[i])
			}
		}()
	}
	wg.Wait()
}

func Scan(store *db.Store, target string) ([]Result, error) {
	files, err := CollectFiles(target)
	if err != nil {
		return nil, err
	}

	// Check .NET status for DLLs (fast, reads only headers)
	for i := range files {
		if files[i].Type == "dll" {
			isDotNet, err := pe.IsNETAssembly(files[i].Path)
			if err == nil {
				files[i].IsDotNet = isDotNet
			}
		}
	}

	// Hash all files in parallel
	hashFilesParallel(files)

	// Build results with DLL-specific runtime detection
	seenHashes := make(map[string]bool)
	results := make([]Result, len(files))
	for i := range files {
		f := &files[i]
		results[i] = Result{
			Filename: f.Filename,
			Path:     f.Path,
			Type:     f.Type,
			IsDotNet: f.IsDotNet,
			Hash:     f.Hash,
		}

		if f.Type == "dll" && f.IsDotNet {
			token, _ := pe.PublicKeyToken(f.Path)
			if token != "" && pe.IsMicrosoftToken(token) {
				results[i].Status = "Known"
				results[i].MatchedBy = "runtime"
				results[i].Source = "microsoft"
			}
		}

		if f.Hash != "" {
			if seenHashes[f.Hash] {
				results[i].Duplicate = true
			} else {
				seenHashes[f.Hash] = true
			}
		}
	}

	// Batch hash lookups, grouped by type
	hashesByType := map[string][]string{}
	for i := range results {
		if results[i].Status == "" && results[i].Hash != "" {
			hashesByType[results[i].Type] = append(hashesByType[results[i].Type], results[i].Hash)
		}
	}
	hashResults := map[string][]db.DLLMatch{}
	for fileType, hashes := range hashesByType {
		matches, err := store.BatchLookupByHash(hashes, fileType)
		if err != nil {
			return nil, err
		}
		for k, v := range matches {
			hashResults[k] = v
		}
	}

	// Apply hash matches
	var needNameLookup []int
	for i := range results {
		if results[i].Status != "" {
			continue
		}
		if results[i].Hash != "" {
			if matches, ok := hashResults[results[i].Hash]; ok && len(matches) > 0 {
				best := pickBest(matches)
				results[i].Status = "Known"
				results[i].MatchedBy = "hash"
				results[i].Source = best.Source
				results[i].PackageName = best.PackageName
				continue
			}
		}
		needNameLookup = append(needNameLookup, i)
	}

	// Batch filename lookups for remaining unknowns, grouped by type
	namesByType := map[string][]string{}
	for _, idx := range needNameLookup {
		name := strings.ToLower(files[idx].Filename)
		namesByType[results[idx].Type] = append(namesByType[results[idx].Type], name)
	}
	nameResults := map[string]map[string][]db.DLLMatch{}
	for fileType, names := range namesByType {
		matches, err := store.BatchLookupByName(names, fileType)
		if err != nil {
			return nil, err
		}
		nameResults[fileType] = matches
	}

	// Apply name matches
	for _, idx := range needNameLookup {
		name := strings.ToLower(files[idx].Filename)
		if typeMatches, ok := nameResults[results[idx].Type]; ok {
			if matches, ok := typeMatches[name]; ok && len(matches) > 0 {
				best := pickBest(matches)
				results[idx].Status = "Known"
				results[idx].MatchedBy = "filename"
				results[idx].Source = best.Source
				results[idx].PackageName = best.PackageName
				continue
			}
		}
		results[idx].Status = "Unknown"
	}

	return results, nil
}

func pickBest(matches []db.DLLMatch) db.DLLMatch {
	return matches[0]
}
