package scanner

import (
	"os"
	"path/filepath"
	"strings"

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
	var filePaths []string

	info, err := os.Stat(target)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		err = filepath.Walk(target, func(p string, fi os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if !fi.IsDir() {
				lower := strings.ToLower(fi.Name())
				if strings.HasSuffix(lower, ".dll") || strings.HasSuffix(lower, ".jar") {
					filePaths = append(filePaths, p)
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	} else {
		filePaths = append(filePaths, target)
	}

	var files []FileInfo
	for _, p := range filePaths {
		filename := filepath.Base(p)
		lower := strings.ToLower(filename)

		f := FileInfo{
			Filename: filename,
			Path:     p,
		}

		if strings.HasSuffix(lower, ".dll") {
			f.Type = "dll"
		} else {
			f.Type = "jar"
		}

		if f.Type == "dll" {
			isDotNet, err := pe.IsNETAssembly(p)
			if err == nil {
				f.IsDotNet = isDotNet
			}
		}

		files = append(files, f)
	}

	return files, nil
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

func Scan(store *db.Store, target string) ([]Result, error) {
	files, err := CollectFiles(target)
	if err != nil {
		return nil, err
	}

	seenHashes := make(map[string]bool)
	var results []Result

	for i := range files {
		f := &files[i]
		r := Result{
			Filename: f.Filename,
			Path:     f.Path,
			Type:     f.Type,
			IsDotNet: f.IsDotNet,
		}

		if f.Type == "dll" && f.IsDotNet {
			token, _ := pe.PublicKeyToken(f.Path)
			if token != "" && pe.IsMicrosoftToken(token) {
				r.Status = "Known"
				r.MatchedBy = "runtime"
				r.Source = "microsoft"
			}
		}

		HashFile(f)
		r.Hash = f.Hash

		if r.Hash != "" {
			if seenHashes[r.Hash] {
				r.Duplicate = true
			} else {
				seenHashes[r.Hash] = true
			}

			if r.Status == "" {
				hashMatches, _ := store.LookupByHash(r.Hash, f.Type)
				if len(hashMatches) > 0 {
					best := pickBest(hashMatches)
					r.Status = "Known"
					r.MatchedBy = "hash"
					r.Source = best.Source
					r.PackageName = best.PackageName
				}
			}
		}

		if r.Status == "" {
			lookupName := strings.ToLower(f.Filename)
			matches, err := store.Lookup(lookupName, f.Type)
			if err != nil {
				return nil, err
			}
			if len(matches) > 0 {
				best := pickBest(matches)
				r.Status = "Known"
				r.MatchedBy = "filename"
				r.Source = best.Source
				r.PackageName = best.PackageName
			} else {
				r.Status = "Unknown"
			}
		}

		results = append(results, r)
	}

	return results, nil
}

func pickBest(matches []db.DLLMatch) db.DLLMatch {
	return matches[0]
}
