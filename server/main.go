package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
)

type LookupRequestBody struct {
	Files []LookupRequest `json:"files"`
}

type LookupResponseBody struct {
	Results []LookupResult `json:"results"`
	Stats   struct {
		Known   int `json:"known"`
		Unknown int `json:"unknown"`
		Total   int `json:"total"`
	} `json:"stats"`
}

func main() {
	listenAddr := flag.String("listen", ":8080", "HTTP listen address")
	chDSN := flag.String("clickhouse", "clickhouse://localhost:9000/default", "ClickHouse DSN")
	importSQLite := flag.String("import-sqlite", "", "Import data from SQLite DB path, then exit")
	importNuGet := flag.String("import-nuget", "", "Import NuGet JSONL data from directory (containing crawl/ and hashes/), then exit")
	flag.Parse()

	store, err := NewCHStore(*chDSN)
	if err != nil {
		log.Fatalf("connect to clickhouse: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	if err := store.CreateSchema(ctx); err != nil {
		log.Fatalf("create schema: %v", err)
	}

	if *importSQLite != "" {
		log.Printf("importing from %s ...", *importSQLite)
		if err := importFromSQLite(ctx, store, *importSQLite); err != nil {
			log.Fatalf("import failed: %v", err)
		}
		os.Exit(0)
	}

	if *importNuGet != "" {
		log.Printf("importing nuget data from %s ...", *importNuGet)
		if err := importNuGetData(ctx, store, *importNuGet); err != nil {
			log.Fatalf("nuget import failed: %v", err)
		}
		os.Exit(0)
	}

	http.HandleFunc("POST /lookup", func(w http.ResponseWriter, r *http.Request) {
		var req LookupRequestBody
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("bad request: %v", err), http.StatusBadRequest)
			return
		}

		results, err := store.BulkLookup(r.Context(), req.Files)
		if err != nil {
			log.Printf("lookup error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		resp := LookupResponseBody{Results: results}
		for _, r := range results {
			resp.Stats.Total++
			if r.Status == "Known" {
				resp.Stats.Known++
			} else {
				resp.Stats.Unknown++
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	http.HandleFunc("GET /stats", func(w http.ResponseWriter, r *http.Request) {
		stats, err := store.Stats(r.Context())
		if err != nil {
			log.Printf("stats error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
	})

	log.Printf("listening on %s", *listenAddr)
	if err := http.ListenAndServe(*listenAddr, nil); err != nil {
		log.Fatal(err)
	}
}
