# hyoketsu

Offline identification of DLLs and JARs. Separate known open-source libraries from custom code during reverse engineering and source code review.

Identifies files using three methods:
1. **Microsoft runtime detection** — .NET public key token extraction
2. **Hash matching** — SHA256 (NuGet) and SHA1 (Maven Central) exact match
3. **Filename matching** — fallback against 12M+ DLLs and 14M+ JARs

## Install

Requires Go 1.22+.

```
go build -o hyoketsu .
```

## Database

Stored at `~/.hyoketsu/hyoketsu.db`.

### Download pre-built (recommended)

```
./hyoketsu update
```

Downloads the latest database from the Assetnote CDN. Also triggered automatically on first scan if no database exists.

### Build from scratch

Run on a server with good bandwidth.

```
./hyoketsu update --build
```

Runs all steps automatically: Maven crawl, NuGet crawl, hash backfill, and import. The individual NuGet pipeline steps can also be run separately:

```
./hyoketsu crawl-nuget       # Step 1: crawl NuGet catalog to JSONL
./hyoketsu hash-backfill      # Step 2: download nupkgs, compute SHA256 hashes
./hyoketsu import             # Step 3: merge JSONL into SQLite
```

All steps support resuming — re-running skips already completed work.

`--workers` controls concurrency for `crawl-nuget`, `hash-backfill`, and `update --build` (default: 128).

## Usage

### Scan

```
./hyoketsu scan /path/to/binaries

# JSON output
./hyoketsu scan --json /path/to/binaries

# Only unknown files (custom code)
./hyoketsu scan --unknown-only /path/to/binaries

# Only known files (libraries)
./hyoketsu scan --known-only /path/to/binaries

# Only .NET assemblies
./hyoketsu scan --dotnet-only /path/to/binaries

# Hide duplicates (by SHA256)
./hyoketsu scan --dedup /path/to/binaries

# Show only filename-matched files
./hyoketsu scan --filename /path/to/project

# Scan against a remote server (ClickHouse backend)
./hyoketsu scan --remote http://host:8080 /path/to/project
```

`--unknown-only` and `--known-only` are mutually exclusive.

## Server

The `server/` directory contains a ClickHouse-backed HTTP server for centralized scanning. See `docker-compose.yml` to get started.

```
cd server && go build -o server .
```

## Extract

Copy unidentified files to a separate directory for decompilation.

```
./hyoketsu extract /path/to/binaries /path/to/output

# Flatten into single directory
./hyoketsu extract --flat /path/to/binaries /path/to/output

# Only .NET, skip dupes
./hyoketsu extract --dotnet-only --dedup /path/to/binaries /path/to/output
```

### Stats

```
./hyoketsu stats
```
