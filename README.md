# Threat Intelligence Pipeline

A production-grade threat intelligence ingestion and analysis pipeline built 
from first principles in Go. Designed to solve the same class of problems as 
enterprise threat intel platforms: ingesting high-volume data from clearnet and 
dark web sources, deduplicating at scale, extracting structured indicators, and 
detecting threat patterns in real time.

Built as a learning project targeting CloudSEK-level infrastructure engineering.
Every component is independently testable, benchmarked, and documented with its
known limitations.

---

## Architecture
URLs (clearnet / Tor)

│

▼

┌─────────────────────────────┐

│     Layer 2 — Crawler       │

│                             │

│  URL frontier (Bloom)       │

│  → per-host rate limiter    │

│  → fetch w/ retry+backoff   │

│  → HTML extraction          │

│  → entity extraction        │

└────────────┬────────────────┘

│ pipeline.Document{Body, Indicators}

▼

┌─────────────────────────────┐

│  Layer 1 — Data Ingestion   │

│                             │

│  SHA-256 exact hash         │

│  → Bloom filter guard       │

│  → Redis confirmation       │

│  → MinHash signature        │

│  → LSH near-dup detection   │

│  → indicator override       │

└────────────┬────────────────┘

│ pass / drop

▼

┌─────────────────────────────┐

│  Layer 3 — Detection        │

│                             │

│  Rule engine (YARA-style)   │

│  → risk scorer              │

│  → sandboxed execution      │

└─────────────────────────────┘

---

## Layers

### Layer 1 — Data Ingestion (`data_ingestion/`)

Multi-stage deduplication pipeline that classifies every incoming document
as exact duplicate, near-duplicate, or novel before it reaches any expensive
downstream processing.

**Components:**
- `hash/` — SHA-256 streaming hash via `io.Writer`. Content-addressed document
  identity. Chosen over MD5/SHA-1 for collision resistance.
- `bloom/` — Hand-rolled Bloom filter using `[]uint64` bit array (8x memory
  efficiency over `[]bool`). Kirsch-Mitzenmacher optimization derives k hash
  functions from one FNV-1a hash. Two-pass `TestAndAdd` prevents self-collision.
  Mutex-guarded for concurrent workers.
- `store/` — Redis-backed hash set as source of truth behind the Bloom guard.
  Fail-open on Redis errors — missing a novel threat is worse than processing
  a duplicate. Mock implementation for testing.
- `minhash/` — 200-function MinHash signature generation with Knuth
  multiplicative seeds. `sync.Pool` for signature slice reuse. Estimates
  Jaccard similarity between documents.
- `lsh/` — LSH banding (50 bands × 2 rows) over MinHash signatures. SHA-256
  bucket keys. `sync.RWMutex` separates concurrent reads from exclusive writes.
- `pipeline/` — Orchestrates all stages. Indicator override: near-duplicate
  documents with new IPs/hashes/CVEs are preserved regardless of text similarity.

**Benchmarks (Apple M1):**

| Metric | Value |
|---|---|
| Pipeline throughput (single core) | 426 docs/sec |
| Allocations per document | 282 allocs/op |
| Memory per document | 775 KB/op |
| Bloom filter FPR at 1M items | ~1% (configured) |

---

### Layer 2 — Crawler (`crawler/`)

Fetches documents from clearnet and Tor sources. Designed to survive
real-world failure modes: dead hosts, malformed HTML, duplicate URLs,
transient network errors.

**Components:**
- `client/` — Clearnet `http.Client` with connection pooling, configurable
  timeouts, and `DialContext` control. Tor client routed through local SOCKS5
  proxy (127.0.0.1:9050), verified against check.torproject.org. Higher
  timeouts for Tor (3-hop relay latency).
- `fetcher/` — `http.NewRequestWithContext` (not `http.Get`) for cancellation.
  `io.LimitReader` caps responses at 5MB to prevent OOM from malicious servers.
- `rateLimiter/` — Per-host token bucket (`golang.org/x/time/rate`). Lazily
  created per domain, mutex-protected. Rate limits the server, not the URL —
  different URLs to the same host share one limiter.
- `retry/` — Exponential backoff with full jitter. Context-aware sleep respects
  cancellation mid-backoff. Distinguishes retryable (429, 503, timeout) from
  terminal (404) errors.
- `extractor/` — DOM-tree text extraction via `golang.org/x/net/html`. Bounded
  input (truncate before parse), bounded node count. Skips
  script/style/noscript/iframe/svg subtrees.
- `entities/` — Structured indicator extraction: IPs (regex + `net.ParseIP`
  validation), hashes (SHA-256/SHA-1/MD5, noise-filtered), CVEs (year-range
  validated 1999–present), domains (`publicsuffix` TLD validation), emails.
- `orchestrator/` — Streaming worker pool. Producer function decoupled from
  total URL count. Separate URL-frontier Bloom filter (distinct from content
  dedup filter — different key space, different concern). Workers select on
  both work channel and `ctx.Done()` for clean cancellation.

**Benchmarks (Apple M1):**

| Metric | Value |
|---|---|
| Extractor throughput | 6.8MB input → 128ms, 2.6M chars extracted |
| Cancellation latency | Halts within 1 polling cycle of ctx.Done() |
| Rate limiter isolation | Cross-host non-blocking confirmed at 12.8µs |

---

### Layer 3 — Detection (`detection/`, `sandbox/`)

YARA-style rule engine that evaluates processed documents against named threat
patterns and produces a risk score.

**Components:**
- `detection/rules.go` — `Rule`, `Pattern`, `RuleMatch`, `RuleEngine` types.
  Rules have named patterns (literal or regex), a match threshold, and a
  severity weight.
- `detection/engine.go` — `New` pre-compiles all regex patterns at startup
  (separate setup cost from per-request cost). `Evaluate` runs all rules
  against document text. Plain strings match case-insensitively via
  `strings.Contains`. Regex patterns use pre-compiled `*regexp.Regexp`.
- `detection/defaults.go` — Five production rules covering: ransomware
  (encrypted files, ransom demand), credential leak (AWS keys, GitHub PATs,
  Slack webhooks, Bearer tokens), data exfiltration (credit card patterns,
  SSNs, SQL dumps, JWT tokens), CVE exploitation (Log4Shell JNDI strings,
  path traversal, SQLi), phishing (urgency phrases, typosquatting domains,
  URL shorteners).
- `detection/risk_scorer.go` — Weighted score from matched rule severities.
  Bonus for multi-rule correlation. Capped at 100. Severity labels: LOW /
  MEDIUM / HIGH / CRITICAL.
- `sandbox/sandbox.go` — Goroutine-based isolation with 2-second timeout and
  panic recovery. Prevents a single document from stalling the pipeline.

---

## Known Limitations

These are documented honestly, not hidden.

**Data Ingestion:**
- Bloom filter and LSH index are in-memory only — state lost on restart.
  Production fix: serialize Bloom bits to disk on shutdown, persist LSH
  buckets to Redis.
- `hasNewIndicators` checks `len(indicators) > 0`, not set-diffing against
  stored candidate indicators. A near-duplicate with an already-seen IP still
  bypasses dedup. Real fix: store indicators per document ID, diff on lookup.

**Crawler:**
- Domain extraction has high false-positive rate. "example.com" in prose is
  indistinguishable from C2 infrastructure without NLP context. Documented
  limitation, not patchable with regex.
- No robots.txt compliance for clearnet sources.
- No Tor circuit rotation on failure (requires Tor control-port, `SIGNAL NEWNYM`).
- URL frontier is in-memory only — same limitation as Bloom filter above.
- No reputation-checked validation. A SHA-256 hash matching the pattern is
  not the same as a confirmed malicious hash. Requires external enrichment
  (VirusTotal-style API) as a separate async stage.

**Detection:**
- `sandbox/sandbox.go` is NOT OS-level sandboxing. It catches panics and
  timeouts but does not prevent malicious documents from making syscalls,
  reading the filesystem, or opening network connections. Real sandboxing
  requires Linux namespaces, seccomp filters, and capability dropping (gVisor
  or Firecracker for full isolation).
- Rule thresholds are set to 1 — increases recall, increases false positives.
  Production tuning requires labeled threat data to find the right tradeoff.

---

## What Production Would Add

- Kafka/message bus between crawler and ingestion pipeline for backpressure
  and replay
- Prometheus metrics on every stage: drop rate, near-dup rate, rule match
  rate, Redis error rate, fetch latency p99
- Persistent URL frontier and document store (Redis-backed)
- Indicator enrichment stage: VirusTotal, AbuseIPDB, Shodan
- Real OS-level sandboxing via Linux namespaces + seccomp for file analysis
- Kubernetes deployment with horizontal scaling on ingestion workers
- Tor circuit rotation via control-port integration
- robots.txt compliance with per-host caching

---

## Running

```bash
# Run all tests
go test ./...

# Run with benchmarks
go test ./... -bench=. -benchmem

# Run specific layer
go test ./data_ingestion/... -v
go test ./crawler/... -v
go test ./detection/... -v
```

**Requirements:**
- Go 1.21+
- Redis (for production store; mock used in tests)
- Tor (optional, for .onion crawling: `brew install tor && brew services start tor`)

---

## Project Structure
threat_pipeline/

├── data_ingestion/     # Layer 1: deduplication pipeline

│   ├── bloom/          # Bloom filter (hand-rolled)

│   ├── hash/           # SHA-256 content hashing

│   ├── lsh/            # Locality-sensitive hashing

│   ├── minhash/        # MinHash signature generation

│   ├── pipeline/       # Pipeline orchestration

│   └── store/          # Redis + mock storage

├── crawler/            # Layer 2: data acquisition

│   ├── client/         # Clearnet + Tor HTTP clients

│   ├── entities/       # Indicator extraction

│   ├── extractor/      # HTML text extraction

│   ├── fetcher/        # HTTP fetcher with context

│   ├── orchestrator/   # Streaming worker pool

│   ├── rateLimiter/    # Per-host token bucket

│   └── retry/          # Exponential backoff

├── detection/          # Layer 3: threat detection

│   ├── engine.go       # Rule evaluation

│   ├── rules.go        # Type definitions

│   ├── defaults.go     # Built-in threat rules

│   └── risk_scorer.go  # Severity scoring

└── sandbox/            # Isolated execution

└── sandbox.go

