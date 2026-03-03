# Inspectra — Automated TLS, Cipher, Certificate & JDK Compatibility Analysis Pipeline

> **Continuous, automated TLS posture visibility across large codebases — powered by GitHub Actions, OpenSSL, and AI.**

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture Diagrams](#2-architecture-diagrams)
3. [High-Level Design (HLD)](#3-high-level-design-hld)
4. [Low-Level Design (LLD)](#4-low-level-design-lld)
5. [MongoDB Schema](#5-mongodb-schema)
6. [Severity Model](#6-severity-model)
7. [Installation Guide](#7-installation-guide)
8. [Developer Guide](#8-developer-guide)
9. [Use Cases](#9-use-cases)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Overview

**Inspectra** is a GitHub Actions–driven security analysis engine that:

| Capability | Detail |
|---|---|
| **Endpoint extraction** | Scans `.properties`, `.yml`, `.yaml` files for HTTPS/HTTP URLs |
| **TLS handshake scanning** | Performs live SSL/TLS handshakes via `openssl s_client -brief` |
| **Certificate inspection** | Extracts issuer, SAN, expiry date, days-to-expiry |
| **JDK detection** | Detects vendor, version, and major of the runner's JDK |
| **Java release ingestion** | Fetches Oracle Java release metadata (GA dates, EOL status) |
| **AI compatibility scoring** | Sends TLS context to GitHub Models (gpt-4o) for compatibility evaluation |
| **Severity classification** | Maps findings to `CRITICAL / HIGH / WARNING / INFO` |
| **Report generation** | Produces Markdown, SARIF, and SonarQube Generic Issue reports |
| **MongoDB persistence** | Seeds results into 8 MongoDB collections for historical analysis |
| **Auto-commit** | Reports committed back to the repository on every run |

### Consumption modes

```yaml
# Mode 1 — standalone (runs everywhere on push)
uses: Challa823/inspectra-github-workflow/.github/workflows/inspectra.yaml

# Mode 2 — reusable workflow (called from another repo)
uses: Challa823/inspectra-github-workflow/.github/workflows/inspectra-rwf.yaml@main
with:
  files_glob: "**/*.{properties,yml,yaml}"
  branch: main
```

---

## 2. Architecture Diagrams

### 2.1 Sequence Diagram

```mermaid
sequenceDiagram
    participant Repo
    participant GHA as GitHub Actions
    participant RWF as Reusable Workflow
    participant PS as Python Scripts
    participant AI as AI Model
    participant MDB as MongoDB

    Repo->>GHA: Trigger Workflow
    GHA->>RWF: Run inspectra-rwf.yaml
    RWF->>PS: collect_endpoints.py
    PS-->>RWF: endpoints.json (with file & line mapping)
    RWF->>PS: endpoint_tls_scans.py (openssl)
    PS-->>RWF: endpoints_scan.json
    RWF->>PS: detect_jdk.py
    RWF->>PS: fetch_java_releases.py
    PS-->>RWF: jdk_info.json + java_releases.json
    RWF->>PS: extract_tls_context.py
    PS-->>RWF: tls_context.json
    RWF->>AI: Send prompt_system + prompt_user
    AI-->>RWF: ai_response.json
    RWF->>PS: extract_analysis.py
    PS-->>RWF: analysis.json
    RWF->>PS: generate_reports.py
    PS-->>RWF: markdown + SARIF + Sonar JSON
    RWF->>PS: seed_loader.py
    PS->>MDB: Insert run data
    RWF-->>Repo: Commit /security/reports/*
```

### 2.2 Reusable vs Standalone Workflow

```
┌────────────────────────────┐        ┌───────────────────────────────────────┐
│   Caller Repository        │        │  Inspectra Workflow Repository         │
│                            │        │  (Challa823/inspectra-github-workflow) │
│  .github/workflows/        │        │                                        │
│  caller.yaml               │  calls │  .github/workflows/                   │
│  ──────────────            │───────▶│  inspectra-rwf.yaml                   │
│  uses: Challa823/          │        │  (checks out caller repo)              │
│  inspectra-github-         │        │  (checks out workflow_repo/)           │
│  workflow/...              │        │  (runs all scripts from workflow_repo/)│
└────────────────────────────┘        └───────────────────────────────────────┘

─────────────────────────────────────────

┌────────────────────────────────────────┐
│  Inspectra Self-Hosted (standalone)    │
│  .github/workflows/inspectra.yaml      │
│  (scripts/ and mongodb/ are local)     │
└────────────────────────────────────────┘
```

### 2.3 Data Flow Diagram

```mermaid
flowchart LR
    A["config/\n*.properties\n*.yml / *.yaml"] -->|URLs extracted| B[endpoints.json\nhost:port, file, line, env]
    B -->|openssl s_client| C[endpoints_scan.json\ntls_protocol, cipher,\ncert, errors]
    D[jdk_info.json] --> E[tls_context.json]
    F[java_releases.json] --> E
    C --> E
    E -->|build_prompt.py| G[prompt_system.txt\nprompt_user.txt]
    G -->|gpt-4o| H[ai_response.json]
    H -->|extract_analysis.py\njoin on tls×cipher| I[analysis.json\nseverity-rated rows]
    I --> J[tls-audit.md]
    I --> K[tls-audit.sarif]
    I --> L[sonar-tls-audit.json]
    I --> M[(MongoDB\n8 collections)]
```

### 2.4 Data Model

```mermaid
erDiagram
    RUN_METADATA {
        string run_id
        string repo
        string branch
        datetime executed_at
        object severity_summary
    }
    ENDPOINT_TLS_SCANS {
        string run_id
        string endpoint_key
        string tls_version
        string cipher
        string cert_expires
        string errors
        datetime observed_at
    }
    COMPATIBILITY_DECISIONS {
        string run_id
        string endpoint_key
        string now_status
        string futureMinor
        string futureMajor
        string severity
        string reason
        string action
    }
    ENDPOINTS_CATALOG {
        string endpoint_key
        string host
        int    port
        string source_file
        int    line
        string git_link
    }
    POSTURE_CURRENT {
        string   endpoint_key
        string   severity
        string   reason
        string   action
        string   last_run_id
        datetime last_updated
    }

    RUN_METADATA      ||--o{ ENDPOINT_TLS_SCANS       : "contains"
    RUN_METADATA      ||--o{ COMPATIBILITY_DECISIONS   : "generates"
    ENDPOINTS_CATALOG ||--o{ POSTURE_CURRENT           : "updates"
```

---

## 3. High-Level Design (HLD)

### 3.1 System Components

| Component | Technology | Role |
|---|---|---|
| Orchestration | GitHub Actions | Pipeline scheduling, secrets, step ordering |
| Endpoint Discovery | Python (`collect_endpoints.py`) | URL extraction from config files |
| TLS Scanner | Python + OpenSSL (`endpoint_tls_scans.py`) | Live handshake per endpoint |
| JDK Inspector | Python + `java -version` (`detect_jdk.py`) | Detects runner JDK |
| Release Fetcher | Python + HTTP (`fetch_java_releases.py`) | Oracle GA/EOL metadata |
| Context Builder | Python (`extract_tls_context.py`) | Merges all inputs into a single JSON for AI |
| Prompt Builder | Python (`build_prompt.py`) | Constructs system + user prompts |
| AI Engine | GitHub Models — `gpt-4o` | Compatibility scoring per TLS×Cipher pair |
| Analysis Extractor | Python (`extract_analysis.py`) | Joins AI output with scan data |
| Report Builder | Python (`build_markdown_report.py`, `generate_reports.py`) | Markdown, SARIF, Sonar |
| Persistence | Python + PyMongo (`mongodb/seed_loader.py`) | MongoDB upsert |
| Version Control | `git` (via Actions bot) | Report commit |

### 3.2 Security Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│  GitHub Actions Secrets                                      │
│  ─────────────────────                                       │
│  GH_TOKEN   → GitHub PAT — used only for Models API call    │
│  MONGO_URI  → MongoDB Atlas SRV URI (optional)              │
└─────────────────────────────────────────────────────────────┘

No secrets written to disk. Reports contain endpoint URLs but
no credentials. SARIF uploaded to GitHub Code Scanning (private
by default for private repos).
```

### 3.3 Triggering Strategies

| Trigger | Workflow | Notes |
|---|---|---|
| Push to any branch | `inspectra.yaml` | Runs full pipeline on every push |
| Manual dispatch | `inspectra.yaml` | Accepts `files_glob` and `branch` inputs |
| `workflow_call` | Both | Callable from any external repo |
| Caller repo push | `inspectra-rwf.yaml` | Caller checkout + workflow script checkout |

---

## 4. Low-Level Design (LLD)

### 4.1 Script Reference

#### `scripts/detect_jdk.py`

| Item | Detail |
|---|---|
| Input | None (queries `java -version`) |
| Output | `jdk_info.json` — `{vendor, version, major}` |
| Error handling | Returns `{vendor:"Unknown", version:"Unknown", major:0}` on failure |

#### `scripts/collect_endpoints.py`

| Item | Detail |
|---|---|
| Input | `--files-glob` pattern, `--base-dir` |
| Output | `endpoints.txt` (host:port list), `endpoints.json` (structured — includes `url`, `file`, `line`, `env`, `host_port`) |
| URL pattern | `https?://[^\s\'">,;{}()\[\]]+` |
| Env detection | Parsed from filename (`application-{env}.yml`) or folder name |
| Deduplication | Per `(host_port, source_file)` pair |

#### `scripts/endpoint_tls_scans.py`

| Item | Detail |
|---|---|
| Input | `--endpoints-json endpoints.json` |
| Output | `endpoints_scan.json` — array of scan results |
| Scan method | `openssl s_client -brief -connect host:port` |
| Extracted fields | `tlsProtocol`, `cipherSuite`, `certificate.subject`, `certificate.issuer`, `certificate.not_after`, `certificate.days_to_expiry`, `errors[]` |
| Timeout | 5 seconds per endpoint |
| Entry point | `scan_all_tls_endpoints()` |

#### `scripts/fetch_java_releases.py`

| Item | Detail |
|---|---|
| Output | `java_releases.json` — list of Java release objects |
| Source | Oracle / Adoptium public API (or GitHub releases) |
| `continue-on-error` | Yes — failure degrades gracefully (AI uses "Unknown" verdicts) |

#### `scripts/extract_tls_context.py`

| Item | Detail |
|---|---|
| Inputs | `jdk_info.json`, `java_releases.json`, `endpoints_scan.json` |
| Output | `tls_context.json` — single merged JSON for prompt consumption |
| Key fields | `CurrentJdkVersion`, `futureJDKMinorUpgradeVersion`, `FutureMajorUpgradedVersion`, endpoint scan rows, unique TLS/cipher pairs, unique errors |

#### `scripts/build_prompt.py`

| Item | Detail |
|---|---|
| Input | `tls_context.json` |
| Output | `prompt_system.txt`, `prompt_user.txt` |
| System prompt | Defines severity rules, output schema, normalization rules |
| User prompt template | Substitutes `<<<TLS_CONTEXT_JSON>>>` with actual context |

#### `scripts/call_github_models.py`

| Item | Detail |
|---|---|
| Inputs | `--system-file`, `--prompt-file` |
| Output | `ai_response.json` — raw GitHub Models API response |
| Model | `gpt-4o` via `https://models.inference.ai.azure.com` |
| Auth | `GITHUB_TOKEN` secret (must be a PAT — auto `GITHUB_TOKEN` returns 403) |
| Output format | `choices[0].message.content` contains `extraction`, `compatibility[]`, `highSummaryFromErrors`, `endpoints_scan_augmented[]` |

#### `scripts/extract_analysis.py`

| Item | Detail |
|---|---|
| Inputs | `ai_response.json`, `endpoints_scan.json` |
| Output | `analysis.json` (flat joined rows), `summary.txt` |
| Join key | `(tlsProtocol, cipherSuite)` from scan ↔ `(tls version, Cipher version)` from AI |
| Output row fields | `endpoint`, `env`, `source_file`, `source_line`, `url`, `tlsProtocol`, `cipherSuite`, `CurrentJDKVersion`, `futureJDKMinorUpgradeVersion`, `FutureMajorUpgradedVersion`, `CurrentJdkTlsStatus`, `FutureJdkMinorTlsStatus`, `FutureJdkMajorTlsStatus`, `severity`, `reason`, `action`, `certificate.*`, `errors[]`, `compatibility{}` |

#### `scripts/build_markdown_report.py`

| Item | Detail |
|---|---|
| Inputs | `analysis.json`, `ai_response.json`, `tls_context.json`, `endpoints.json`, `jdk_info.json` |
| Output | `security/reports/tls-audit.md` |
| Sections | Severity Summary table → Endpoint Detail table |
| Sorting | `CRITICAL → HIGH → WARNING → INFO`, then env, then host:port |
| Step summary | Appended to `$GITHUB_STEP_SUMMARY` if the env var is set |
| Severity utils | `severity_rank()`, `count_severities()`, `determine_severity()` |

#### `scripts/generate_reports.py`

| Item | Detail |
|---|---|
| Inputs | `analysis.json`, `endpoints.json` |
| Output | `tls-audit.sarif`, `sonar-tls-audit.json` |
| SARIF | Rule `TLS001`, level = `error`/`warning`/`note`, `runs[0].properties.severitySummary` |
| Sonar | Generic Issue format, `severitySummary` at root |
| Severity map | `CRITICAL → error / BLOCKER`, `HIGH → error / CRITICAL`, `WARNING → warning / MAJOR`, `INFO → note / INFO` |

#### `mongodb/seed_loader.py`

| Item | Detail |
|---|---|
| Inputs | All report files via `--reports-dir`, plus run metadata flags |
| Output | Upserts into 8 MongoDB collections |
| Key function | `build_severity_summary(analysis)` → `{critical, high, warning, info}` |
| `severity_summary` stored in | `workflow_runs` document |
| `--dry-run` | Prints documents without writing |
| Connection | `pymongo[srv]` via `MONGO_URI` secret |

### 4.2 Workflow Step Order

```
Step  1  Checkout caller repo
Step  2  Checkout workflow_repo (reusable only)
Step  3  Setup Python 3.11
Step  4  pip install -r requirements.txt
Step  5  mkdir -p security/reports
Step  6  detect_jdk.py           → jdk_info.json
Step  7  collect_endpoints.py    → endpoints.txt, endpoints.json
Step  8  endpoint_tls_scans.py   → endpoints_scan.json
Step  9  fetch_java_releases.py  → java_releases.json       [continue-on-error]
Step 10  extract_tls_context.py  → tls_context.json
Step 11  build_prompt.py         → prompt_system.txt, prompt_user.txt
Step 12  call_github_models.py   → ai_response.json
Step 13  extract_analysis.py     → analysis.json, summary.txt
Step 14  build_markdown_report.py → tls-audit.md
Step 15  seed_loader.py          → MongoDB (8 collections)   [if: always()]
Step 16  generate_reports.py     → tls-audit.sarif, sonar-tls-audit.json
Step 17  Upload SARIF            → GitHub Code Scanning
Step 18  git commit + push       → security/reports/
```

### 4.3 File Artifacts Map

```
security/reports/
├── jdk_info.json              ← detect_jdk.py
├── endpoints.txt              ← collect_endpoints.py
├── endpoints.json             ← collect_endpoints.py
├── endpoints_scan.json        ← endpoint_tls_scans.py
├── java_releases.json         ← fetch_java_releases.py
├── tls_context.json           ← extract_tls_context.py
├── prompt_system.txt          ← build_prompt.py
├── prompt_user.txt            ← build_prompt.py
├── ai_response.json           ← call_github_models.py
├── analysis.json              ← extract_analysis.py
├── summary.txt                ← extract_analysis.py
├── tls-audit.md               ← build_markdown_report.py
├── tls-audit.sarif            ← generate_reports.py
└── sonar-tls-audit.json       ← generate_reports.py
```

---

## 5. MongoDB Schema

### 5.1 Database: `inspectra`

Eight collections, all using `schema_version: 1`.

```
inspectra (database)
├── workflow_runs          ← one doc per GitHub Actions run
├── jdk_snapshots          ← JDK detected per run (TTL 90 days)
├── endpoint_tls_scans     ← raw SSL handshake per endpoint per run (TTL 30 days)
├── tls_scan_findings      ← AI-enriched finding per endpoint per run (TTL 90 days)
├── tls_endpoint_posture   ← latest-per-endpoint materialized view
├── certificate_expiry     ← cert expiry tracking (TTL 395 days)
├── ai_model_invocations   ← one doc per LLM call (TTL 90 days)
└── java_releases_cache    ← Oracle GA/EOL cache (TTL 7 days)
```

### 5.2 Collection Details

#### `workflow_runs`

Primary parent document. One document per `{org}/{repo}#{run_id}`.

| Field | Type | Description |
|---|---|---|
| `_id` | String | `{org}/{repo}#{run_id}` |
| `org` | String | GitHub organisation |
| `repo` | String | Repository name |
| `branch` | String | Scanned branch |
| `run_id` | String | `GITHUB_RUN_ID` |
| `workflow_file` | String | e.g. `inspectra-rwf.yaml` |
| `triggered_by` | String | GitHub actor login |
| `status` | Enum | `queued │ in_progress │ completed │ failed` |
| `conclusion` | Enum | `success │ failure │ cancelled │ skipped` |
| `git_sha` | String | Commit SHA |
| `caller_repo` | String | Caller repo (reusable workflow only) |
| `severity_summary` | Object | `{critical, high, warning, info}` counts |
| `created_at` | Date | |
| `updated_at` | Date | |
| `completed_at` | Date | |

#### `jdk_snapshots`

| Field | Type | Description |
|---|---|---|
| `run_id` | String | FK → `workflow_runs` |
| `vendor` | String | e.g. `openjdk` |
| `version` | String | e.g. `17.0.18` |
| `major` | Int | e.g. `17` |
| `future_minor_version` | String | Next minor JDK version |
| `future_major_version` | String | Next major JDK version |
| `observed_at` | Date | |
| TTL | 90 days | On `created_at` |

#### `endpoint_tls_scans`

Raw scanner output. One document per `{run_id}::{endpoint}::{source_file}`.

| Field | Type | Description |
|---|---|---|
| `endpoint` | String | `host:port` |
| `tls_protocol` | String | e.g. `TLSv1.3` |
| `cipher_suite` | String | e.g. `TLS_AES_256_GCM_SHA384` |
| `certificate.subject` | String | |
| `certificate.issuer` | String | |
| `certificate.not_after` | Date | Cert expiry timestamp |
| `certificate.days_to_expiry` | Int | |
| `errors[]` | Array | OpenSSL error lines |
| `source_file` | String | Config file path |
| TTL | 30 days | On `created_at` |

#### `tls_scan_findings`

AI-enriched findings. Primary analytics collection.

| Field | Type | Description |
|---|---|---|
| `tls_version` | String | Observed TLS version |
| `cipher_version` | String | Observed cipher suite |
| `current_jdk_version` | String | e.g. `17.0.18` |
| `future_jdk_minor_version` | String | |
| `current_jdk_tls_status` | Enum | `Supported │ Not Supported │ Unknown` |
| `future_jdk_minor_tls_status` | Enum | `Supported │ Not Supported │ Unknown` |
| `future_jdk_major_tls_status` | Enum | `Supported │ Not Supported │ Unknown` |
| `severity` | Enum | `CRITICAL │ HIGH │ WARNING │ INFO` |
| `reason` | String | ≤140 chars |
| `action` | String | ≤140 chars |
| TTL | 90 days | On `created_at` |

#### `tls_endpoint_posture`

Latest-per-endpoint materialized view. One document per `{org}/{repo}/{endpoint}`.

| Field | Type | Description |
|---|---|---|
| `worst_severity` | Enum | `CRITICAL │ HIGH │ WARNING │ INFO` |
| `last_seen_tls` | String | Most recent TLS protocol |
| `last_run_id` | String | Run that last updated this |
| `cert_expiry_days` | Int | Days until cert expires |

#### `certificate_expiry`

| Field | Type | Description |
|---|---|---|
| `endpoint` | String | `host:port` |
| `subject` | String | Cert subject |
| `issuer` | String | Cert issuer |
| `not_after` | Date | Expiry timestamp |
| `days_to_expiry` | Int | |
| TTL | 395 days | On `not_after` |

#### `ai_model_invocations`

| Field | Type | Description |
|---|---|---|
| `model` | String | e.g. `gpt-4o` |
| `prompt_tokens` | Int | |
| `completion_tokens` | Int | |
| `total_tokens` | Int | |
| `duration_ms` | Int | Wall-clock time |
| `status` | Enum | `success │ error` |
| TTL | 90 days | On `created_at` |

#### `java_releases_cache`

| Field | Type | Description |
|---|---|---|
| `source` | String | `oracle │ adoptium` |
| `releases[]` | Array | Raw release objects |
| TTL | 7 days | On `fetched_at` |

### 5.3 Indexes

```javascript
// workflow_runs
{ org: 1, repo: 1, created_at: -1 }  // tenant queries
{ branch: 1, created_at: -1 }         // branch history

// tls_scan_findings
{ org: 1, repo: 1, severity: 1, created_at: -1 }  // severity dashboards
{ endpoint: 1, severity: 1 }                        // endpoint posture

// endpoint_tls_scans
{ run_id: 1, endpoint: 1 }            // run detail lookup

// certificate_expiry
{ not_after: 1 }                      // expiry alerts
{ endpoint: 1 }                       // per-endpoint cert history

// java_releases_cache
{ source: 1, fetched_at: -1 }         // cache invalidation
```

### 5.4 MongoDB Atlas Setup (Quick)

```bash
# 1. Apply validators
mongosh inspectra < mongodb/validation.js

# 2. Create indexes
mongosh inspectra < mongodb/indexes.js

# 3. Dry-run seed to verify
python mongodb/seed_loader.py --dry-run --reports-dir security/reports \
  --org myorg --repo myrepo --branch main --run-id test-001
```

---

## 6. Severity Model

### 6.1 Scale

| Level | Meaning |
|---|---|
| **CRITICAL** | Endpoint TLS is broken NOW. Immediate action required. |
| **HIGH** | Working now but will break at next scheduled JDK minor upgrade. |
| **WARNING** | Compatibility at next minor upgrade is unknown — verify manually. |
| **INFO** | Endpoint is compatible with current and future minor JDK. |

### 6.2 Decision Rules

Rules are evaluated top-to-bottom; first match wins.

```
Rule 1 (& 5):  currentJdkTlsStatus == "Not Supported"
               → CRITICAL   (endpoint is broken today)

Rule 2:        currentJdkTlsStatus == "Supported"
               AND futureMinorJdkTlsStatus == "Not Supported"
               → HIGH       (will break after minor upgrade)

Rule 3:        currentJdkTlsStatus == "Supported"
               AND futureMinorJdkTlsStatus == "Unknown"
               → WARNING    (future compatibility undetermined)

Rule 4:        currentJdkTlsStatus == "Supported"
               AND futureMinorJdkTlsStatus == "Supported"
               → INFO       (no action needed)

Note: futureMajorJdkTlsStatus is informational only — it does NOT
      influence severity unless Rule 1 is triggered.
```

### 6.3 Status Normalization

The AI is instructed to normalize all status strings before applying rules:

| Raw value | Normalized |
|---|---|
| `"supported"`, `"ok"`, `"true"` | `Supported` |
| `"not supported"`, `"false"`, `"fail"`, `"no"` | `Not Supported` |
| `""`, `null`, `"unknown"` | `Unknown` |

### 6.4 Severity in Reports

| Report | CRITICAL | HIGH | WARNING | INFO |
|---|---|---|---|---|
| Markdown | Top of table | Second | Third | Last |
| SARIF | `level: error` | `level: error` | `level: warning` | `level: note` |
| SonarQube | `BLOCKER` | `CRITICAL` | `MAJOR` | `INFO` |
| MongoDB | `"CRITICAL"` | `"HIGH"` | `"WARNING"` | `"INFO"` |

### 6.5 Severity Summary

Every run produces a summary counts object:

```json
{ "CRITICAL": 3, "HIGH": 7, "WARNING": 12, "INFO": 45 }
```

Stored in:
- `workflow_runs.severity_summary` (MongoDB, lowercase keys)
- `runs[0].properties.severitySummary` (SARIF)
- `severitySummary` root field (SonarQube)
- `## Severity Summary` table header (Markdown)

---

## 7. Installation Guide

### 7.1 Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| GitHub Actions | — | Any plan; free tier supports reusable workflows |
| Python | 3.11+ | Auto-provisioned on `ubuntu-latest` |
| OpenSSL | 1.1.1+ | Installed on `ubuntu-latest` by default |
| MongoDB Atlas | M0+ | Optional — skip `MONGO_URI` secret to disable persistence |
| GitHub PAT | `models:read` | Required for GitHub Models API |

### 7.2 Required Secrets

| Secret | Required | Description |
|---|---|---|
| `GH_TOKEN` | **Yes** | GitHub Personal Access Token with `models:read` scope. The auto `GITHUB_TOKEN` returns HTTP 403 from the Models API. |
| `MONGO_URI` | Optional | MongoDB Atlas SRV connection string, e.g. `mongodb+srv://user:pass@cluster.mongodb.net/` |

Add secrets at: **Settings → Secrets and variables → Actions → New repository secret**

### 7.3 Mode A — Standalone

`inspectra.yaml` is already present in this repository. Push to any branch to trigger.

```yaml
# Trigger manually with custom settings
gh workflow run inspectra.yaml \
  -f files_glob="config/**/*.{properties,yml,yaml}" \
  -f branch=main
```

### 7.4 Mode B — Reusable Workflow (caller repo)

1. In the **caller** repository, create `.github/workflows/tls-audit.yaml`:

```yaml
name: TLS Audit
on:
  push:
    branches: [main]
  schedule:
    - cron: '0 3 * * 1'   # Weekly Monday 03:00 UTC

jobs:
  inspectra:
    uses: Challa823/inspectra-github-workflow/.github/workflows/inspectra-rwf.yaml@main
    with:
      files_glob: "**/*.{properties,yml,yaml}"
      branch: main
    secrets: inherit
```

2. Add `GH_TOKEN` (and optionally `MONGO_URI`) to the caller repo's secrets.
3. Grant the caller repo permission to call the reusable workflow if your org restricts it.

### 7.5 Python Dependencies

```
requests>=2.31.0
pymongo[srv]>=4.6.0
dnspython>=2.4.0
```

```bash
pip install -r requirements.txt
```

### 7.6 MongoDB Setup

```bash
# Apply validators and indexes
mongosh inspectra < mongodb/validation.js
mongosh inspectra < mongodb/indexes.js

# Test with a dry run
python mongodb/seed_loader.py \
  --dry-run \
  --reports-dir security/reports \
  --org myorg --repo myrepo \
  --branch main --run-id 999 \
  --git-sha abc123 --workflow-file inspectra.yaml
```

---

## 8. Developer Guide

### 8.1 Repository Layout

```
inspectra-github-workflow/
├── .github/
│   └── workflows/
│       ├── inspectra.yaml          ← Standalone workflow
│       └── inspectra-rwf.yaml      ← Reusable workflow
├── scripts/
│   ├── detect_jdk.py               ← Step  6: JDK detection
│   ├── collect_endpoints.py        ← Step  7: URL extraction
│   ├── endpoint_tls_scans.py       ← Step  8: TLS/cert scanning
│   ├── fetch_java_releases.py      ← Step  9: Java release API
│   ├── extract_tls_context.py      ← Step 10: Context merge
│   ├── build_prompt.py             ← Step 11: Prompt construction
│   ├── call_github_models.py       ← Step 12: AI API call
│   ├── extract_analysis.py         ← Step 13: Join + flatten
│   ├── build_markdown_report.py    ← Step 14: Markdown output
│   └── generate_reports.py         ← Step 16: SARIF + Sonar
├── mongodb/
│   ├── seed_loader.py              ← Step 15: MongoDB upsert
│   ├── schema_contract.json        ← Canonical field definitions
│   ├── indexes.js                  ← Index creation script
│   ├── validation.js               ← $jsonSchema validators
│   └── README.md                   ← MongoDB-specific docs
├── config/                         ← Sample config files for scanning
│   ├── application-dsit.properties
│   ├── application-rqa.yaml
│   ├── application-staging.yml
│   ├── dsit/
│   └── prod/
├── security/
│   └── reports/                    ← Generated artefacts (git-committed)
├── requirements.txt
└── README.md
```

### 8.2 Adding a New Script Step

1. Create `scripts/my_script.py` with a `if __name__ == "__main__":` block.
2. Add the step in **both** workflow YAML files:
   - `inspectra.yaml` → `python scripts/my_script.py`
   - `inspectra-rwf.yaml` → `python workflow_repo/scripts/my_script.py`
3. Update the artifacts map above if the script produces new output files.
4. If a new MongoDB collection is needed, update `schema_contract.json`, `validation.js`, `indexes.js`, and `seed_loader.py`.

### 8.3 Running Scripts Locally

```bash
# Clone and install
git clone https://github.com/Challa823/inspectra-github-workflow.git
cd inspectra-github-workflow
pip install -r requirements.txt
mkdir -p security/reports

# Step 6 — JDK
python scripts/detect_jdk.py --output security/reports/jdk_info.json

# Step 7 — Endpoints
python scripts/collect_endpoints.py \
  --files-glob "**/*.{properties,yml,yaml}" \
  --base-dir config \
  --output security/reports/endpoints.txt

# Step 8 — TLS scan
python scripts/endpoint_tls_scans.py \
  --endpoints-json security/reports/endpoints.json \
  --output security/reports/endpoints_scan.json

# Step 9 — Java releases
python scripts/fetch_java_releases.py \
  --output security/reports/java_releases.json

# Step 10 — TLS context
python scripts/extract_tls_context.py \
  --jdk-info       security/reports/jdk_info.json \
  --java-releases  security/reports/java_releases.json \
  --endpoints-scan security/reports/endpoints_scan.json \
  --output         security/reports/tls_context.json

# Step 11 — Prompts
python scripts/build_prompt.py \
  --tls-context security/reports/tls_context.json \
  --system-out  security/reports/prompt_system.txt \
  --user-out    security/reports/prompt_user.txt

# Step 12 — AI call (requires PAT)
export GITHUB_TOKEN=ghp_xxxxxxxxxxxx
python scripts/call_github_models.py \
  --system-file security/reports/prompt_system.txt \
  --prompt-file security/reports/prompt_user.txt \
  --output      security/reports/ai_response.json

# Step 13 — Analysis
python scripts/extract_analysis.py \
  --model-response security/reports/ai_response.json \
  --endpoints-scan security/reports/endpoints_scan.json \
  --output         security/reports/analysis.json \
  --summary-out    security/reports/summary.txt

# Step 14 — Markdown
python scripts/build_markdown_report.py \
  --analysis    security/reports/analysis.json \
  --ai-response security/reports/ai_response.json \
  --output-md   security/reports/tls-audit.md

# Step 15 — MongoDB (optional)
export MONGO_URI="mongodb+srv://user:pass@cluster.mongodb.net/"
python mongodb/seed_loader.py \
  --mongo-uri "$MONGO_URI" --db inspectra \
  --org myorg --repo myrepo --branch main \
  --run-id local-001 --reports-dir security/reports

# Step 16 — SARIF + Sonar
python scripts/generate_reports.py \
  --analysis       security/reports/analysis.json \
  --endpoints-json security/reports/endpoints.json \
  --out-dir        security/reports
```

### 8.4 Severity Helper Reference

All three report scripts expose equivalent severity utilities:

```python
# Severity rank for sorting (lower number = worse = shown first in table)
severity_rank(sev: str) -> int
# CRITICAL=0, HIGH=1, WARNING=2, INFO=3, else=4

# Count per severity across a list of finding rows/items
count_severities(rows: list) -> dict
# Returns {"CRITICAL": n, "HIGH": n, "WARNING": n, "INFO": n}

# Derive severity from TLS status strings
determine_severity(now, fut_minor_status, fut_major_status) -> str
# Applies Rules 1–4 as defined in Section 6.2
```

### 8.5 Environment Detection in `collect_endpoints.py`

The environment name is auto-detected from the config file path using three strategies (first match wins):

1. **Filename suffix**: `application-{env}.yml` → env = `{env}`
2. **First non-generic folder**: traverses path parts, skips `src`, `main`, `resources`, `config`, `conf`, `settings`, `environments`, `env`, `application`, `services`, `api`, `app`, `project`
3. **Filename itself**: if neither strategy matches, the bare filename becomes the env label.

To control the environment label: rename the file or folder accordingly.

### 8.6 Adding a New Severity Level

> The scale is `CRITICAL / HIGH / WARNING / INFO`. Adding a new level requires changes to **7 locations**:

1. `scripts/build_prompt.py` — SYSTEM_PROMPT + USER_TEMPLATE severity rules
2. `scripts/build_markdown_report.py` — `severity_rank()`, `SEVERITY_ORDER`, `determine_severity()`
3. `scripts/generate_reports.py` — `_SEVERITY_ORDER`, SARIF level map, Sonar severity map
4. `scripts/extract_analysis.py` — fallback severity string
5. `mongodb/seed_loader.py` — `SEVERITY_RANK`, `_SEVERITY_ORDER`, `build_severity_summary()`
6. `mongodb/validation.js` — `severity` and `worst_severity` enums
7. `mongodb/schema_contract.json` — `severity` enum in `tls_scan_findings` and `tls_endpoint_posture`

---

## 9. Use Cases

### UC-01 — Continuous TLS Posture Monitoring

**Actor:** Security team  
**Trigger:** Developer pushes code to any branch  
**Flow:**
1. Push triggers `inspectra.yaml`
2. All HTTPS endpoints in config files are discovered and scanned
3. CRITICAL/HIGH findings appear in GitHub Code Scanning via SARIF upload
4. Markdown summary posted to Step Summary in the Actions tab
5. Results persisted to MongoDB for trend analysis

**Value:** Catch TLS regressions before they reach production.

---

### UC-02 — JDK Upgrade Impact Assessment

**Actor:** Platform engineering planning JDK 17 → 21  
**Trigger:** Manual `workflow_dispatch` on the candidate branch  
**Flow:**
1. Dispatch with `branch: feature/jdk21-upgrade`
2. `detect_jdk.py` captures JDK 17.0.x as the current version
3. `fetch_java_releases.py` identifies JDK 21 as `FutureMajorUpgradedVersion`
4. AI evaluates each TLS×Cipher pair for compatibility at JDK 21
5. `analysis.json` lists all endpoints with `FutureJdkMajorTlsStatus: "Not Supported"`
6. Report shows which endpoints need cipher updates before the upgrade

**Value:** Zero-surprise JDK upgrades.

---

### UC-03 — Certificate Expiry Alerting

**Actor:** SRE on-call  
**Trigger:** Scheduled weekly run  
**Flow:**
1. Workflow runs on cron `0 3 * * 1`
2. `endpoint_tls_scans.py` extracts `certificate.not_after` and `days_to_expiry`
3. `seed_loader.py` upserts into `certificate_expiry` collection
4. External dashboards (Grafana / Atlas Charts) alert when `days_to_expiry < 30`

**Value:** Proactive cert renewal — no more expired cert outages.

---

### UC-04 — Multi-Repository TLS Governance

**Actor:** Enterprise security team managing 100+ repos  
**Trigger:** Each repo calls `inspectra-rwf.yaml` on push  
**Flow:**
1. Every repo has `.github/workflows/tls-audit.yaml` pointing to `inspectra-rwf.yaml@main`
2. All data lands in the same `MONGO_URI` / `inspectra` database
3. `workflow_runs.org` and `workflow_runs.repo` partition data per team
4. Org-level dashboard queries `tls_scan_findings` across all repos for CRITICAL findings

**Value:** Centralised TLS posture for the entire organisation.

---

### UC-05 — SonarQube Quality Gate Integration

**Actor:** Dev team with SonarQube quality gates  
**Trigger:** PR build pipeline  
**Flow:**
1. Inspectra runs as a pipeline step before SonarScanner
2. `sonar-tls-audit.json` fed to SonarScanner via `--genericissues`
3. CRITICAL/HIGH findings fail the Quality Gate
4. PR blocked until findings are resolved

**Value:** TLS security enforced at code-review time.

---

### UC-06 — AI Decision Auditability

**Actor:** Compliance / audit team  
**Trigger:** Periodic review of AI-generated verdicts  
**Flow:**
1. `ai_model_invocations` collection records every call: model name, token counts, duration, status
2. `prompt_system.txt` and `prompt_user.txt` committed to `security/reports/` on every run
3. `ai_response.json` committed alongside — full chain of custody from prompt to verdict

**Value:** Traceable, auditable AI-assisted security decisions.

---

## 10. Troubleshooting

### T-01 — `403 Forbidden` from GitHub Models API

**Symptom:** `call_github_models.py` exits with HTTP 403.  
**Cause:** The automatic `GITHUB_TOKEN` does not have `models:read` permission.  
**Fix:**
1. Create a PAT: **github.com → Settings → Developer settings → Fine-grained tokens**
2. Grant scope: `models:read` (under Account permissions)
3. Add it as a repository secret named `GH_TOKEN`
4. Confirm your YAML uses `${{ secrets.GH_TOKEN }}` (not `${{ secrets.GITHUB_TOKEN }}`)

---

### T-02 — No endpoints discovered

**Symptom:** `endpoints.json` is empty; reports are blank.

| Cause | Fix |
|---|---|
| Wrong `files_glob` | Default is `**/*.{properties,yml,yaml}`. Pass explicitly if files use different extensions. |
| Files contain no `https://` URLs | Only HTTP/HTTPS URLs are extracted. JDBC URLs etc. are not scanned. |
| Wrong `base-dir` | Ensure `--base-dir` points to the root where config files live. |

---

### T-03 — OpenSSL connection timeout or refused

**Symptom:** `endpoints_scan.json` entries show `errors: ["Connection refused"]` or empty TLS fields.  
**Causes:**
- Endpoint is behind a firewall inaccessible from GitHub Actions runners
- Endpoint is an internal-only hostname
- Port is wrong

**Fix:**
- For internal endpoints, use self-hosted runners on the same network.
- Filter internal-only config files using a narrower `files_glob`.

---

### T-04 — AI response is not valid JSON

**Symptom:** `extract_analysis.py` logs `[WARN] Model response is not valid JSON`.  
**Cause:** `gpt-4o` occasionally wraps output in markdown fences.  
**Fix:** `extract_analysis.py` already handles this with a raw-text fallback entry. If persistent, add fence-stripping in `call_github_models.py` before writing `ai_response.json`.

---

### T-05 — MongoDB connection failure

**Symptom:** `seed_loader.py` exits with `ServerSelectionTimeoutError`.

| Cause | Fix |
|---|---|
| `MONGO_URI` secret not set | Add the secret or use `--dry-run` for testing without MongoDB. |
| IP whitelist | Add GitHub Actions IP ranges to your Atlas Network Access list. |
| Wrong URI format | Must be `mongodb+srv://...` for Atlas. Local: `mongodb://localhost:27017/` |

```bash
# Test without MongoDB
python mongodb/seed_loader.py --dry-run --reports-dir security/reports \
  --org myorg --repo myrepo --branch main --run-id test-001
```

---

### T-06 — `git push` fails in commit step

**Symptom:** `error: failed to push some refs to ...`  
**Cause:** Concurrent run pushed between checkout and commit.  
**Fix:** Add `git pull --rebase` before the push:

```yaml
- name: Commit reports
  run: |
    git config user.name  "github-actions[bot]"
    git config user.email "github-actions[bot]@users.noreply.github.com"
    git pull --rebase origin ${{ github.ref_name }} || true
    git add security/reports/
    git commit -m "TLS audit reports [skip ci]" || echo "No changes"
    git push
```

---

### T-07 — SARIF upload fails schema validation

**Symptom:** `upload-sarif` action fails with "Invalid SARIF file".  
**Fix:**
1. Validate: `python -c "import json; json.load(open('security/reports/tls-audit.sarif'))"`
2. Ensure `analysis.json` is a non-empty list before `generate_reports.py` runs.
3. Add `continue-on-error: true` to the upload step if SARIF is non-critical.

---

### T-08 — All severities show as `WARNING`

**Symptom:** Every finding has `severity: "WARNING"`.  
**Cause:** AI returns `futureMinorJdkTlsStatus: "Unknown"` for all pairs, triggering Rule 3.  
**Root cause:** `java_releases.json` is empty — without release metadata the AI cannot determine future version support.  
**Fix:**
1. Check the `fetch_java_releases.py` step log for network errors.
2. Inspect `security/reports/java_releases.json` — should contain actual release entries.
3. If Oracle/Adoptium API is unavailable, populate `java_releases.json` manually.

---

### T-09 — Severity summary counts all zero

**Symptom:** `severity_summary: {critical: 0, high: 0, warning: 0, info: 0}` in MongoDB.  
**Cause:** `analysis.json` was empty or missing when `seed_loader.py` ran. The step uses `if: always()` so it runs even after a failed analysis step.  
**Fix:** Confirm `extract_analysis.py` succeeded and `security/reports/analysis.json` is a non-empty JSON array.

---

*Inspectra v1.0 · March 2026*
