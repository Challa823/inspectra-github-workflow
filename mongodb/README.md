# Inspectra — MongoDB Schema Design

**Database:** `inspectra`  
**Version:** 1.0.0  
**Architecture tier:** Production-ready, multi-tenant, Atlas-compatible

---

## 1. Design Principles

| Principle | Decision |
|---|---|
| Multi-tenancy | Partitioned by `org` + `repo` + `branch`; every document carries these fields |
| Embedding vs. Reference | Scan findings embed source-location arrays (low cardinality, always accessed together); workflow runs are referenced by `run_id` string (FK-style) |
| Natural keys | Composite deterministic `_id` where stable; auto ObjectId otherwise |
| Timestamps | ISO 8601 strings — `created_at`, `updated_at`, `observed_at` |
| Retention | TTL indexes on ephemeral raw-scan collections; long-lived "posture" views upserted, never deleted |
| PII | No user PII; endpoint hostnames are infrastructure — treat as internal-confidential |
| Sharding | Shard key candidates noted per collection; enable once data exceeds single-node limits |

---

## 2. Pipeline → Collection Mapping

```
detect_jdk.py          → jdk_snapshots
collect_endpoints.py      → (feeds endpoint_tls_scans; not stored separately)
endpoint_tls_scans.py     → endpoint_tls_scans
fetch_java_releases.py → java_releases_cache
extract_tls_context.py → (ephemeral; data flows into tls_scan_findings)
build_prompt.py        → ai_model_invocations
call_github_models.py  → ai_model_invocations
extract_analysis.py    → tls_scan_findings
generate_reports.py    → (reportartifacts; data already in tls_scan_findings)
build_markdown_report  → (no dedicated collection; reads tls_scan_findings)

GitHub Actions metadata → workflow_runs
Aggregated current view → tls_endpoint_posture (upserted)
Certificate tracking   → certificate_expiry    (upserted)
```

---

## 3. Collections

### 3.1 `workflow_runs`

**Purpose:** One document per GitHub Actions workflow execution. Parent record for all scan telemetry in a run.  
**Access patterns:** Write-once on run start, update on run end; read by run_id for dashboards.  
**TTL:** None — retained as audit log. Consider archiving runs older than 2 years to cold storage.

**Embedding decision:** Status history is embedded (≤20 steps per run, always read together). Artifacts are referenced by `run_id`.

**Key fields:**

| Field | Type | Notes |
|---|---|---|
| `_id` | string | `"{org}/{repo}#{run_id}"` — deterministic, globally unique |
| `org` | string | GitHub org / owner |
| `repo` | string | Repository name |
| `branch` | string | Branch that triggered the run |
| `run_id` | string | GitHub Actions `GITHUB_RUN_ID` |
| `run_number` | int | `GITHUB_RUN_NUMBER` |
| `workflow_file` | string | e.g. `inspectra-rwf.yaml` |
| `triggered_by` | string | Actor login |
| `status` | string | `queued \| in_progress \| completed \| failed` |
| `conclusion` | string | `success \| failure \| cancelled \| null` |
| `created_at` | date | Run start time (UTC) |
| `updated_at` | date | Last status change |
| `completed_at` | date \| null | Run end time |
| `git_sha` | string | `GITHUB_SHA` |
| `caller_repo` | string | Caller repo when using reusable workflow |

**Shard key:** `{ org: 1, repo: 1 }` — good cardinality split per tenant.

---

### 3.2 `jdk_snapshots`

**Purpose:** JDK detected in the scanned repository per workflow run.  
**Source:** `jdk_info.json` (detect_jdk.py) + `tls_context.json` (extract_tls_context.py).  
**TTL:** 90 days (ephemeral telemetry; posture tracked in `tls_endpoint_posture`).

| Field | Type | Notes |
|---|---|---|
| `_id` | ObjectId | Auto |
| `run_id` | string | FK → `workflow_runs._id` |
| `org` | string | |
| `repo` | string | |
| `branch` | string | |
| `vendor` | string | e.g. `openjdk` |
| `version` | string | e.g. `17.0.18` |
| `major` | int | e.g. `17` |
| `future_minor_version` | string | From tls_context; `Unknown` if not determinable |
| `future_major_version` | string | From tls_context; e.g. `21.0.9` |
| `observed_at` | date | Scan timestamp |
| `created_at` | date | Insert time |

---

### 3.3 `endpoint_tls_scans`

**Purpose:** Raw TLS handshake result per (endpoint × source_file × run). Direct output of `endpoint_tls_scans.py` / `endpoints_scan.json`.  
**Cardinality:** ~N endpoints × M config files per run. Expect 10–500 docs per run.  
**TTL:** 30 days — raw handshake data is high-volume and superseded by `tls_scan_findings`.

| Field | Type | Notes |
|---|---|---|
| `_id` | string | `"{run_id}::{endpoint}::{source_file}"` |
| `run_id` | string | FK → `workflow_runs` |
| `org` | string | |
| `repo` | string | |
| `branch` | string | |
| `env` | string | e.g. `dsit`, `prod`, `rqa`, `staging` |
| `endpoint` | string | `host:port` |
| `tls_protocol` | string | e.g. `TLSv1.3`, `<none>` |
| `cipher_suite` | string | e.g. `TLS_AES_256_GCM_SHA384` |
| `certificate` | object | Embedded: `subject`, `issuer`, `not_after`, `days_to_expiry` |
| `errors` | array[string] | e.g. `["timeout"]` |
| `source_file` | string | Config file path |
| `source_line` | int | Line number |
| `source_context` | string | Raw config line |
| `url` | string | Full URL |
| `observed_at` | date | Scan time |
| `created_at` | date | Insert time |

**Embedding decision:** Certificate is embedded — it's always read with the finding and has 1:1 cardinality.

---

### 3.4 `tls_scan_findings`

**Purpose:** AI-enriched TLS compatibility finding per (endpoint × source_file × run). Output of `extract_analysis.py`. The primary analytics collection.  
**TTL:** 90 days for raw run findings. Current posture is maintained as a separate upsert in `tls_endpoint_posture`.

| Field | Type | Notes |
|---|---|---|
| `_id` | string | `"{run_id}::{endpoint}::{source_file}"` |
| `run_id` | string | FK → `workflow_runs` |
| `org` | string | |
| `repo` | string | |
| `branch` | string | |
| `env` | string | Deploy environment |
| `endpoint` | string | `host:port` |
| `tls_version` | string | |
| `cipher_version` | string | |
| `current_jdk_version` | string | |
| `future_jdk_minor_version` | string | |
| `future_jdk_major_version` | string | |
| `current_jdk_tls_status` | string | `Supported \| Not Supported \| Unknown` |
| `future_jdk_minor_tls_status` | string | |
| `future_jdk_major_tls_status` | string | |
| `severity` | string | `CRITICAL \| HIGH \| MEDIUM \| LOW \| OK \| UNKNOWN` |
| `reason` | string | AI-generated rationale |
| `action` | string | AI-generated remediation |
| `source_file` | string | |
| `source_line` | int | |
| `source_url` | string | |
| `compatibility` | object | Embedded backward-compat block from extract_analysis |
| `ai_model` | string | Model used e.g. `gpt-4o-mini-2024-07-18` |
| `observed_at` | date | |
| `created_at` | date | |

---

### 3.5 `tls_endpoint_posture`

**Purpose:** Current (latest) security posture per endpoint per repo. **Upserted on every run** — provides a live dashboard view without time-series overhead.  
**TTL:** None — this is the authoritative current state. Replace, never delete.  
**Access pattern:** High-read, low-write. Primary source for dashboards and alerting.

| Field | Type | Notes |
|---|---|---|
| `_id` | string | `"{org}/{repo}::{endpoint}"` |
| `org` | string | |
| `repo` | string | |
| `endpoint` | string | `host:port` |
| `last_run_id` | string | FK → `workflow_runs` |
| `last_observed_at` | date | Timestamp of last scan |
| `envs` | array[string] | All environments this endpoint appeared in |
| `worst_severity` | string | Highest severity across all findings |
| `tls_version` | string | Most recent TLS version |
| `cipher_version` | string | Most recent cipher |
| `current_jdk_version` | string | |
| `current_jdk_tls_status` | string | |
| `future_jdk_minor_version` | string | |
| `future_jdk_minor_tls_status` | string | |
| `future_jdk_major_version` | string | |
| `future_jdk_major_tls_status` | string | |
| `reason` | string | Latest AI reason |
| `action` | string | Latest AI action |
| `cert_not_after` | date \| null | Certificate expiry |
| `cert_days_to_expiry` | int \| null | Days remaining |
| `cert_issuer` | string | |
| `finding_count` | int | Number of source files referencing this endpoint |
| `updated_at` | date | |

**Shard key:** `{ org: 1, repo: 1 }` — same as `workflow_runs`.

---

### 3.6 `certificate_expiry`

**Purpose:** Deduplicated certificate expiry tracker per endpoint. Enables expiry alerting independent of full scan runs. Upserted on every scan.  
**TTL:** None — kept; stale entries identified by `last_observed_at`.

| Field | Type | Notes |
|---|---|---|
| `_id` | string | `"{org}/{repo}::{endpoint}"` |
| `org` | string | |
| `repo` | string | |
| `endpoint` | string | |
| `subject` | string | |
| `issuer` | string | |
| `not_after` | date | Certificate expiry |
| `days_to_expiry` | int | At time of last scan |
| `is_expired` | bool | `days_to_expiry <= 0` |
| `alert_threshold_days` | int | Default: 30 |
| `last_run_id` | string | |
| `last_observed_at` | date | |
| `updated_at` | date | |

---

### 3.7 `ai_model_invocations`

**Purpose:** Audit log of all GitHub Models API calls — model, tokens, prompt fingerprint, raw content for explainability and cost tracking.  
**TTL:** 30 days — large documents, high PII risk if prompts contain secrets.

| Field | Type | Notes |
|---|---|---|
| `_id` | string | `"{run_id}"` — one invocation per run |
| `run_id` | string | |
| `org` | string | |
| `repo` | string | |
| `model` | string | e.g. `gpt-4o-mini-2024-07-18` |
| `prompt_tokens` | int | |
| `completion_tokens` | int | |
| `total_tokens` | int | |
| `finish_reason` | string | `stop \| length \| content_filter` |
| `system_prompt_hash` | string | SHA-256 of system prompt — no raw prompt stored |
| `user_prompt_hash` | string | SHA-256 of user prompt |
| `content_filtered` | bool | Any content filter triggered |
| `response_object_id` | string | AI response `id` field |
| `observed_at` | date | |
| `created_at` | date | |

---

### 3.8 `java_releases_cache`

**Purpose:** Cache of Java release data fetched from GitHub Releases API. Avoids repeated API calls.  
**TTL:** 7 days — refresh weekly.

| Field | Type | Notes |
|---|---|---|
| `_id` | string | `"java-releases"` — singleton document, replaced on refresh |
| `fetched_at` | date | |
| `releases` | array[object] | `{ version, major, release_date }` |
| `source_run_id` | string | Which run populated this |
| `created_at` | date | |

---

## 4. Retention Summary

| Collection | TTL | Strategy |
|---|---|---|
| `workflow_runs` | None (archive >2yr) | Manual archive to cold storage |
| `jdk_snapshots` | 90 days | TTL on `created_at` |
| `endpoint_tls_scans` | 30 days | TTL on `created_at` |
| `tls_scan_findings` | 90 days | TTL on `created_at` |
| `tls_endpoint_posture` | None | Upsert; SCD Type 1 |
| `certificate_expiry` | None | Upsert; alert on `days_to_expiry` |
| `ai_model_invocations` | 30 days | TTL on `created_at` |
| `java_releases_cache` | 7 days | TTL on `fetched_at` |

---

## 5. Indexing Strategy

See [indexes.js](indexes.js) for full DDL. Key decisions:

- All collections have compound index on `{ org, repo, branch }` for tenant isolation queries.
- `tls_scan_findings` has index on `{ org, repo, severity, observed_at }` for dashboard severity queries.
- `tls_endpoint_posture` has index on `{ worst_severity, cert_days_to_expiry }` for alert queries.
- `certificate_expiry` has index on `{ not_after, is_expired }` for expiry-based alerting.
- TTL indexes use `{ created_at: 1 }` or `{ fetched_at: 1 }` with `expireAfterSeconds`.

---

## 6. Schema Versioning & Migration

Each collection includes a `schema_version` field (int, default `1`).

**Migration strategy (zero-downtime):**

1. **Expand:** Add new optional field to `$jsonSchema`; deploy new writer version.
2. **Migrate:** Background script backfills `schema_version` and new fields on existing docs.
3. **Contract:** Once all docs at new version, make field required in `$jsonSchema`.
4. **Cleanup:** Remove old fields from readers.

Never rename fields in a single deploy — always expand → migrate → contract.

---

## 7. Security & Access Control (MongoDB Roles)

```
Role: inspectra_writer
  - readWrite on collections: workflow_runs, jdk_snapshots, endpoint_tls_scans,
    tls_scan_findings, tls_endpoint_posture, certificate_expiry,
    ai_model_invocations, java_releases_cache
  - Used by: GitHub Actions seed_loader.py

Role: inspectra_reader
  - read on all above collections
  - Used by: Dashboards, BI connectors, Atlas Charts

Role: inspectra_admin
  - dbAdmin + inspectra_writer
  - Used by: DBA / migration scripts only

Never grant: clusterAdmin, userAdminAnyDatabase to application roles.
```

---

## 8. Atlas Search / Analytics

- Enable Atlas Search index on `tls_scan_findings.reason` and `tls_scan_findings.action` for full-text querying of AI rationale.
- Enable Change Streams on `tls_endpoint_posture` for real-time webhook alerting when `worst_severity` changes to `CRITICAL`.
- Atlas Charts: connect on `inspectra_reader` role; primary dashboard collections: `tls_endpoint_posture`, `certificate_expiry`, `workflow_runs`.
