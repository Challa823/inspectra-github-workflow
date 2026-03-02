// =============================================================================
// Inspectra — MongoDB Index DDL
// Database: inspectra
// Version:  1.0.0
//
// Run with: mongosh inspectra indexes.js
// All indexes support the read/write patterns described in README.md.
// =============================================================================

// ─────────────────────────────────────────────────────────────────────────────
// workflow_runs
// ─────────────────────────────────────────────────────────────────────────────
// _id is already indexed (deterministic string key: "{org}/{repo}#{run_id}")

// Dashboard: list all runs for a repo, newest first
db.workflow_runs.createIndex(
  { org: 1, repo: 1, created_at: -1 },
  { name: "idx_wr_tenant_date", background: true }
);

// Status polling: find all in-progress runs
db.workflow_runs.createIndex(
  { status: 1, created_at: -1 },
  { name: "idx_wr_status_date", background: true }
);

// Lookup by branch
db.workflow_runs.createIndex(
  { org: 1, repo: 1, branch: 1, created_at: -1 },
  { name: "idx_wr_tenant_branch_date", background: true }
);


// ─────────────────────────────────────────────────────────────────────────────
// jdk_snapshots
// ─────────────────────────────────────────────────────────────────────────────

// TTL: auto-expire after 90 days
db.jdk_snapshots.createIndex(
  { created_at: 1 },
  { name: "idx_jdk_ttl", expireAfterSeconds: 7776000, background: true }
);

// Lookup all JDK snaps for a repo run
db.jdk_snapshots.createIndex(
  { run_id: 1 },
  { name: "idx_jdk_run", background: true }
);

// Trend: JDK version history per repo
db.jdk_snapshots.createIndex(
  { org: 1, repo: 1, observed_at: -1 },
  { name: "idx_jdk_tenant_date", background: true }
);


// ─────────────────────────────────────────────────────────────────────────────
// endpoint_tls_scans
// ─────────────────────────────────────────────────────────────────────────────
// _id is: "{run_id}::{endpoint}::{source_file}"

// TTL: auto-expire after 30 days
db.endpoint_tls_scans.createIndex(
  { created_at: 1 },
  { name: "idx_ssl_ttl", expireAfterSeconds: 2592000, background: true }
);

// Lookup all findings for a run
db.endpoint_tls_scans.createIndex(
  { run_id: 1 },
  { name: "idx_ssl_run", background: true }
);

// Lookup all findings for an endpoint (across runs)
db.endpoint_tls_scans.createIndex(
  { org: 1, repo: 1, endpoint: 1, observed_at: -1 },
  { name: "idx_ssl_tenant_endpoint_date", background: true }
);

// Certificate expiry alerting
db.endpoint_tls_scans.createIndex(
  { "certificate.days_to_expiry": 1, observed_at: -1 },
  { name: "idx_ssl_cert_expiry", background: true, sparse: true }
);

// Filter by env
db.endpoint_tls_scans.createIndex(
  { org: 1, repo: 1, env: 1, endpoint: 1 },
  { name: "idx_ssl_tenant_env_endpoint", background: true }
);


// ─────────────────────────────────────────────────────────────────────────────
// tls_scan_findings
// ─────────────────────────────────────────────────────────────────────────────
// _id is: "{run_id}::{endpoint}::{source_file}"

// TTL: auto-expire after 90 days
db.tls_scan_findings.createIndex(
  { created_at: 1 },
  { name: "idx_tls_ttl", expireAfterSeconds: 7776000, background: true }
);

// Lookup all findings for a run (most common write-time read)
db.tls_scan_findings.createIndex(
  { run_id: 1 },
  { name: "idx_tls_run", background: true }
);

// Dashboard: severity breakdown per tenant, newest first
db.tls_scan_findings.createIndex(
  { org: 1, repo: 1, severity: 1, observed_at: -1 },
  { name: "idx_tls_tenant_severity_date", background: true }
);

// Endpoint drill-down: all findings for a specific endpoint
db.tls_scan_findings.createIndex(
  { org: 1, repo: 1, endpoint: 1, observed_at: -1 },
  { name: "idx_tls_tenant_endpoint_date", background: true }
);

// Env filter (dsit / prod / rqa / staging)
db.tls_scan_findings.createIndex(
  { org: 1, repo: 1, env: 1, severity: 1 },
  { name: "idx_tls_tenant_env_severity", background: true }
);

// TLS/cipher analytics
db.tls_scan_findings.createIndex(
  { tls_version: 1, cipher_version: 1 },
  { name: "idx_tls_protocol_cipher", background: true }
);

// Atlas Search index (define via Atlas UI or CLI):
// { "fields": [{ "type": "string", "path": "reason" }, { "type": "string", "path": "action" }] }


// ─────────────────────────────────────────────────────────────────────────────
// tls_endpoint_posture
// ─────────────────────────────────────────────────────────────────────────────
// _id is: "{org}/{repo}::{endpoint}" — unique per tenant+endpoint

// Alert query: all CRITICAL/HIGH endpoints across a repo
db.tls_endpoint_posture.createIndex(
  { org: 1, repo: 1, worst_severity: 1 },
  { name: "idx_posture_tenant_severity", background: true }
);

// Cert expiry alerting: endpoints expiring within N days
db.tls_endpoint_posture.createIndex(
  { cert_days_to_expiry: 1, org: 1, repo: 1 },
  { name: "idx_posture_cert_expiry", background: true, sparse: true }
);

// Last observed (staleness detection)
db.tls_endpoint_posture.createIndex(
  { last_observed_at: 1 },
  { name: "idx_posture_last_observed", background: true }
);

// Change stream support: watch for severity escalations (no extra index needed;
// use Atlas App Services / trigger on this collection)


// ─────────────────────────────────────────────────────────────────────────────
// certificate_expiry
// ─────────────────────────────────────────────────────────────────────────────
// _id is: "{org}/{repo}::{endpoint}"

// Expiry alerting: certs expiring soonest first
db.certificate_expiry.createIndex(
  { not_after: 1 },
  { name: "idx_cert_not_after", background: true, sparse: true }
);

// Filter expired certs
db.certificate_expiry.createIndex(
  { is_expired: 1, org: 1, repo: 1 },
  { name: "idx_cert_expired_tenant", background: true }
);

// Staleness: last time cert was checked
db.certificate_expiry.createIndex(
  { last_observed_at: 1 },
  { name: "idx_cert_last_observed", background: true }
);


// ─────────────────────────────────────────────────────────────────────────────
// ai_model_invocations
// ─────────────────────────────────────────────────────────────────────────────
// _id is: "{run_id}"

// TTL: auto-expire after 30 days
db.ai_model_invocations.createIndex(
  { created_at: 1 },
  { name: "idx_ai_ttl", expireAfterSeconds: 2592000, background: true }
);

// Lookup by run
db.ai_model_invocations.createIndex(
  { run_id: 1 },
  { name: "idx_ai_run", unique: true, background: true }
);

// Cost analytics: token usage per model over time
db.ai_model_invocations.createIndex(
  { model: 1, observed_at: -1 },
  { name: "idx_ai_model_date", background: true }
);

// Content filter audit
db.ai_model_invocations.createIndex(
  { content_filtered: 1, observed_at: -1 },
  { name: "idx_ai_filtered_date", background: true, sparse: true }
);


// ─────────────────────────────────────────────────────────────────────────────
// java_releases_cache
// ─────────────────────────────────────────────────────────────────────────────
// _id is: "java-releases" (singleton — no additional indexes needed)

// TTL: auto-expire after 7 days (forces refresh)
db.java_releases_cache.createIndex(
  { fetched_at: 1 },
  { name: "idx_jrc_ttl", expireAfterSeconds: 604800, background: true }
);
