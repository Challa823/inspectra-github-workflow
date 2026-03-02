#!/usr/bin/env python3
"""
seed_loader.py — Inspectra MongoDB Seed Loader
===============================================
Reads all pipeline output files and upserts/inserts documents into the
inspectra MongoDB database.

Usage:
    python scripts/seed_loader.py \\
        --mongo-uri  "mongodb+srv://user:pass@cluster.mongodb.net" \\
        --db         inspectra \\
        --org        MyOrg \\
        --repo       my-repo \\
        --branch     main \\
        --run-id     1234567890 \\
        --git-sha    abc123def456

Input files (auto-located under security/reports/ or overridable via flags):
    --analysis         analysis.json          (extract_analysis.py output)
    --endpoints-scan   endpoints_scan.json    (ssl_scan.py output)
    --jdk-info         jdk_info.json          (detect_jdk.py output)
    --tls-context      tls_context.json       (extract_tls_context.py output)
    --ai-response      ai_response.json       (call_github_models.py output)

Collections written:
    workflow_runs          — one document per pipeline invocation
    jdk_snapshots          — one document per run (JDK metadata)
    endpoint_tls_scans      — one document per endpoint × source_file (raw ssl)
    tls_scan_findings      — one document per finding in analysis.json
    tls_endpoint_posture   — upserted per endpoint (current rolled-up state)
    certificate_expiry     — upserted per endpoint (cert state)
    ai_model_invocations   — one document per run (AI call metadata)
    java_releases_cache    — singleton upsert if releases present in ai_response
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from pymongo import MongoClient, UpdateOne, InsertOne
    from pymongo.errors import BulkWriteError, DuplicateKeyError
except ImportError:
    sys.exit(
        "ERROR: pymongo is not installed.\n"
        "       Run: pip install pymongo[srv]\n"
    )

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCHEMA_VERSION = 1
DEFAULT_DB = "inspectra"
DEFAULT_REPORTS_DIR = "security/reports"
SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "UNKNOWN": 0}
CERT_ALERT_THRESHOLD_DAYS = 30

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("seed_loader")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue
    return None


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _load(path: Path, label: str) -> Any:
    if not path.exists():
        log.warning("File not found, skipping %s: %s", label, path)
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        log.info("Loaded %s (%s)", label, path.name)
        return data
    except json.JSONDecodeError as exc:
        log.error("Invalid JSON in %s: %s", path, exc)
        return None


def _worst_severity(*severities: str | None) -> str:
    best = "UNKNOWN"
    best_rank = -1
    for s in severities:
        rank = SEVERITY_RANK.get((s or "UNKNOWN").upper(), 0)
        if rank > best_rank:
            best_rank = rank
            best = (s or "UNKNOWN").upper()
    return best


# ---------------------------------------------------------------------------
# Document builders
# ---------------------------------------------------------------------------

def build_workflow_run(args: argparse.Namespace, now: datetime) -> dict:
    return {
        "_id": f"{args.org}/{args.repo}#{args.run_id}",
        "schema_version": SCHEMA_VERSION,
        "org": args.org,
        "repo": args.repo,
        "branch": args.branch,
        "run_id": args.run_id,
        "run_number": None,
        "workflow_file": args.workflow_file,
        "triggered_by": args.triggered_by or None,
        "status": "completed",
        "conclusion": args.conclusion or "success",
        "git_sha": args.git_sha or None,
        "caller_repo": args.caller_repo or None,
        "created_at": now,
        "updated_at": now,
        "completed_at": now,
    }


def build_jdk_snapshot(jdk_data: dict, tls_ctx: dict | None, args: argparse.Namespace, now: datetime) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": args.run_id,
        "org": args.org,
        "repo": args.repo,
        "branch": args.branch,
        "vendor": jdk_data.get("vendor"),
        "version": str(jdk_data.get("version", "unknown")),
        "major": int(jdk_data.get("major", 0)),
        "future_minor_version": (tls_ctx or {}).get("futureJDKMinorUpgradeVersion", ""),
        "future_major_version": (tls_ctx or {}).get("FutureMajorUpgradedVersion", ""),
        "raw": jdk_data,
        "observed_at": now,
        "created_at": now,
    }


def build_ssl_findings(scan_data: list, args: argparse.Namespace, now: datetime) -> list[dict]:
    docs = []
    for entry in scan_data:
        endpoint = entry.get("endpoint") or entry.get("host_port", "unknown")
        source_file = entry.get("source_file", "")
        cert_raw = entry.get("certificate") or {}
        not_after_str = cert_raw.get("notAfter") or cert_raw.get("not_after")
        days_raw = cert_raw.get("daysToExpiry") or cert_raw.get("days_to_expiry")
        doc = {
            "_id": f"{args.run_id}::{endpoint}::{source_file}",
            "schema_version": SCHEMA_VERSION,
            "run_id": args.run_id,
            "org": args.org,
            "repo": args.repo,
            "branch": args.branch,
            "env": entry.get("env", ""),
            "endpoint": endpoint,
            "tls_protocol": entry.get("tlsProtocol", ""),
            "cipher_suite": entry.get("cipherSuite", ""),
            "certificate": {
                "subject": cert_raw.get("subject"),
                "issuer": cert_raw.get("issuer"),
                "not_after": _parse_date(not_after_str),
                "days_to_expiry": int(days_raw) if days_raw is not None else None,
            },
            "errors": entry.get("errors", []),
            "source_file": source_file,
            "source_line": entry.get("line"),
            "source_context": entry.get("context"),
            "url": entry.get("url"),
            "observed_at": now,
            "created_at": now,
        }
        docs.append(doc)
    return docs


def build_tls_findings(analysis: list, args: argparse.Namespace, now: datetime) -> list[dict]:
    docs = []
    for entry in analysis:
        endpoint = entry.get("endpoint", "unknown")
        source_file = entry.get("source_file", "")
        doc = {
            "_id": f"{args.run_id}::{endpoint}::{source_file}",
            "schema_version": SCHEMA_VERSION,
            "run_id": args.run_id,
            "org": args.org,
            "repo": args.repo,
            "branch": args.branch,
            "env": entry.get("env", ""),
            "endpoint": endpoint,
            "tls_version": entry.get("tlsVersion", ""),
            "cipher_version": entry.get("CipherVersion", ""),
            "current_jdk_version": entry.get("CurrentJDKVersion", ""),
            "future_jdk_minor_version": entry.get("futureJDKMinorUpgradeVersion", ""),
            "future_jdk_major_version": entry.get("FutureMajorUpgradedVersion", ""),
            "current_jdk_tls_status": entry.get("CurrentJdkTlsStatus", "Unknown"),
            "future_jdk_minor_tls_status": entry.get("FutureJdkMinorTlsStatus", "Unknown"),
            "future_jdk_major_tls_status": entry.get("FutureJdkMajorTlsStatus", "Unknown"),
            "severity": (entry.get("severity") or "UNKNOWN").upper(),
            "reason": entry.get("reason"),
            "action": entry.get("action"),
            "source_file": source_file,
            "source_line": entry.get("line") or entry.get("source_line"),
            "source_url": entry.get("source_url"),
            "ai_model": args.ai_model or None,
            "compatibility": entry.get("compatibility"),
            "observed_at": now,
            "created_at": now,
        }
        docs.append(doc)
    return docs


def build_posture_upserts(analysis: list, ssl_by_endpoint: dict, args: argparse.Namespace, now: datetime) -> list[UpdateOne]:
    """
    Build upsert operations for tls_endpoint_posture (one doc per tenant+endpoint).
    The function tolerates multiple analysis rows for the same endpoint by keeping
    the worst severity.
    """
    # aggregate by endpoint
    posture: dict[str, dict] = {}
    for entry in analysis:
        endpoint = entry.get("endpoint", "unknown")
        sev = (entry.get("severity") or "UNKNOWN").upper()
        if endpoint not in posture or SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(posture[endpoint]["worst_severity"], 0):
            ssl_entry = ssl_by_endpoint.get(endpoint, {})
            cert_raw = ssl_entry.get("certificate", {})
            not_after_str = cert_raw.get("notAfter") or cert_raw.get("not_after")
            days_raw = cert_raw.get("daysToExpiry") or cert_raw.get("days_to_expiry")
            posture[endpoint] = {
                "worst_severity": sev,
                "tls_version": entry.get("tlsVersion", ""),
                "cipher_version": entry.get("CipherVersion", ""),
                "current_jdk_version": entry.get("CurrentJDKVersion", ""),
                "current_jdk_tls_status": entry.get("CurrentJdkTlsStatus", "Unknown"),
                "future_jdk_minor_version": entry.get("futureJDKMinorUpgradeVersion", ""),
                "future_jdk_minor_tls_status": entry.get("FutureJdkMinorTlsStatus", "Unknown"),
                "future_jdk_major_version": entry.get("FutureMajorUpgradedVersion", ""),
                "future_jdk_major_tls_status": entry.get("FutureJdkMajorTlsStatus", "Unknown"),
                "reason": entry.get("reason"),
                "action": entry.get("action"),
                "cert_not_after": _parse_date(not_after_str),
                "cert_days_to_expiry": int(days_raw) if days_raw is not None else None,
                "cert_issuer": cert_raw.get("issuer"),
                "env_set": {entry.get("env", "")},
            }
        else:
            posture[endpoint]["env_set"].add(entry.get("env", ""))

    ops = []
    for endpoint, p in posture.items():
        doc_id = f"{args.org}/{args.repo}::{endpoint}"
        envs = sorted(e for e in p.pop("env_set") if e)
        ops.append(UpdateOne(
            {"_id": doc_id},
            {"$set": {
                "_id": doc_id,
                "schema_version": SCHEMA_VERSION,
                "org": args.org,
                "repo": args.repo,
                "endpoint": endpoint,
                "last_run_id": args.run_id,
                "last_observed_at": now,
                "envs": envs,
                "updated_at": now,
                **p,
            }, "$inc": {"finding_count": 1}},
            upsert=True,
        ))
    return ops


def build_cert_upserts(ssl_docs: list[dict], args: argparse.Namespace, now: datetime) -> list[UpdateOne]:
    ops = []
    seen: set[str] = set()
    for doc in ssl_docs:
        endpoint = doc["endpoint"]
        doc_id = f"{args.org}/{args.repo}::{endpoint}"
        if doc_id in seen:
            continue
        seen.add(doc_id)
        cert = doc.get("certificate") or {}
        days = cert.get("days_to_expiry")
        ops.append(UpdateOne(
            {"_id": doc_id},
            {"$set": {
                "_id": doc_id,
                "schema_version": SCHEMA_VERSION,
                "org": args.org,
                "repo": args.repo,
                "endpoint": endpoint,
                "subject": cert.get("subject"),
                "issuer": cert.get("issuer"),
                "not_after": cert.get("not_after"),
                "days_to_expiry": days,
                "is_expired": (days is not None and days < 0),
                "alert_threshold_days": CERT_ALERT_THRESHOLD_DAYS,
                "last_run_id": args.run_id,
                "last_observed_at": now,
                "updated_at": now,
            }},
            upsert=True,
        ))
    return ops


def build_ai_invocation(ai_data: dict, system_prompt: str | None, user_prompt: str | None,
                         args: argparse.Namespace, now: datetime) -> dict:
    usage = ai_data.get("usage") or {}
    choices = ai_data.get("choices") or [{}]
    finish_reason = (choices[0] if choices else {}).get("finish_reason")
    content_filter = (choices[0] if choices else {}).get("content_filter_results") or {}
    filtered = any(
        v.get("filtered", False) for v in content_filter.values()
        if isinstance(v, dict)
    )
    return {
        "_id": args.run_id,
        "schema_version": SCHEMA_VERSION,
        "run_id": args.run_id,
        "org": args.org,
        "repo": args.repo,
        "model": ai_data.get("model", "unknown"),
        "prompt_tokens": usage.get("prompt_tokens"),
        "completion_tokens": usage.get("completion_tokens"),
        "total_tokens": usage.get("total_tokens"),
        "finish_reason": finish_reason,
        "system_prompt_hash": _sha256(system_prompt) if system_prompt else None,
        "user_prompt_hash": _sha256(user_prompt) if user_prompt else None,
        "content_filtered": filtered,
        "response_object_id": ai_data.get("id"),
        "observed_at": now,
        "created_at": now,
    }


def build_java_releases_cache(ai_data: dict, args: argparse.Namespace, now: datetime) -> dict | None:
    """Cache java releases if present in ai_response (extraction block)."""
    releases_raw = ai_data.get("java_releases") or ai_data.get("extractions", {}).get("java_releases")
    if not releases_raw or not isinstance(releases_raw, list):
        return None
    releases = []
    for r in releases_raw:
        releases.append({
            "version": r.get("version", ""),
            "major": int(r.get("major", 0)),
            "release_date": _parse_date(r.get("release_date") or r.get("ga_date")),
        })
    return {
        "_id": "java-releases",
        "schema_version": SCHEMA_VERSION,
        "fetched_at": now,
        "source_run_id": args.run_id,
        "releases": releases,
        "created_at": now,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Load Inspectra pipeline outputs into MongoDB")
    p.add_argument("--mongo-uri",    required=True, help="MongoDB URI (mongodb:// or mongodb+srv://)")
    p.add_argument("--db",           default=DEFAULT_DB, help="Database name (default: inspectra)")
    p.add_argument("--org",          required=True, help="GitHub org/owner")
    p.add_argument("--repo",         required=True, help="GitHub repository name")
    p.add_argument("--branch",       default="main", help="Git branch (default: main)")
    p.add_argument("--run-id",       required=True, help="GitHub Actions run_id (string)")
    p.add_argument("--git-sha",      default=None,  help="Git commit SHA")
    p.add_argument("--workflow-file",default="inspectra.yaml", help="Workflow filename")
    p.add_argument("--triggered-by", default=None, help="Actor who triggered the run")
    p.add_argument("--conclusion",   default="success", choices=["success","failure","cancelled","skipped"],
                   help="Workflow conclusion")
    p.add_argument("--caller-repo",  default=None, help="Caller repo for reusable workflows")
    p.add_argument("--ai-model",     default=None, help="AI model identifier used in this run")
    p.add_argument("--reports-dir",  default=DEFAULT_REPORTS_DIR, help="Base directory for report files")
    p.add_argument("--analysis",     default=None, help="Path to analysis.json")
    p.add_argument("--endpoints-scan", default=None, help="Path to endpoints_scan.json")
    p.add_argument("--jdk-info",     default=None, help="Path to jdk_info.json")
    p.add_argument("--tls-context",  default=None, help="Path to tls_context.json")
    p.add_argument("--ai-response",  default=None, help="Path to ai_response.json")
    p.add_argument("--dry-run",      action="store_true", help="Print documents without writing to MongoDB")
    return p.parse_args()


def resolve(args: argparse.Namespace, flag: str | None, default_name: str) -> Path:
    if flag:
        return Path(flag)
    return Path(args.reports_dir) / default_name


def main() -> None:
    args = parse_args()
    now = _now()

    # ── locate files ──────────────────────────────────────────────────────────
    analysis_path   = resolve(args, args.analysis,      "analysis.json")
    ssl_scan_path   = resolve(args, args.endpoints_scan, "endpoints_scan.json")
    jdk_path        = resolve(args, args.jdk_info,       "jdk_info.json")
    tls_ctx_path    = resolve(args, args.tls_context,    "tls_context.json")
    ai_resp_path    = resolve(args, args.ai_response,    "ai_response.json")

    # ── load files ────────────────────────────────────────────────────────────
    analysis     = _load(analysis_path,  "analysis")     or []
    ssl_scan     = _load(ssl_scan_path,  "endpoints_scan") or []
    jdk_data     = _load(jdk_path,       "jdk_info")     or {}
    tls_ctx      = _load(tls_ctx_path,   "tls_context")  or {}
    ai_resp      = _load(ai_resp_path,   "ai_response")  or {}

    # try to read prompt files for hashing (best-effort)
    system_prompt_text = None
    user_prompt_text   = None
    for name, attr in [("prompt_system.txt", "system_prompt_text"), ("prompt_user.txt", "user_prompt_text")]:
        p = Path(args.reports_dir) / name
        if p.exists():
            try:
                content = p.read_text(encoding="utf-8")
                if attr == "system_prompt_text":
                    system_prompt_text = content
                else:
                    user_prompt_text = content
            except Exception:
                pass

    # ── build documents ───────────────────────────────────────────────────────
    wr_doc    = build_workflow_run(args, now)
    jdk_doc   = build_jdk_snapshot(jdk_data, tls_ctx, args, now) if jdk_data else None
    ssl_docs  = build_ssl_findings(ssl_scan, args, now)
    tls_docs  = build_tls_findings(analysis, args, now)
    ai_doc    = build_ai_invocation(ai_resp, system_prompt_text, user_prompt_text, args, now) if ai_resp else None
    jrc_doc   = build_java_releases_cache(ai_resp, args, now) if ai_resp else None

    ssl_by_endpoint = {d["endpoint"]: ssl_scan[i] for i, d in enumerate(ssl_docs)}
    posture_ops = build_posture_upserts(analysis, ssl_by_endpoint, args, now)
    cert_ops    = build_cert_upserts(ssl_docs, args, now)

    if args.dry_run:
        log.info("── DRY RUN – no writes ──")
        print(json.dumps({
            "workflow_runs":        [wr_doc],
            "jdk_snapshots":        [jdk_doc] if jdk_doc else [],
            "endpoint_tls_scans":    ssl_docs[:2],
            "tls_scan_findings":    tls_docs[:2],
            "tls_endpoint_posture": f"{len(posture_ops)} upsert operations",
            "certificate_expiry":   f"{len(cert_ops)} upsert operations",
            "ai_model_invocations": [ai_doc] if ai_doc else [],
            "java_releases_cache":  [jrc_doc] if jrc_doc else [],
        }, indent=2, default=str))
        return

    # ── write to MongoDB ──────────────────────────────────────────────────────
    log.info("Connecting to MongoDB …")
    client = MongoClient(args.mongo_uri)
    db = client[args.db]

    errors: list[str] = []

    # workflow_runs — replace on re-run
    try:
        db.workflow_runs.replace_one({"_id": wr_doc["_id"]}, wr_doc, upsert=True)
        log.info("✔ workflow_runs  upserted %s", wr_doc["_id"])
    except Exception as exc:
        errors.append(f"workflow_runs: {exc}")

    # jdk_snapshots — insert (keep history)
    if jdk_doc:
        try:
            db.jdk_snapshots.insert_one(jdk_doc)
            log.info("✔ jdk_snapshots  inserted")
        except DuplicateKeyError:
            log.warning("jdk_snapshots duplicate, skipping")
        except Exception as exc:
            errors.append(f"jdk_snapshots: {exc}")

    # endpoint_tls_scans — ordered=False → skip duplicates, continue
    if ssl_docs:
        try:
            db.endpoint_tls_scans.insert_many(ssl_docs, ordered=False)
            log.info("✔ endpoint_tls_scans  inserted %d docs", len(ssl_docs))
        except BulkWriteError as bwe:
            written = bwe.details.get("nInserted", 0)
            log.warning("endpoint_tls_scans  %d inserted, %d duplicates skipped", written,
                        len(bwe.details.get("writeErrors", [])))
        except Exception as exc:
            errors.append(f"endpoint_tls_scans: {exc}")

    # tls_scan_findings — ordered=False
    if tls_docs:
        try:
            db.tls_scan_findings.insert_many(tls_docs, ordered=False)
            log.info("✔ tls_scan_findings  inserted %d docs", len(tls_docs))
        except BulkWriteError as bwe:
            written = bwe.details.get("nInserted", 0)
            log.warning("tls_scan_findings  %d inserted, %d duplicates skipped", written,
                        len(bwe.details.get("writeErrors", [])))
        except Exception as exc:
            errors.append(f"tls_scan_findings: {exc}")

    # tls_endpoint_posture — bulk upsert
    if posture_ops:
        try:
            result = db.tls_endpoint_posture.bulk_write(posture_ops, ordered=False)
            log.info("✔ tls_endpoint_posture  upserted=%d modified=%d",
                     result.upserted_count, result.modified_count)
        except Exception as exc:
            errors.append(f"tls_endpoint_posture: {exc}")

    # certificate_expiry — bulk upsert
    if cert_ops:
        try:
            result = db.certificate_expiry.bulk_write(cert_ops, ordered=False)
            log.info("✔ certificate_expiry  upserted=%d modified=%d",
                     result.upserted_count, result.modified_count)
        except Exception as exc:
            errors.append(f"certificate_expiry: {exc}")

    # ai_model_invocations — replace to avoid growing the doc
    if ai_doc:
        try:
            db.ai_model_invocations.replace_one({"_id": ai_doc["_id"]}, ai_doc, upsert=True)
            log.info("✔ ai_model_invocations  upserted %s", ai_doc["_id"])
        except Exception as exc:
            errors.append(f"ai_model_invocations: {exc}")

    # java_releases_cache — singleton upsert
    if jrc_doc:
        try:
            db.java_releases_cache.replace_one({"_id": "java-releases"}, jrc_doc, upsert=True)
            log.info("✔ java_releases_cache  upserted singleton")
        except Exception as exc:
            errors.append(f"java_releases_cache: {exc}")

    client.close()

    if errors:
        log.error("Completed with %d error(s):", len(errors))
        for e in errors:
            log.error("  • %s", e)
        sys.exit(1)
    else:
        log.info("All collections loaded successfully.")


if __name__ == "__main__":
    main()
