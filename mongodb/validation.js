// =============================================================================
// Inspectra — MongoDB $jsonSchema Validators
// Database: inspectra
// Version:  1.0.0
//
// Apply with:
//   mongosh inspectra validation.js
//
// Each collMod call adds validator + validationLevel:"moderate" so existing
// documents are not rejected, only new inserts/updates are validated.
// Change to "strict" once data is fully migrated to new schema.
// =============================================================================

// ─────────────────────────────────────────────────────────────────────────────
// workflow_runs
// ─────────────────────────────────────────────────────────────────────────────
db.createCollection("workflow_runs", {
  validator: {
    $jsonSchema: {
      bsonType: "object",
      required: ["_id", "schema_version", "org", "repo", "branch", "run_id", "workflow_file", "status", "created_at", "updated_at"],
      properties: {
        _id:            { bsonType: "string",  description: "{org}/{repo}#{run_id}" },
        schema_version: { bsonType: "int",     minimum: 1 },
        org:            { bsonType: "string",  minLength: 1 },
        repo:           { bsonType: "string",  minLength: 1 },
        branch:         { bsonType: "string",  minLength: 1 },
        run_id:         { bsonType: "string",  minLength: 1 },
        run_number:     { bsonType: ["int","null"] },
        workflow_file:  { bsonType: "string",  minLength: 1 },
        triggered_by:   { bsonType: ["string","null"] },
        status:         { bsonType: "string",  enum: ["queued","in_progress","completed","failed"] },
        conclusion:     { bsonType: ["string","null"], enum: ["success","failure","cancelled","skipped", null] },
        git_sha:        { bsonType: ["string","null"] },
        caller_repo:    { bsonType: ["string","null"] },
        created_at:     { bsonType: "date" },
        updated_at:     { bsonType: "date" },
        completed_at:   { bsonType: ["date","null"] }
      },
      additionalProperties: true
    }
  },
  validationLevel: "moderate",
  validationAction: "warn"
});

// If collection already exists, use collMod:
db.runCommand({
  collMod: "workflow_runs",
  validator: {
    $jsonSchema: {
      bsonType: "object",
      required: ["_id", "schema_version", "org", "repo", "branch", "run_id", "workflow_file", "status", "created_at", "updated_at"],
      properties: {
        _id:            { bsonType: "string" },
        schema_version: { bsonType: "int", minimum: 1 },
        org:            { bsonType: "string", minLength: 1 },
        repo:           { bsonType: "string", minLength: 1 },
        branch:         { bsonType: "string", minLength: 1 },
        run_id:         { bsonType: "string", minLength: 1 },
        workflow_file:  { bsonType: "string", minLength: 1 },
        status:         { bsonType: "string", enum: ["queued","in_progress","completed","failed"] },
        created_at:     { bsonType: "date" },
        updated_at:     { bsonType: "date" }
      }
    }
  },
  validationLevel: "moderate",
  validationAction: "warn"
});


// ─────────────────────────────────────────────────────────────────────────────
// jdk_snapshots
// ─────────────────────────────────────────────────────────────────────────────
db.runCommand({
  collMod: "jdk_snapshots",
  validator: {
    $jsonSchema: {
      bsonType: "object",
      required: ["schema_version", "run_id", "org", "repo", "branch", "version", "major", "future_minor_version", "future_major_version", "observed_at", "created_at"],
      properties: {
        schema_version:        { bsonType: "int", minimum: 1 },
        run_id:                { bsonType: "string", minLength: 1 },
        org:                   { bsonType: "string", minLength: 1 },
        repo:                  { bsonType: "string", minLength: 1 },
        branch:                { bsonType: "string", minLength: 1 },
        vendor:                { bsonType: ["string","null"] },
        version:               { bsonType: "string", minLength: 1 },
        major:                 { bsonType: "int", minimum: 1 },
        future_minor_version:  { bsonType: "string" },
        future_major_version:  { bsonType: "string" },
        observed_at:           { bsonType: "date" },
        created_at:            { bsonType: "date" }
      }
    }
  },
  validationLevel: "moderate",
  validationAction: "warn"
});


// ─────────────────────────────────────────────────────────────────────────────
// endpoint_tls_scans
// ─────────────────────────────────────────────────────────────────────────────
db.runCommand({
  collMod: "endpoint_tls_scans",
  validator: {
    $jsonSchema: {
      bsonType: "object",
      required: ["_id", "schema_version", "run_id", "org", "repo", "branch", "env", "endpoint", "tls_protocol", "cipher_suite", "errors", "source_file", "observed_at", "created_at"],
      properties: {
        _id:            { bsonType: "string" },
        schema_version: { bsonType: "int", minimum: 1 },
        run_id:         { bsonType: "string", minLength: 1 },
        org:            { bsonType: "string", minLength: 1 },
        repo:           { bsonType: "string", minLength: 1 },
        branch:         { bsonType: "string", minLength: 1 },
        env:            { bsonType: "string", minLength: 1 },
        endpoint:       { bsonType: "string", minLength: 1 },
        tls_protocol:   { bsonType: "string" },
        cipher_suite:   { bsonType: "string" },
        certificate: {
          bsonType: "object",
          properties: {
            subject:        { bsonType: ["string","null"] },
            issuer:         { bsonType: ["string","null"] },
            not_after:      { bsonType: ["date","null"] },
            days_to_expiry: { bsonType: ["int","double","null"] }
          }
        },
        errors:         { bsonType: "array", items: { bsonType: "string" } },
        source_file:    { bsonType: "string", minLength: 1 },
        source_line:    { bsonType: ["int","null"] },
        source_context: { bsonType: ["string","null"] },
        url:            { bsonType: ["string","null"] },
        observed_at:    { bsonType: "date" },
        created_at:     { bsonType: "date" }
      }
    }
  },
  validationLevel: "moderate",
  validationAction: "warn"
});


// ─────────────────────────────────────────────────────────────────────────────
// tls_scan_findings
// ─────────────────────────────────────────────────────────────────────────────
db.runCommand({
  collMod: "tls_scan_findings",
  validator: {
    $jsonSchema: {
      bsonType: "object",
      required: ["_id", "schema_version", "run_id", "org", "repo", "branch", "env", "endpoint",
                 "tls_version", "cipher_version", "current_jdk_version",
                 "future_jdk_minor_version", "future_jdk_major_version",
                 "current_jdk_tls_status", "future_jdk_minor_tls_status", "future_jdk_major_tls_status",
                 "severity", "source_file", "observed_at", "created_at"],
      properties: {
        _id:                         { bsonType: "string" },
        schema_version:              { bsonType: "int", minimum: 1 },
        run_id:                      { bsonType: "string", minLength: 1 },
        org:                         { bsonType: "string", minLength: 1 },
        repo:                        { bsonType: "string", minLength: 1 },
        branch:                      { bsonType: "string", minLength: 1 },
        env:                         { bsonType: "string", minLength: 1 },
        endpoint:                    { bsonType: "string", minLength: 1 },
        tls_version:                 { bsonType: "string" },
        cipher_version:              { bsonType: "string" },
        current_jdk_version:         { bsonType: "string" },
        future_jdk_minor_version:    { bsonType: "string" },
        future_jdk_major_version:    { bsonType: "string" },
        current_jdk_tls_status:      { bsonType: "string", enum: ["Supported","Not Supported","Unknown"] },
        future_jdk_minor_tls_status: { bsonType: "string", enum: ["Supported","Not Supported","Unknown"] },
        future_jdk_major_tls_status: { bsonType: "string", enum: ["Supported","Not Supported","Unknown"] },
        severity:                    { bsonType: "string", enum: ["CRITICAL","HIGH","WARNING","INFO"] },
        reason:                      { bsonType: ["string","null"] },
        action:                      { bsonType: ["string","null"] },
        source_file:                 { bsonType: "string", minLength: 1 },
        source_line:                 { bsonType: ["int","null"] },
        source_url:                  { bsonType: ["string","null"] },
        ai_model:                    { bsonType: ["string","null"] },
        compatibility:               { bsonType: ["object","null"] },
        observed_at:                 { bsonType: "date" },
        created_at:                  { bsonType: "date" }
      }
    }
  },
  validationLevel: "moderate",
  validationAction: "warn"
});


// ─────────────────────────────────────────────────────────────────────────────
// tls_endpoint_posture
// ─────────────────────────────────────────────────────────────────────────────
db.runCommand({
  collMod: "tls_endpoint_posture",
  validator: {
    $jsonSchema: {
      bsonType: "object",
      required: ["_id", "schema_version", "org", "repo", "endpoint", "last_run_id",
                 "last_observed_at", "envs", "worst_severity", "tls_version", "cipher_version",
                 "current_jdk_version", "current_jdk_tls_status",
                 "future_jdk_minor_version", "future_jdk_minor_tls_status",
                 "future_jdk_major_version", "future_jdk_major_tls_status",
                 "finding_count", "updated_at"],
      properties: {
        _id:                         { bsonType: "string" },
        schema_version:              { bsonType: "int", minimum: 1 },
        org:                         { bsonType: "string", minLength: 1 },
        repo:                        { bsonType: "string", minLength: 1 },
        endpoint:                    { bsonType: "string", minLength: 1 },
        last_run_id:                 { bsonType: "string", minLength: 1 },
        last_observed_at:            { bsonType: "date" },
        envs:                        { bsonType: "array",  items: { bsonType: "string" } },
        worst_severity:              { bsonType: "string", enum: ["CRITICAL","HIGH","WARNING","INFO"] },
        tls_version:                 { bsonType: "string" },
        cipher_version:              { bsonType: "string" },
        current_jdk_version:         { bsonType: "string" },
        current_jdk_tls_status:      { bsonType: "string", enum: ["Supported","Not Supported","Unknown"] },
        future_jdk_minor_version:    { bsonType: "string" },
        future_jdk_minor_tls_status: { bsonType: "string", enum: ["Supported","Not Supported","Unknown"] },
        future_jdk_major_version:    { bsonType: "string" },
        future_jdk_major_tls_status: { bsonType: "string", enum: ["Supported","Not Supported","Unknown"] },
        reason:                      { bsonType: ["string","null"] },
        action:                      { bsonType: ["string","null"] },
        cert_not_after:              { bsonType: ["date","null"] },
        cert_days_to_expiry:         { bsonType: ["int","double","null"] },
        cert_issuer:                 { bsonType: ["string","null"] },
        finding_count:               { bsonType: "int", minimum: 0 },
        updated_at:                  { bsonType: "date" }
      }
    }
  },
  validationLevel: "moderate",
  validationAction: "warn"
});


// ─────────────────────────────────────────────────────────────────────────────
// certificate_expiry
// ─────────────────────────────────────────────────────────────────────────────
db.runCommand({
  collMod: "certificate_expiry",
  validator: {
    $jsonSchema: {
      bsonType: "object",
      required: ["_id", "schema_version", "org", "repo", "endpoint", "is_expired",
                 "alert_threshold_days", "last_run_id", "last_observed_at", "updated_at"],
      properties: {
        _id:                  { bsonType: "string" },
        schema_version:       { bsonType: "int", minimum: 1 },
        org:                  { bsonType: "string", minLength: 1 },
        repo:                 { bsonType: "string", minLength: 1 },
        endpoint:             { bsonType: "string", minLength: 1 },
        subject:              { bsonType: ["string","null"] },
        issuer:               { bsonType: ["string","null"] },
        not_after:            { bsonType: ["date","null"] },
        days_to_expiry:       { bsonType: ["int","double","null"] },
        is_expired:           { bsonType: "bool" },
        alert_threshold_days: { bsonType: "int", minimum: 0 },
        last_run_id:          { bsonType: "string", minLength: 1 },
        last_observed_at:     { bsonType: "date" },
        updated_at:           { bsonType: "date" }
      }
    }
  },
  validationLevel: "moderate",
  validationAction: "warn"
});


// ─────────────────────────────────────────────────────────────────────────────
// ai_model_invocations
// ─────────────────────────────────────────────────────────────────────────────
db.runCommand({
  collMod: "ai_model_invocations",
  validator: {
    $jsonSchema: {
      bsonType: "object",
      required: ["_id", "schema_version", "run_id", "org", "repo", "model",
                 "content_filtered", "observed_at", "created_at"],
      properties: {
        _id:                { bsonType: "string" },
        schema_version:     { bsonType: "int", minimum: 1 },
        run_id:             { bsonType: "string", minLength: 1 },
        org:                { bsonType: "string", minLength: 1 },
        repo:               { bsonType: "string", minLength: 1 },
        model:              { bsonType: "string", minLength: 1 },
        prompt_tokens:      { bsonType: ["int","null"] },
        completion_tokens:  { bsonType: ["int","null"] },
        total_tokens:       { bsonType: ["int","null"] },
        finish_reason:      { bsonType: ["string","null"] },
        system_prompt_hash: { bsonType: ["string","null"] },
        user_prompt_hash:   { bsonType: ["string","null"] },
        content_filtered:   { bsonType: "bool" },
        response_object_id: { bsonType: ["string","null"] },
        observed_at:        { bsonType: "date" },
        created_at:         { bsonType: "date" }
      }
    }
  },
  validationLevel: "moderate",
  validationAction: "warn"
});


// ─────────────────────────────────────────────────────────────────────────────
// java_releases_cache
// ─────────────────────────────────────────────────────────────────────────────
db.runCommand({
  collMod: "java_releases_cache",
  validator: {
    $jsonSchema: {
      bsonType: "object",
      required: ["_id", "schema_version", "fetched_at", "releases", "created_at"],
      properties: {
        _id:            { bsonType: "string" },
        schema_version: { bsonType: "int", minimum: 1 },
        fetched_at:     { bsonType: "date" },
        source_run_id:  { bsonType: ["string","null"] },
        releases: {
          bsonType: "array",
          items: {
            bsonType: "object",
            properties: {
              version:      { bsonType: "string" },
              major:        { bsonType: "int" },
              release_date: { bsonType: ["date","null"] }
            }
          }
        },
        created_at: { bsonType: "date" }
      }
    }
  },
  validationLevel: "moderate",
  validationAction: "warn"
});

print("✅ All validators applied to inspectra database.");
