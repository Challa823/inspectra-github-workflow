import json
import subprocess
import tempfile
import os
import argparse
from datetime import datetime, timezone


def ssl_scan_endpoint(ep_meta):
    """
    Perform SSL scan for a single endpoint.
    ep_meta: dict from collect_endpoints.py JSON
              keys: host_port, url, env, source_file, line, context
    Returns enriched scan result dict.
    """
    host_port = ep_meta["host_port"]
    host, port = host_port.rsplit(':', 1)

    try:
        raw = subprocess.check_output(
            ['openssl', 's_client', '-showcerts', '-servername', host, '-connect', f'{host}:{port}'],
            stderr=subprocess.STDOUT,
            timeout=15,
            input=b''
        ).decode('utf-8', errors='replace')
    except subprocess.TimeoutExpired:
        raw = "timeout"
    except subprocess.CalledProcessError as e:
        raw = e.output.decode('utf-8', errors='replace')
    except FileNotFoundError:
        raw = "error: openssl not found"

    cert_info = extract_certificate_info(raw)

    return {
        # SSL scan fields
        "endpoint":    host_port,
        "tlsProtocol": extract_tls_protocol(raw),
        "cipherSuite": extract_cipher_suite(raw),
        "certificate": cert_info,
        "errors":      extract_errors(raw),
        # Metadata from collect_endpoints.py
        "url":         ep_meta.get("url", ""),
        "env":         ep_meta.get("env", "unknown"),
        "source_file": ep_meta.get("source_file", ""),
        "line":        ep_meta.get("line", 0),
        "context":     ep_meta.get("context", ""),
    }


def ssl_scan(endpoints_meta):
    """
    Scan all endpoints from collect_endpoints.py JSON output.
    endpoints_meta: list of dicts from endpoints.json
    """
    results = []
    for ep_meta in endpoints_meta:
        print(f"[INFO] Scanning {ep_meta['host_port']} (env={ep_meta.get('env','?')}, src={ep_meta.get('source_file','?')}:{ep_meta.get('line','?')})")
        result = ssl_scan_endpoint(ep_meta)
        results.append(result)
    return results


def extract_tls_protocol(raw):
    """
    Extract negotiated TLS protocol from openssl s_client output.

    Priority order (most reliable first):
      1. Handshake summary line:  'New, TLSv1.3, Cipher is ...'
      2. Summary block:           'Protocol: TLSv1.3'  (no space before colon)
      3. SSL-Session block:       'Protocol  : TLSv1.3' (double-space)
      4. Any TLSv\d.\d occurrence as last resort
    """
    import re

    # 1. Handshake line: "New, TLSv1.3, Cipher is ..."
    m = re.search(r'New,\s+(TLS(?:v[\d.]+|[\d.]+))\s*,\s*Cipher', raw)
    if m:
        proto = m.group(1).strip()
        print(f"[DEBUG] TLS protocol extracted (handshake line): {proto}")
        return proto

    # 2. "Protocol: TLSv1.3"  or  "Protocol : TLSv1.3"  or  "Protocol  : TLSv1.3"
    m = re.search(r'^\s*Protocol\s*:\s*(\S+)', raw, re.MULTILINE)
    if m:
        proto = m.group(1).strip()
        print(f"[DEBUG] TLS protocol extracted (Protocol: line): {proto}")
        return proto

    # 3. Generic TLSv pattern fallback
    m = re.search(r'TLS(?:v[\d.]+)', raw)
    if m:
        proto = m.group(0).strip()
        print(f"[DEBUG] TLS protocol extracted (regex fallback): {proto}")
        return proto

    print("[WARN] TLS protocol not found in openssl output")
    return '<none>'


def extract_cipher_suite(raw):
    """
    Extract negotiated cipher suite from openssl s_client output.

    Priority order:
      1. Handshake summary line: 'New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384'
      2. SSL-Session block:      'Cipher    : TLS_AES_256_GCM_SHA384'
    """
    import re

    # 1. "Cipher is <suite>" — appears in the handshake summary for both TLS 1.2 and 1.3
    m = re.search(r'Cipher\s+is\s+(\S+)', raw)
    if m:
        cipher = m.group(1).strip()
        print(f"[DEBUG] Cipher extracted (handshake 'Cipher is' line): {cipher}")
        return cipher

    # 2. SSL-Session block: "    Cipher    : <suite>"
    m = re.search(r'^\s*Cipher\s*:\s*(\S+)', raw, re.MULTILINE)
    if m:
        cipher = m.group(1).strip()
        print(f"[DEBUG] Cipher extracted (SSL-Session block): {cipher}")
        return cipher

    print("[WARN] Cipher suite not found in openssl output")
    return '<none>'


def extract_certificate_info(raw):
    """Extract leaf cert subject, issuer, notAfter and compute daysToExpiry."""
    cert_lines = []
    in_cert = False
    for line in raw.splitlines():
        if '-----BEGIN CERTIFICATE-----' in line:
            in_cert = True
            cert_lines = [line]
        elif '-----END CERTIFICATE-----' in line and in_cert:
            cert_lines.append(line)
            break
        elif in_cert:
            cert_lines.append(line)

    if not cert_lines:
        return {"subject": "", "issuer": "", "notAfter": None, "daysToExpiry": None}

    cert_pem = "\n".join(cert_lines)

    with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as tmp:
        tmp.write(cert_pem)
        tmp_path = tmp.name

    try:
        subject  = _run_openssl_x509(tmp_path, '-subject')
        issuer   = _run_openssl_x509(tmp_path, '-issuer')
        not_after = _run_openssl_x509(tmp_path, '-enddate')
    finally:
        os.unlink(tmp_path)

    subject   = subject.replace('subject=', '').strip()
    issuer    = issuer.replace('issuer=', '').strip()
    not_after = not_after.replace('notAfter=', '').strip()

    days_to_expiry = None
    iso_expiry = None
    if not_after:
        try:
            expiry_dt = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
            iso_expiry = expiry_dt.strftime('%Y-%m-%dT%H:%M:%SZ')
            days_to_expiry = (expiry_dt - datetime.now(timezone.utc)).days
        except ValueError:
            pass

    return {
        "subject":      subject,
        "issuer":       issuer,
        "notAfter":     iso_expiry,
        "daysToExpiry": days_to_expiry
    }


def _run_openssl_x509(cert_path, flag):
    try:
        return subprocess.check_output(
            ['openssl', 'x509', '-in', cert_path, '-noout', flag],
            stderr=subprocess.DEVNULL
        ).decode('utf-8', errors='replace').strip()
    except subprocess.CalledProcessError:
        return ''


def extract_errors(raw):
    errors = []
    for line in raw.splitlines():
        low = line.lower()
        if any(k in low for k in ('error', 'unable', 'failed', 'timeout')):
            errors.append(line.strip())
    return errors


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="SSL scan endpoints from collect_endpoints.py JSON output")
    parser.add_argument("--endpoints-json", default="endpoints.json",
                        help="Path to endpoints.json produced by collect_endpoints.py")
    parser.add_argument("--output", default="endpoints_scan.json",
                        help="Path to write scan results JSON")
    args = parser.parse_args()

    if not os.path.exists(args.endpoints_json):
        print(f"[ERROR] endpoints.json not found: {args.endpoints_json}")
        raise SystemExit(1)

    with open(args.endpoints_json) as f:
        endpoints_meta = json.load(f)

    print(f"[INFO] Loaded {len(endpoints_meta)} endpoints from {args.endpoints_json}")
    scan_results = ssl_scan(endpoints_meta)

    with open(args.output, 'w') as f:
        json.dump(scan_results, f, indent=2)

    print(f"[INFO] Scan complete. Results written to {args.output}")
    print(f"\n{'ENV':<12} {'ENDPOINT':<35} {'TLS':<10} {'DAYS LEFT':<10} {'SOURCE'}")
    print("-" * 100)
    for r in scan_results:
        days = r['certificate'].get('daysToExpiry')
        days_str = str(days) if days is not None else 'N/A'
        print(f"{r['env']:<12} {r['endpoint']:<35} {r['tlsProtocol']:<10} {days_str:<10} {r['source_file']}:{r['line']}")
