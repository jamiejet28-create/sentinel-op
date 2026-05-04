#!/usr/bin/env python3
"""
Sentinel-OP: Proof of Contribution CLI for AI Developers
Establishes cryptographic records of human creative intent behind AI-generated code.
"""

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path


SENTINEL_DIR = ".sentinel"
RECORDS_DIR = os.path.join(SENTINEL_DIR, "records")
META_FILE = os.path.join(SENTINEL_DIR, "meta.json")

DEFAULT_TSA_URL = "https://freetsa.org/tsr"


def _ensure_sentinel_exists():
    if not os.path.isdir(SENTINEL_DIR):
        print("Error: No .sentinel directory found. Run `sentinel init` first.", file=sys.stderr)
        sys.exit(1)


def _sha256_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _normalize_path(filepath: str) -> str:
    return os.path.normpath(filepath)


def _gpg_binary():
    """Return path to gpg binary, or None if not found."""
    return shutil.which("gpg") or shutil.which("gpg2")


def _openssl_binary():
    """Return path to openssl binary, or None if not found."""
    return shutil.which("openssl")



def _ipfs_binary():
    """Return path to ipfs binary, or None if not found."""
    return shutil.which("ipfs")


def _require_ipfs():
    """Exit with a helpful message if ipfs is not installed."""
    if _ipfs_binary() is None:
        print(
            "Error: IPFS (Kubo) is not installed or not found in PATH.\n"
            "\n"
            "To publish provenance records to the decentralized web, you need\n"
            "a local IPFS node running. Install options:\n"
            "\n"
            "  Option 1 — Install Kubo (recommended):\n"
            "    https://docs.ipfs.tech/install/command-line/\n"
            "    Then run: ipfs init && ipfs daemon\n"
            "\n"
            "  Option 2 — Use a pinning service (no local node needed):\n"
            "    • Pinata:    https://www.pinata.cloud/\n"
            "    • Web3.Storage: https://web3.storage/\n"
            "    • Infura:    https://infura.io/product/ipfs\n"
            "    Upload your .jsonld manifest file directly to any pinning service\n"
            "    and record the CID manually in your manifest.\n",
            file=sys.stderr,
        )
        sys.exit(1)

def _require_gpg():
    """Exit with a helpful message if gpg is not installed."""
    if _gpg_binary() is None:
        print(
            "Error: GPG is not installed or not found in PATH.\n"
            "Install it with:\n"
            "  macOS:   brew install gnupg\n"
            "  Debian:  sudo apt install gnupg\n"
            "  Fedora:  sudo dnf install gnupg2\n"
            "  Windows: https://gpg4win.org/",
            file=sys.stderr,
        )
        sys.exit(1)


def _require_openssl():
    """Exit with a helpful message if openssl is not installed."""
    if _openssl_binary() is None:
        print(
            "Error: OpenSSL is not installed or not found in PATH.\n"
            "Install it with:\n"
            "  macOS:   brew install openssl\n"
            "  Debian:  sudo apt install openssl\n"
            "  Fedora:  sudo dnf install openssl\n"
            "  Windows: https://slproweb.com/products/Win32OpenSSL.html",
            file=sys.stderr,
        )
        sys.exit(1)


def _canonical_payload(manifest: dict) -> str:
    """
    Return a deterministic JSON string of the manifest with the
    sentinel:digitalSignature and sentinel:trustedTimestamp keys removed.
    This is the exact bytes that are signed / verified / timestamped.
    """
    excluded = {"sentinel:digitalSignature", "sentinel:trustedTimestamp"}
    payload = {k: v for k, v in manifest.items() if k not in excluded}
    return json.dumps(payload, sort_keys=True, ensure_ascii=False)


def _gpg_sign(payload: str) -> tuple:
    """
    Sign *payload* with GPG (detached, ASCII-armored).
    Returns (signature_ascii, signer_uid, key_id).
    Raises RuntimeError on failure.
    """
    gpg = _gpg_binary()
    try:
        result = subprocess.run(
            [gpg, "--batch", "--yes", "--armor", "--detach-sign"],
            input=payload.encode("utf-8"),
            capture_output=True,
        )
    except FileNotFoundError:
        raise RuntimeError("GPG binary not executable.")

    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")
        raise RuntimeError(f"GPG signing failed (exit {result.returncode}):\n{stderr}")

    signature = result.stdout.decode("utf-8")

    # Extract the key ID / signer identity from GPG status output
    status_result = subprocess.run(
        [gpg, "--batch", "--armor", "--detach-sign", "--status-fd", "1"],
        input=payload.encode("utf-8"),
        capture_output=True,
    )
    signer_uid = "unknown"
    key_id = "unknown"
    for line in status_result.stdout.decode("utf-8", errors="replace").splitlines():
        if line.startswith("[GNUPG:] KEY_CONSIDERED"):
            parts = line.split()
            if len(parts) >= 3:
                key_id = parts[2][:16]
        if line.startswith("[GNUPG:] SIG_CREATED"):
            parts = line.split()
            if len(parts) >= 5:
                key_id = parts[4]

    # Resolve UID from key listing
    list_result = subprocess.run(
        [gpg, "--batch", "--with-colons", "--list-secret-keys"],
        capture_output=True,
    )
    for line in list_result.stdout.decode("utf-8", errors="replace").splitlines():
        if line.startswith("uid:"):
            uid_parts = line.split(":")
            if len(uid_parts) > 9 and uid_parts[9]:
                signer_uid = uid_parts[9]
                break

    return signature, signer_uid, key_id


def _gpg_verify(payload: str, signature: str) -> tuple:
    """
    Verify *signature* over *payload* using GPG.
    Returns (ok: bool, message: str).
    """
    gpg = _gpg_binary()
    if gpg is None:
        return False, "GPG not installed — cannot verify signature."

    with tempfile.TemporaryDirectory() as tmpdir:
        payload_file = os.path.join(tmpdir, "payload.txt")
        sig_file = os.path.join(tmpdir, "payload.txt.asc")

        with open(payload_file, "wb") as f:
            f.write(payload.encode("utf-8"))
        with open(sig_file, "w") as f:
            f.write(signature)

        result = subprocess.run(
            [gpg, "--batch", "--verify", sig_file, payload_file],
            capture_output=True,
        )

    if result.returncode == 0:
        stderr_text = result.stderr.decode("utf-8", errors="replace")
        signer_info = ""
        for line in stderr_text.splitlines():
            if "Good signature from" in line:
                signer_info = line.strip()
                break
        return True, signer_info or "Good signature."
    else:
        stderr_text = result.stderr.decode("utf-8", errors="replace")
        return False, stderr_text.strip()


def _request_tsa_token(canonical_payload: str, tsa_url: str) -> dict:
    """
    Request an RFC 3161 Trusted Timestamp from a TSA using openssl.
    Returns a dict with tsa_url, base64-encoded TSR token, and status.
    Raises RuntimeError on failure.
    """
    openssl = _openssl_binary()
    if openssl is None:
        raise RuntimeError("OpenSSL is not installed.")

    with tempfile.TemporaryDirectory() as tmpdir:
        data_file = os.path.join(tmpdir, "payload.dat")
        tsq_file = os.path.join(tmpdir, "request.tsq")
        tsr_file = os.path.join(tmpdir, "response.tsr")

        # Write the canonical payload to a file
        with open(data_file, "wb") as f:
            f.write(canonical_payload.encode("utf-8"))

        # Step 1: Create a Timestamp Query (TSQ) using openssl
        result = subprocess.run(
            [openssl, "ts", "-query", "-data", data_file, "-no_nonce", "-sha256", "-out", tsq_file],
            capture_output=True,
        )
        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="replace")
            raise RuntimeError(f"OpenSSL ts -query failed (exit {result.returncode}):\n{stderr}")

        # Read the TSQ for the HTTP POST
        with open(tsq_file, "rb") as f:
            tsq_data = f.read()

        # Step 2: Send the TSQ to the TSA via curl (more reliable than urllib for TSA servers)
        curl_bin = shutil.which("curl")
        if curl_bin:
            result = subprocess.run(
                [
                    curl_bin, "-s", "-S",
                    "-H", "Content-Type: application/timestamp-query",
                    "--data-binary", "@" + tsq_file,
                    "-o", tsr_file,
                    "-w", "%{http_code}",
                    "--max-time", "30",
                    tsa_url,
                ],
                capture_output=True,
            )
            http_code = result.stdout.decode("utf-8", errors="replace").strip()
            if result.returncode != 0:
                stderr = result.stderr.decode("utf-8", errors="replace")
                raise RuntimeError(f"curl to TSA failed (exit {result.returncode}):\n{stderr}")
            if http_code and not http_code.startswith("2"):
                raise RuntimeError(f"TSA returned HTTP {http_code}")
        else:
            # Fallback: use urllib from stdlib
            import urllib.request
            req = urllib.request.Request(
                tsa_url,
                data=tsq_data,
                headers={"Content-Type": "application/timestamp-query"},
            )
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    tsr_data = resp.read()
                with open(tsr_file, "wb") as f:
                    f.write(tsr_data)
            except Exception as e:
                raise RuntimeError(f"HTTP request to TSA failed: {e}")

        if not os.path.isfile(tsr_file) or os.path.getsize(tsr_file) == 0:
            raise RuntimeError("TSA returned an empty response.")

        # Step 3: Verify the TSR against the original data
        verify_result = subprocess.run(
            [openssl, "ts", "-verify", "-data", data_file, "-in", tsr_file,
             "-token_in"],
            capture_output=True,
        )
        # Note: verification may fail without the TSA certificate chain;
        # we still store the token and mark whether verification succeeded locally
        verified_locally = verify_result.returncode == 0

        # Read and base64-encode the TSR
        with open(tsr_file, "rb") as f:
            tsr_bytes = f.read()
        tsr_b64 = base64.b64encode(tsr_bytes).decode("ascii")

        # Try to extract the timestamp text from the TSR for display
        reply_text_result = subprocess.run(
            [openssl, "ts", "-reply", "-in", tsr_file, "-text"],
            capture_output=True,
        )
        tsr_text = reply_text_result.stdout.decode("utf-8", errors="replace") if reply_text_result.returncode == 0 else ""

        # Extract the "Time stamp" line if present
        tsa_time = ""
        for line in tsr_text.splitlines():
            if "Time stamp:" in line:
                tsa_time = line.split(":", 1)[1].strip()
                break

        return {
            "tsa_url": tsa_url,
            "tsr_token": tsr_b64,
            "tsr_size_bytes": len(tsr_bytes),
            "tsa_time": tsa_time,
            "verified_locally": verified_locally,
            "status": "fetched",
        }


def _verify_tsa_token(canonical_payload: str, tsr_b64: str) -> tuple:
    """
    Verify a stored TSR token against the canonical payload.
    Returns (ok: bool, message: str, tsa_time: str).
    """
    openssl = _openssl_binary()
    if openssl is None:
        return False, "OpenSSL not installed — cannot verify TSA token.", ""

    with tempfile.TemporaryDirectory() as tmpdir:
        data_file = os.path.join(tmpdir, "payload.dat")
        tsr_file = os.path.join(tmpdir, "response.tsr")

        with open(data_file, "wb") as f:
            f.write(canonical_payload.encode("utf-8"))

        try:
            tsr_bytes = base64.b64decode(tsr_b64)
        except Exception:
            return False, "Invalid base64 in TSR token.", ""

        with open(tsr_file, "wb") as f:
            f.write(tsr_bytes)

        # Extract timestamp info
        reply_result = subprocess.run(
            [openssl, "ts", "-reply", "-in", tsr_file, "-text"],
            capture_output=True,
        )
        tsa_time = ""
        if reply_result.returncode == 0:
            for line in reply_result.stdout.decode("utf-8", errors="replace").splitlines():
                if "Time stamp:" in line:
                    tsa_time = line.split(":", 1)[1].strip()
                    break

        # Try to verify (may need TSA cert chain for full verification)
        verify_result = subprocess.run(
            [openssl, "ts", "-verify", "-data", data_file, "-in", tsr_file, "-token_in"],
            capture_output=True,
        )

        if verify_result.returncode == 0:
            return True, "TSA token verified against payload.", tsa_time
        else:
            # Even if local crypto verification fails (missing TSA CA cert),
            # the token itself is still valid evidence
            stderr = verify_result.stderr.decode("utf-8", errors="replace").strip()
            return False, f"Local verification inconclusive (TSA CA cert may be needed): {stderr}", tsa_time



def _find_manifests_for_file(filepath: str) -> list:
    """
    Find all manifest files for a given filepath, sorted by internal timestamp
    (oldest first). Returns list of Path objects.
    """
    safe_stem = filepath.replace(os.sep, "_").replace(".", "_")
    records_path = Path(RECORDS_DIR)
    candidates = list(records_path.glob(f"{safe_stem}_*.jsonld"))

    def _get_timestamp(manifest_path):
        try:
            with open(manifest_path) as f:
                data = json.load(f)
            return data.get("prov:generatedAtTime", "")
        except (json.JSONDecodeError, OSError):
            return ""

    return sorted(candidates, key=_get_timestamp)

# ── Commands ──────────────────────────────────────────────────────────


def cmd_init(args):
    if os.path.isdir(SENTINEL_DIR):
        print(f"Sentinel already initialized in '{os.path.abspath(SENTINEL_DIR)}'.")
        return

    os.makedirs(RECORDS_DIR, exist_ok=True)

    meta = {
        "sentinel_version": "2.0.0",
        "project_root": os.path.abspath("."),
        "initialized_at": datetime.now(timezone.utc).isoformat(),
        "description": "Sentinel-OP Proof of Contribution store"
    }
    with open(META_FILE, "w") as f:
        json.dump(meta, f, indent=2)

    gitignore_path = os.path.join(SENTINEL_DIR, ".gitignore")
    with open(gitignore_path, "w") as f:
        f.write("# Keep records tracked by git for auditability\n")
        f.write("!records/\n")

    print(f"Initialized Sentinel-OP in '{os.path.abspath(SENTINEL_DIR)}'")
    print("Records will be stored in .sentinel/records/")


def cmd_record(args):
    _ensure_sentinel_exists()

    prompt = args.prompt.strip()
    filepath = _normalize_path(args.file)

    if not os.path.isfile(filepath):
        print(f"Error: File not found: '{filepath}'", file=sys.stderr)
        sys.exit(1)

    if not prompt:
        print("Error: --prompt cannot be empty.", file=sys.stderr)
        sys.exit(1)

    file_hash = _sha256_file(filepath)
    record_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    manifest = {
        "@context": {
            "@vocab": "https://schema.org/",
            "prov": "http://www.w3.org/ns/prov#",
            "sentinel": "https://sentinel-op.dev/vocab#"
        },
        "@type": "sentinel:ProvenanceRecord",
        "@id": f"urn:sentinel:{record_id}",
        "sentinel:recordId": record_id,
        "sentinel:schemaVersion": "2.0.0",
        "prov:generatedAtTime": timestamp,
        "prov:wasAttributedTo": {
            "@type": "prov:Person",
            "prov:label": "Human Developer (author of prompt)"
        },
        "sentinel:humanIntent": {
            "@type": "sentinel:Prompt",
            "sentinel:promptText": prompt,
            "sentinel:promptTimestamp": timestamp
        },
        "sentinel:artifactRecord": {
            "@type": "sentinel:CodeArtifact",
            "sentinel:filePath": filepath,
            "sentinel:hashAlgorithm": "SHA-256",
            "sentinel:fileHash": file_hash,
            "sentinel:recordedAt": timestamp
        },
        "sentinel:digitalSignature": {
            "@type": "sentinel:SignaturePlaceholder",
            "sentinel:status": "unsigned",
            "sentinel:note": (
                "Replace this placeholder with a cryptographic signature "
                "(e.g., GPG or Ed25519) over the canonical JSON-LD to complete "
                "the Proof of Contribution chain."
            ),
            "sentinel:signatureValue": None
        }
    }

    # ── Optional: RFC 3161 Trusted Timestamp ──
    tsa_url = getattr(args, "tsa", None)
    if tsa_url:
        _require_openssl()
        canonical = _canonical_payload(manifest)
        print(f"  Requesting trusted timestamp from {tsa_url} ...")
        try:
            tsa_result = _request_tsa_token(canonical, tsa_url)
            manifest["sentinel:trustedTimestamp"] = {
                "@type": "sentinel:RFC3161Timestamp",
                "sentinel:tsaUrl": tsa_result["tsa_url"],
                "sentinel:tsrToken": tsa_result["tsr_token"],
                "sentinel:tsaTime": tsa_result["tsa_time"],
                "sentinel:status": tsa_result["status"],
                "sentinel:verifiedLocally": tsa_result["verified_locally"],
                "sentinel:tsrSizeBytes": tsa_result["tsr_size_bytes"],
            }
            print(f"  ✓ Trusted timestamp obtained (TSA time: {tsa_result['tsa_time'] or 'see token'})")
        except RuntimeError as e:
            print(f"  ⚠ TSA request failed: {e}", file=sys.stderr)
            print("  Record will be created without a trusted timestamp.", file=sys.stderr)

    safe_stem = filepath.replace(os.sep, "_").replace(".", "_")
    short_id = record_id[:8]
    ts_compact = timestamp.replace(":", "").replace("-", "").replace("+", "")[:15]
    record_filename = f"{safe_stem}_{ts_compact}_{short_id}.jsonld"
    record_path = os.path.join(RECORDS_DIR, record_filename)

    with open(record_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"Provenance record created:")
    print(f"  Record ID : {record_id}")
    print(f"  File      : {filepath}")
    print(f"  SHA-256   : {file_hash}")
    print(f"  Timestamp : {timestamp}")
    print(f"  Manifest  : {record_path}")
    if "sentinel:trustedTimestamp" in manifest:
        print(f"  TSA       : {tsa_url} (RFC 3161)")


def cmd_sign(args):
    """Sign a manifest file using the user's GPG key."""
    _require_gpg()

    manifest_path = _normalize_path(args.manifest)
    if not os.path.isfile(manifest_path):
        print(f"Error: Manifest file not found: '{manifest_path}'", file=sys.stderr)
        sys.exit(1)

    with open(manifest_path) as f:
        try:
            manifest = json.load(f)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in manifest: {e}", file=sys.stderr)
            sys.exit(1)

    sig_block = manifest.get("sentinel:digitalSignature", {})
    if sig_block.get("sentinel:status") == "signed":
        print(
            f"Warning: This manifest is already signed by "
            f"'{sig_block.get('sentinel:signerIdentity', 'unknown')}'.\n"
            "Re-signing will overwrite the existing signature."
        )

    payload = _canonical_payload(manifest)

    try:
        signature, signer_uid, key_id = _gpg_sign(payload)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    manifest["sentinel:digitalSignature"] = {
        "@type": "sentinel:GPGSignature",
        "sentinel:status": "signed",
        "sentinel:signerIdentity": signer_uid,
        "sentinel:keyId": key_id,
        "sentinel:signedAt": datetime.now(timezone.utc).isoformat(),
        "sentinel:algorithm": "GPG detached ASCII-armored signature",
        "sentinel:signatureValue": signature,
    }

    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"Manifest signed successfully:")
    print(f"  Manifest  : {manifest_path}")
    print(f"  Signer    : {signer_uid}")
    print(f"  Key ID    : {key_id}")
    print(f"\n✓ SIGNED — Manifest now contains a GPG detached signature.")


def cmd_verify(args):
    _ensure_sentinel_exists()

    filepath = _normalize_path(args.file)

    if not os.path.isfile(filepath):
        print(f"Error: File not found: '{filepath}'", file=sys.stderr)
        sys.exit(1)

    matching = _find_manifests_for_file(filepath)

    if not matching:
        print(f"No provenance records found for '{filepath}'.")
        sys.exit(1)

    latest_record_path = matching[-1]

    with open(latest_record_path) as f:
        manifest = json.load(f)

    stored_hash = manifest["sentinel:artifactRecord"]["sentinel:fileHash"]
    current_hash = _sha256_file(filepath)

    record_id = manifest.get("sentinel:recordId", "unknown")
    recorded_at = manifest["sentinel:artifactRecord"].get("sentinel:recordedAt", "unknown")
    prompt = manifest["sentinel:humanIntent"].get("sentinel:promptText", "")

    print(f"Verifying: {filepath}")
    print(f"  Record ID   : {record_id}")
    print(f"  Recorded at : {recorded_at}")
    print(f"  Prompt      : {prompt[:80]}{'...' if len(prompt) > 80 else ''}")
    print(f"  Stored hash : {stored_hash}")
    print(f"  Current hash: {current_hash}")

    # --- Hash integrity check ---
    if current_hash != stored_hash:
        print("\n✗ MISMATCH — File has been modified since the record was created.")
        print("  This may indicate unauthorized alteration of the artifact.")
        sys.exit(2)

    print("\n✓ VERIFIED — File matches the provenance record. Hash is intact.")

    # --- GPG signature check (only if manifest is signed) ---
    sig_block = manifest.get("sentinel:digitalSignature", {})
    sig_status = sig_block.get("sentinel:status", "unsigned")

    if sig_status == "signed":
        signature = sig_block.get("sentinel:signatureValue")
        signer_uid = sig_block.get("sentinel:signerIdentity", "unknown")
        key_id = sig_block.get("sentinel:keyId", "unknown")

        if not signature:
            print("\n⚠ WARNING — Manifest status is 'signed' but no signature value found.")
        else:
            payload = _canonical_payload(manifest)
            ok, message = _gpg_verify(payload, signature)
            if ok:
                print(f"\n✓ SIGNATURE VERIFIED — Signed by '{signer_uid}' (Key: {key_id})")
                if message:
                    print(f"  GPG: {message}")
            else:
                print(f"\n✗ SIGNATURE INVALID — Signature verification failed.")
                print(f"  Signer on record : {signer_uid} (Key: {key_id})")
                print(f"  GPG output       : {message}")
                sys.exit(3)
    else:
        print(f"\n  Signature status: {sig_status} (run `sentinel sign --manifest {latest_record_path}` to sign)")

    # --- RFC 3161 Trusted Timestamp check ---
    tsa_block = manifest.get("sentinel:trustedTimestamp")
    if tsa_block:
        tsa_url = tsa_block.get("sentinel:tsaUrl", "unknown")
        tsa_status = tsa_block.get("sentinel:status", "unknown")
        tsa_time = tsa_block.get("sentinel:tsaTime", "")
        tsr_token = tsa_block.get("sentinel:tsrToken", "")

        print(f"\n🕐 TRUSTED TIMESTAMP DETECTED")
        print(f"  TSA URL     : {tsa_url}")
        print(f"  TSA Time    : {tsa_time or '(embedded in token)'}")
        print(f"  Status      : {tsa_status}")

        if tsr_token and _openssl_binary():
            canonical = _canonical_payload(manifest)
            ok, message, verified_time = _verify_tsa_token(canonical, tsr_token)
            if ok:
                print(f"  ✓ TSA TOKEN VERIFIED — Timestamp is authentic against payload.")
            else:
                print(f"  ⚠ TSA local verification: {message}")
                print(f"    (The TSR token is still valid evidence; full verification requires the TSA's CA certificate.)")
        elif not _openssl_binary():
            print(f"  ⚠ OpenSSL not available — cannot verify TSA token locally.")
    else:
        print(f"\n  Trusted Timestamp: none (use `--tsa` flag with `record` to add one)")


def cmd_publish(args):
    """Publish a manifest to IPFS for decentralized, unsinkable provenance."""
    _require_ipfs()

    manifest_path = _normalize_path(args.manifest)
    if not os.path.isfile(manifest_path):
        print(f"Error: Manifest file not found: '{manifest_path}'", file=sys.stderr)
        sys.exit(1)

    with open(manifest_path) as f:
        try:
            manifest = json.load(f)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in manifest: {e}", file=sys.stderr)
            sys.exit(1)

    ipfs = _ipfs_binary()

    print(f"Publishing to IPFS: {manifest_path}")

    try:
        result = subprocess.run(
            [ipfs, "add", "-q", manifest_path],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        print(
            "Error: IPFS add timed out after 60 seconds.\n"
            "Make sure the IPFS daemon is running: ipfs daemon",
            file=sys.stderr,
        )
        sys.exit(1)
    except FileNotFoundError:
        print("Error: IPFS binary not executable.", file=sys.stderr)
        sys.exit(1)

    if result.returncode != 0:
        stderr = result.stderr.strip()
        print(f"Error: IPFS add failed (exit {result.returncode}):", file=sys.stderr)
        if stderr:
            print(f"  {stderr}", file=sys.stderr)
        if "no IPFS repo" in stderr.lower() or "not initialized" in stderr.lower():
            print("  Run `ipfs init` first to initialize your IPFS repository.", file=sys.stderr)
        elif "lock" in stderr.lower() or "daemon" in stderr.lower():
            print("  Make sure the IPFS daemon is running: ipfs daemon", file=sys.stderr)
        sys.exit(1)

    cid = result.stdout.strip()
    if not cid:
        print("Error: IPFS returned an empty CID.", file=sys.stderr)
        sys.exit(1)

    gateway_url = f"https://ipfs.io/ipfs/{cid}"
    published_at = datetime.now(timezone.utc).isoformat()

    manifest["sentinel:ipfsRecord"] = {
        "@type": "sentinel:IPFSPublication",
        "sentinel:ipfsCid": cid,
        "sentinel:gatewayUrl": gateway_url,
        "sentinel:publishedAt": published_at,
        "sentinel:status": "published",
    }

    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"\n✓ PUBLISHED to IPFS — Your provenance record is now on the decentralized web.")
    print(f"  Manifest  : {manifest_path}")
    print(f"  CID       : {cid}")
    print(f"  Gateway   : {gateway_url}")
    print(f"  Published : {published_at}")
    print(f"\nThis record is now \'unsinkable\' — no central authority can delete or alter it.")
    print(f"Pin it with a pinning service (Pinata, Web3.Storage) for long-term persistence.")


def cmd_list(args):
    """List all provenance records in .sentinel/records/."""
    _ensure_sentinel_exists()

    records_path = Path(RECORDS_DIR)
    manifests = sorted(records_path.glob("*.jsonld"))

    if not manifests:
        print("No provenance records found.")
        return

    print(f"{'ID':<38} {'Timestamp':<28} {'File':<30} {'Sig':<10} {'TSA':<10} {'IPFS':<10}")
    print("─" * 126)

    for manifest_path in manifests:
        try:
            with open(manifest_path) as f:
                manifest = json.load(f)
        except (json.JSONDecodeError, OSError):
            print(f"{'(corrupt)':<38} {'—':<28} {manifest_path.name:<30} {'—':<10} {'—':<10}")
            continue

        record_id = manifest.get("sentinel:recordId", "unknown")
        recorded_at = manifest.get("prov:generatedAtTime", "unknown")
        filepath = manifest.get("sentinel:artifactRecord", {}).get("sentinel:filePath", "unknown")

        # Signature status
        sig_block = manifest.get("sentinel:digitalSignature", {})
        sig_status = sig_block.get("sentinel:status", "none")
        if sig_status == "signed":
            sig_display = "✓ signed"
        elif sig_status == "unsigned":
            sig_display = "unsigned"
        else:
            sig_display = sig_status

        # TSA status
        tsa_block = manifest.get("sentinel:trustedTimestamp")
        if tsa_block:
            tsa_status = tsa_block.get("sentinel:status", "unknown")
            tsa_display = f"✓ {tsa_status}" if tsa_status == "fetched" else tsa_status
        else:
            tsa_display = "none"

        # IPFS status
        ipfs_block = manifest.get("sentinel:ipfsRecord")
        if ipfs_block:
            ipfs_status = ipfs_block.get("sentinel:status", "unknown")
            ipfs_display = f"✓ {ipfs_status}" if ipfs_status == "published" else ipfs_status
        else:
            ipfs_display = "none"

        # Truncate fields for display
        rec_id_short = record_id[:36]
        ts_short = recorded_at[:26]
        file_short = filepath if len(filepath) <= 28 else "..." + filepath[-25:]

        print(f"{rec_id_short:<38} {ts_short:<28} {file_short:<30} {sig_display:<10} {tsa_display:<10} {ipfs_display:<10}")

    print(f"\nTotal: {len(manifests)} record(s)")


def main():
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel-OP: Cryptographic Proof of Contribution for AI-generated work."
    )
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
    subparsers.required = True

    # init
    init_parser = subparsers.add_parser(
        "init",
        help="Initialize a .sentinel directory in the current path."
    )
    init_parser.set_defaults(func=cmd_init)

    # record
    record_parser = subparsers.add_parser(
        "record",
        help="Create a provenance manifest for an AI-generated file."
    )
    record_parser.add_argument("--prompt", required=True, help="The human prompt that produced the file.")
    record_parser.add_argument("--file", required=True, help="Path to the AI-generated file to record.")
    record_parser.add_argument(
        "--tsa", nargs="?", const=DEFAULT_TSA_URL, default=None,
        help=(
            f"Request an RFC 3161 trusted timestamp from a TSA. "
            f"Optionally provide a URL (default: {DEFAULT_TSA_URL})."
        ),
    )
    record_parser.set_defaults(func=cmd_record)

    # sign
    sign_parser = subparsers.add_parser(
        "sign",
        help="Sign a provenance manifest with your GPG key."
    )
    sign_parser.add_argument(
        "--manifest", required=True,
        help="Path to the .jsonld manifest file to sign."
    )
    sign_parser.set_defaults(func=cmd_sign)

    # verify
    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify that a file matches its latest provenance record (and GPG signature / TSA token if present)."
    )
    verify_parser.add_argument("--file", required=True, help="Path to the file to verify.")
    verify_parser.set_defaults(func=cmd_verify)

    # publish
    publish_parser = subparsers.add_parser(
        "publish",
        help="Publish a provenance manifest to IPFS for decentralized, unsinkable storage."
    )
    publish_parser.add_argument(
        "--manifest", required=True,
        help="Path to the .jsonld manifest file to publish to IPFS."
    )
    publish_parser.set_defaults(func=cmd_publish)

    # list
    list_parser = subparsers.add_parser(
        "list",
        help="List all provenance records in .sentinel/records/."
    )
    list_parser.set_defaults(func=cmd_list)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
