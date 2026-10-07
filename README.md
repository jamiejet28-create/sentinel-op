# Sentinel-OP

> **Proof of Contribution** — Cryptographic provenance for AI-generated work.

---

## Quickstart (10 lines)

```bash
git clone https://github.com/jamiejet28-create/sentinel-op.git
cd sentinel-op
python3 sentinel.py init
# after AI generates a file:
python3 sentinel.py record --prompt "your prompt" --file path/to/file.py
python3 sentinel.py list
```

Commit `.sentinel/` with your code. That is your proof trail.

---

## What Is Sentinel-OP?

Sentinel-OP is a lightweight CLI tool for recording provenance information about code or other artifacts, including a prompt, a file hash, and optional signatures or timestamp tokens.

As AI-assisted development becomes the norm, legal systems are grappling with a central question:

> *Who owns AI-generated code — and can that ownership be proven?*

Sentinel-OP stores a prompt supplied by the user alongside a hash of a file in a JSON-LD manifest. The record can optionally be signed with GPG and submitted to a third-party Timestamp Authority (TSA). These mechanisms protect the recorded data against undetected changes; they do not independently prove that an AI system received the prompt, who created the file, or who owns its copyright.

---

## The "Human-in-the-Loop" Legal Theory

### Why Human Contribution Matters

Copyright rules vary by jurisdiction and change over time. Whether a person qualifies as an author depends on the facts and applicable law; a provenance record cannot answer that question or establish ownership.

Human direction and creative contribution may be relevant in some copyright analyses, but there is no general “Human-in-the-Loop” rule that this tool can certify.

### How Prompt + Output = Defensible IP

Sentinel-OP records the following data and optional mechanisms:

| Pillar | What It Captures | Legal Significance |
|---|---|---|
| **Prompt** | Text entered by the user | Records the text; does not prove it was sent to an AI |
| **File hash** | SHA-256 hash of the selected file | Allows later comparison with the file's bytes |
| **Local time** | System clock time when recording | Informational only; the local clock may be inaccurate or changed |
| **GPG signature** | Optional signature of the manifest payload | Can verify a signature against a public key; does not establish legal identity by itself |
| **TSA token** | Optional RFC 3161 timestamp response | Can support verification that a submitted hash existed by a TSA time, subject to validating the token and trust chain |

Keeping records in version control can create an **auditable history** that:

1. Shows what prompt text and file hash a record contained.
2. Allows later comparison to see whether a file matches its recorded hash.
3. A valid signature can show that the signed payload was signed by the key holder; key ownership and identity still need to be established separately.
4. A successfully verified TSA token can support a claim that the submitted payload existed no later than the time attested by that TSA.

These records do not by themselves prove authorship, ownership, originality, legal priority, or admissibility in a proceeding. Their evidentiary value depends on the facts, verification, applicable law, and the decision-maker.

---

## Installation

No Python dependencies beyond the standard library (Python 3.8+).

```bash
git clone https://github.com/jamiejet28-create/sentinel-op.git
cd sentinel-op
chmod +x sentinel.py
# Optionally add to PATH
cp sentinel.py /usr/local/bin/sentinel
```

### System Requirements (optional, for full feature set)
- **GPG** — for identity signing (`gpg --gen-key` to create a key)
- **OpenSSL** — for RFC 3161 trusted timestamps (`openssl version` to check)
- **curl** — for TSA HTTP requests (fallback to Python `urllib` if unavailable)
- **IPFS Kubo** — for decentralized publishing (`ipfs version` to check)

---

## Usage

### 1. Initialize

Run once per project:

```bash
cd my-ai-project/
python sentinel.py init
```

Creates a `.sentinel/` directory with a `records/` subdirectory and a `meta.json` project manifest.

Records are stored in plain text. Review them before committing or sharing: prompts may contain confidential code, customer information, credentials, or other sensitive details.

---

### 2. Record a Contribution

After generating a file with an AI tool:

```bash
python sentinel.py record \
  --prompt "Write a Python function that validates JWT tokens using HMAC-SHA256" \
  --file src/auth/jwt_validator.py
```

**Example output:**
```
Provenance record created:
  Record ID : a3f7c012-...
  File      : src/auth/jwt_validator.py
  SHA-256   : e3b0c44298fc1c149afb...
  Timestamp : 2026-04-29T14:23:01.456789+00:00
  Manifest  : .sentinel/records/src_auth_jwt_validator_py_...jsonld
```

---

### 3. Record with a Trusted Timestamp (Recommended)

Add `--tsa` to request an RFC 3161 trusted timestamp from a third-party authority:

```bash
# Use the default TSA (freetsa.org)
python sentinel.py record \
  --prompt "Implement JWT validation with RS256 support" \
  --file src/auth/jwt_validator.py \
  --tsa

# Or specify a custom TSA URL
python sentinel.py record \
  --prompt "Implement JWT validation with RS256 support" \
  --file src/auth/jwt_validator.py \
  --tsa https://timestamp.digicert.com
```

**Example output:**
```
  Requesting trusted timestamp from https://freetsa.org/tsr ...
  ✓ Trusted timestamp obtained (TSA time: Apr 29 14:23:02 2026 GMT)
Provenance record created:
  Record ID : b8e2a1f0-...
  File      : src/auth/jwt_validator.py
  SHA-256   : e3b0c44298fc1c149afb...
  Timestamp : 2026-04-29T14:23:01.456789+00:00
  Manifest  : .sentinel/records/...jsonld
  TSA       : https://freetsa.org/tsr (RFC 3161)
```

> **Note:** If the TSA server is unreachable, the record is still created — just without the trusted timestamp. You can always re-record later with `--tsa`.

---

### 4. Sign a Manifest (Recommended)

After recording, sign the manifest with your GPG key to bind your identity:

```bash
python sentinel.py sign \
  --manifest .sentinel/records/src_auth_jwt_validator_py_20260429T142301_b8e2a1f0.jsonld
```

**Example output:**
```
Manifest signed successfully:
  Manifest  : .sentinel/records/...jsonld
  Signer    : Alice Developer <alice@example.com>
  Key ID    : BE9A28B3DF413995

✓ SIGNED — Manifest now contains a GPG detached signature.
```

#### GPG Setup

If you don't have a GPG key, generate one:

```bash
gpg --gen-key
```

Install GPG if needed:
- **macOS:** `brew install gnupg`
- **Debian/Ubuntu:** `sudo apt install gnupg`
- **Fedora:** `sudo dnf install gnupg2`
- **Windows:** https://gpg4win.org/

---

### 5. Verify a File

To confirm a file has not been altered, check the signature, and inspect the trusted timestamp:

```bash
python sentinel.py verify --file src/auth/jwt_validator.py
```

**Full verification output (signed + timestamped):**
```
Verifying: src/auth/jwt_validator.py
  Record ID   : b8e2a1f0-...
  Recorded at : 2026-04-29T14:23:01+00:00
  Prompt      : Implement JWT validation with RS256 support
  Stored hash : e3b0c44298fc...
  Current hash: e3b0c44298fc...

✓ VERIFIED — File matches the provenance record. Hash is intact.

✓ SIGNATURE VERIFIED — Signed by 'Alice Developer <alice@example.com>' (Key: BE9A28B3DF413995)
  GPG: gpg: Good signature from "Alice Developer <alice@example.com>"

🕐 TRUSTED TIMESTAMP DETECTED
  TSA URL     : https://freetsa.org/tsr
  TSA Time    : Apr 29 14:23:02 2026 GMT
  Status      : fetched
  ✓ TSA TOKEN VERIFIED — Timestamp is authentic against payload.
```

**Exit codes:**
| Code | Meaning |
|------|---------|
| `0` | Verified (hash matches; signature valid if present) |
| `1` | No provenance record found |
| `2` | Hash mismatch — file was modified |
| `3` | Hash matches but GPG signature is invalid |

---

### 6. List All Records

Browse all provenance records in the current project:

```bash
python sentinel.py list
```

**Example output:**
```
ID                                     Timestamp                    File                           Sig        TSA
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
b8e2a1f0-4a3b-4e9c-8d1f-2e7a6c5b9d0e   2026-04-29T14:23:01+00:00  src/auth/jwt_validator.py       ✓ signed   ✓ fetched
c3d4e5f6-7a8b-9c0d-1e2f-3a4b5c6d7e8f   2026-04-29T15:01:22+00:00  src/utils/helpers.py            unsigned   none

Total: 2 record(s)
```

---

### 7. Publish to IPFS (Decentralized Storage)

Make your provenance record **unsinkable** by publishing it to the [InterPlanetary File System (IPFS)](https://ipfs.tech/):

```bash
python sentinel.py publish \
  --manifest .sentinel/records/src_auth_jwt_validator_py_20260429T142301_b8e2a1f0.jsonld
```

**Example output:**
```
Publishing to IPFS: .sentinel/records/...jsonld

✓ PUBLISHED to IPFS.
  Manifest  : .sentinel/records/...jsonld
  CID       : QmX4z8f...abc123
  Gateway   : https://ipfs.io/ipfs/QmX4z8f...abc123
  Published : 2026-04-29T16:45:00+00:00

The manifest is left unchanged after publishing so that the CID refers to the exact file uploaded and existing signatures remain intact. Save the CID separately. IPFS content may become unavailable unless retained or pinned by nodes; publication does not guarantee permanence or broad availability.
```

#### IPFS Setup

Install the IPFS Kubo node:

```bash
# Download from https://docs.ipfs.tech/install/command-line/
# Then initialize and start the daemon:
ipfs init
ipfs daemon
```

Alternatively, upload your `.jsonld` manifest directly to a **pinning service** without running a local node:
- [Pinata](https://www.pinata.cloud/)
- [Web3.Storage](https://web3.storage/)
- [Infura IPFS](https://infura.io/product/ipfs)

---

## What IPFS Provides

### The Problem with Centralized Storage

When your provenance records live only on your local machine or even on GitHub, they are vulnerable:

- **Local failure:** Hard drive crashes, accidental deletions, or ransomware can destroy your records.
- **Platform risk:** A centralized service can go down, delete your repository, or be acquired by an entity hostile to your interests.
- **Tampering allegations:** An adversary could argue that you modified files on your own infrastructure after the fact.

### What IPFS Provides

[IPFS](https://ipfs.tech/) is a **content-addressed, peer-to-peer** storage network. When you publish a file to IPFS:

1. **Content-addressed integrity** — The file's address (CID) is derived from a cryptographic hash of its contents. If even a single byte changes, the CID changes. This makes tampering mathematically impossible without generating a new address.
2. **Potential persistence** — Content may remain available while nodes retain or pin it, but availability is not guaranteed.
3. **Global verifiability** — Anyone in the world can retrieve your manifest using just the CID. No account, no API key, no permission needed.
4. **Complementary to TSA** — A TSA token may attest to a submitted hash's time; IPFS provides a content address for the bytes uploaded. Neither mechanism establishes authorship or ownership.

### The Complete Proof Stack

| Layer | Tool | What It Proves |
|-------|------|----------------|
| **Prompt** | `sentinel record --prompt` | The text entered in the record |
| **Integrity** | SHA-256 file hash | The artifact has not been altered |
| **Identity** | `sentinel sign` (GPG) | *You specifically* made this claim |
| **Time** | `sentinel record --tsa` (RFC 3161) | A TSA's attestation time, if the token and trust chain verify |
| **Content address** | `sentinel publish` (IPFS) | A CID for the exact uploaded bytes; availability depends on retention |

## Why Trusted Timestamps Are the Gold Standard

### The Problem with Self-Asserted Timestamps

When you create a file and record a timestamp, that timestamp is *self-asserted*. You set it. A skeptic, a court, or an opposing counsel could argue that you manipulated your system clock, backdated the record, or fabricated the timestamp after the fact. Even Git commit timestamps can be forged.

### What RFC 3161 Can Provide

[RFC 3161](https://datatracker.ietf.org/doc/html/rfc3161) defines a protocol where an independent, trusted third party — a **Timestamp Authority (TSA)** — cryptographically signs a hash of your data along with the current time from their own clock. This creates a **Timestamp Token (TSR)** that proves:

1. A valid token can attest that a hash was submitted to a TSA by the time in the token.
2. Verification requires validating the token and the TSA's certificate chain and trust policy.
3. Legal effect and admissibility depend on the jurisdiction and circumstances; RFC 3161 alone does not guarantee either.

### Recordkeeping, Not First-to-File Protection

An independently verified timestamp may be one piece of recordkeeping evidence. It does not establish patent rights, copyright ownership, or priority by itself:

- **Patent matters:** Patentability, prior art, and rights depend on applicable patent law and specific facts.
- **Copyright matters:** A timestamp does not determine authorship or which claimant prevails.
- **Trade secrets:** A timestamp does not establish that information qualifies for trade-secret protection or that reasonable secrecy measures were taken.

### Public TSA Services

Several free and commercial TSA services are available:

| TSA | URL | Notes |
|-----|-----|-------|
| FreeTSA | `https://freetsa.org/tsr` | Free, open-source (default) |
| DigiCert | `https://timestamp.digicert.com` | Commercial CA, widely trusted |
| Sectigo | `http://timestamp.sectigo.com` | Commercial CA |
| Apple | `http://timestamp.apple.com/ts01` | Apple's TSA |

---

## Manifest Format (JSON-LD)

Each `.sentinel/records/*.jsonld` file uses [W3C PROV-O](https://www.w3.org/TR/prov-o/) vocabulary and [JSON-LD](https://json-ld.org/), making it interoperable with semantic web tooling and future legal-tech platforms.

```json
{
  "@context": { ... },
  "@type": "sentinel:ProvenanceRecord",
  "@id": "urn:sentinel:<uuid>",
  "sentinel:recordId": "<uuid>",
  "sentinel:schemaVersion": "2.0.0",
  "prov:generatedAtTime": "2026-04-29T14:23:01+00:00",
  "prov:wasAttributedTo": {
    "@type": "prov:Person",
    "prov:label": "Human Developer (author of prompt)"
  },
  "sentinel:humanIntent": {
    "sentinel:promptText": "Implement JWT validation...",
    "sentinel:promptTimestamp": "2026-04-29T14:23:01+00:00"
  },
  "sentinel:artifactRecord": {
    "sentinel:filePath": "src/auth/jwt_validator.py",
    "sentinel:hashAlgorithm": "SHA-256",
    "sentinel:fileHash": "e3b0c44298fc1c149afb..."
  },
  "sentinel:digitalSignature": {
    "@type": "sentinel:GPGSignature",
    "sentinel:status": "signed",
    "sentinel:signerIdentity": "Alice Developer <alice@example.com>",
    "sentinel:keyId": "BE9A28B3DF413995",
    "sentinel:signedAt": "2026-04-29T14:23:05+00:00",
    "sentinel:signatureValue": "-----BEGIN PGP SIGNATURE-----\n..."
  },
  "sentinel:trustedTimestamp": {
    "@type": "sentinel:RFC3161Timestamp",
    "sentinel:tsaUrl": "https://freetsa.org/tsr",
    "sentinel:tsrToken": "<base64-encoded TSR>",
    "sentinel:tsaTime": "Apr 29 14:23:02 2026 GMT",
    "sentinel:status": "fetched",
    "sentinel:verifiedLocally": true,
    "sentinel:tsrSizeBytes": 4521
  },
  "sentinel:ipfsRecord": {
    "@type": "sentinel:IPFSPublication",
    "sentinel:ipfsCid": "QmX4z8f...abc123",
    "sentinel:gatewayUrl": "https://ipfs.io/ipfs/QmX4z8f...abc123",
    "sentinel:publishedAt": "2026-04-29T16:45:00+00:00",
    "sentinel:status": "published"
  }
}
```

---

## Recommended Workflow

```
Write prompt → Generate code → sentinel record --tsa → sentinel sign → sentinel publish → save CID separately → git commit
                                                                                            ↑
                                                              .sentinel/records/ committed here
```

If you edit the AI output after signing, **record again** and **sign again** with a new prompt noting your changes. This creates an audit trail of your iterative creative process.

---

## Limitations & Disclaimers

- Sentinel-OP is a **technical tool**, not legal advice. Consult an IP attorney for your jurisdiction.
- Records contain prompt text in plain text. Do not record or publish secrets or information you are not willing to disclose. IPFS publication may make the manifest publicly retrievable, and availability depends on pinning or retention.
- Git history and local timestamps can be changed; a public repository does not independently prove authorship or ownership.
- TSA token verification requires the TSA's certificate chain and trust validation. An inconclusive local check does not establish that a token is valid.
- GPG signature verification requires the signer's public key to be available in the verifier's GPG keyring.
- The `--tsa` flag requires `openssl` to be installed on your system.
- Signing and timestamping can support verification of a record but do not guarantee legal admissibility, copyright protection, or ownership.

---

## License

MIT — use freely, contribute openly.
