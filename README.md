# Sentinel-OP

> **Proof of Contribution** — Cryptographic provenance for AI-generated work.

---

## What Is Sentinel-OP?

Sentinel-OP is a lightweight CLI tool for AI developers to establish a **defensible, cryptographic record of human creative contribution** over AI-generated code or other artifacts.

As AI-assisted development becomes the norm, legal systems are grappling with a central question:

> *Who owns AI-generated code — and can that ownership be proven?*

Sentinel-OP answers that question by capturing the **human intent** (your prompt) alongside the **AI output** (the file) in a tamper-evident JSON-LD provenance manifest — optionally **signed** with your GPG key and **timestamped** by a third-party Trusted Timestamp Authority (TSA).

---

## The "Human-in-the-Loop" Legal Theory

### Why Human Contribution Matters

Current copyright frameworks — including U.S. copyright law and the EU AI Act — require a **human author** to claim IP ownership. A purely machine-generated work, with no human creative direction, may be ineligible for copyright protection.

The decisive factor courts and IP offices are beginning to examine is not *who typed the code*, but **who exercised creative control and directed the output**. This is the "Human-in-the-Loop" doctrine.

### How Prompt + Output = Defensible IP

Sentinel-OP operationalizes this theory with five pillars:

| Pillar | What It Captures | Legal Significance |
|---|---|---|
| **Intent** | The developer's prompt — the creative question posed | Demonstrates human authorship direction |
| **Output** | SHA-256 hash of the produced file | Immutably links the intent to a specific artifact |
| **Timestamp** | UTC ISO-8601 at moment of recording | Establishes priority and chain of custody |
| **Identity** | GPG signature over the manifest | Cryptographically binds *your identity* to *your claim* |
| **Trusted Time** | RFC 3161 TSA token from a third-party authority | Court-admissible proof of *when* the record was created |

By committing these records to version control (e.g., Git), you create a **timestamped, auditable paper trail** that:

1. **Proves you were the originating human agent** — you wrote the prompt, you reviewed the output, you accepted or rejected it.
2. **Establishes prior art** against others who may later claim the same work.
3. **Survives challenge** — if your ownership is disputed, the hash proves the exact file you claimed has not been altered since you recorded it.
4. **Proves identity** — when signed with your GPG key, the manifest is a non-repudiable assertion that *you specifically* made this contribution.
5. **Proves timing** — an RFC 3161 trusted timestamp is issued by an independent third party, providing court-admissible evidence of *when* you recorded your claim.

---

## Installation

No Python dependencies beyond the standard library (Python 3.8+).

```bash
git clone https://github.com/yourname/sentinel-op
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

**Commit `.sentinel/` to your repository.** The records are your proof.

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

✓ PUBLISHED to IPFS — Your provenance record is now on the decentralized web.
  Manifest  : .sentinel/records/...jsonld
  CID       : QmX4z8f...abc123
  Gateway   : https://ipfs.io/ipfs/QmX4z8f...abc123
  Published : 2026-04-29T16:45:00+00:00

This record is now 'unsinkable' — no central authority can delete or alter it.
Pin it with a pinning service (Pinata, Web3.Storage) for long-term persistence.
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

## Why IPFS Makes Your Proof "Unsinkable"

### The Problem with Centralized Storage

When your provenance records live only on your local machine or even on GitHub, they are vulnerable:

- **Local failure:** Hard drive crashes, accidental deletions, or ransomware can destroy your records.
- **Platform risk:** A centralized service can go down, delete your repository, or be acquired by an entity hostile to your interests.
- **Tampering allegations:** An adversary could argue that you modified files on your own infrastructure after the fact.

### What IPFS Provides

[IPFS](https://ipfs.tech/) is a **content-addressed, peer-to-peer** storage network. When you publish a file to IPFS:

1. **Content-addressed integrity** — The file's address (CID) is derived from a cryptographic hash of its contents. If even a single byte changes, the CID changes. This makes tampering mathematically impossible without generating a new address.
2. **Decentralized persistence** — Once published and pinned by multiple nodes, no single entity can delete or censor your record. It exists across a distributed network.
3. **Global verifiability** — Anyone in the world can retrieve your manifest using just the CID. No account, no API key, no permission needed.
4. **Complementary to TSA** — While a Trusted Timestamp proves *when* your record was created, IPFS proves that the record has been *publicly available and unaltered* since publication.

### The Complete Proof Stack

| Layer | Tool | What It Proves |
|-------|------|----------------|
| **Intent** | `sentinel record --prompt` | You directed the AI's output |
| **Integrity** | SHA-256 file hash | The artifact has not been altered |
| **Identity** | `sentinel sign` (GPG) | *You specifically* made this claim |
| **Time** | `sentinel record --tsa` (RFC 3161) | *When* you made the claim (court-admissible) |
| **Persistence** | `sentinel publish` (IPFS) | The claim is globally available and untamperable |

## Why Trusted Timestamps Are the Gold Standard

### The Problem with Self-Asserted Timestamps

When you create a file and record a timestamp, that timestamp is *self-asserted*. You set it. A skeptic, a court, or an opposing counsel could argue that you manipulated your system clock, backdated the record, or fabricated the timestamp after the fact. Even Git commit timestamps can be forged.

### What RFC 3161 Provides

[RFC 3161](https://datatracker.ietf.org/doc/html/rfc3161) defines a protocol where an independent, trusted third party — a **Timestamp Authority (TSA)** — cryptographically signs a hash of your data along with the current time from their own clock. This creates a **Timestamp Token (TSR)** that proves:

1. **Your data existed at a specific moment** — the TSA certifies that the hash you submitted existed at the exact time the token was issued. You cannot backdate a TSR.
2. **The timestamp is independently verifiable** — anyone with the TSA's public certificate can verify the token without contacting you or the TSA.
3. **The timestamp is court-admissible** — RFC 3161 timestamps are recognized as evidence in legal proceedings in the U.S., EU, and most major jurisdictions. They meet the requirements of the EU eIDAS regulation and the U.S. ESIGN Act.

### First-to-File Protection

In patent and IP disputes, **priority** often determines ownership. The party who can demonstrate the earliest verifiable creation date wins. A trusted timestamp provides this proof:

- **Prior art defense:** If someone files a patent on a technique you already documented with a TSA timestamp, you have cryptographic proof that your work predates their filing.
- **Copyright priority:** When two parties claim authorship of similar AI-generated code, the party with the earliest TSR wins the priority dispute.
- **Trade secret documentation:** TSA timestamps prove when proprietary knowledge was documented, establishing the timeline for trade secret protection.

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
Write prompt → Generate code → sentinel record --tsa → sentinel sign → sentinel publish → git commit
                                                                                            ↑
                                                              .sentinel/records/ committed here
```

If you edit the AI output after signing, **record again** and **sign again** with a new prompt noting your changes. This creates an audit trail of your iterative creative process.

---

## Limitations & Disclaimers

- Sentinel-OP is a **technical tool**, not legal advice. Consult an IP attorney for your jurisdiction.
- For strongest protection, push your `.sentinel/records/` to a **public, timestamped Git repository** (GitHub, GitLab) immediately after recording.
- TSA token local verification requires the TSA's CA certificate chain. Without it, `openssl ts -verify` may report inconclusive — the token itself remains valid evidence.
- GPG signature verification requires the signer's public key to be available in the verifier's GPG keyring.
- The `--tsa` flag requires `openssl` to be installed on your system.

---

## License

MIT — use freely, contribute openly.
