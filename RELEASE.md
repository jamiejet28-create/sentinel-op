# Sentinel-OP v0.1.0

Single-file CLI for cryptographic proof of human contribution over AI-generated files.

## Ship checklist (user, 2 min)

```bash
cd sentinel-op
git pull
bash package.sh
git tag v0.1.0
git push origin v0.1.0
# GitHub → Releases → Draft from tag v0.1.0 → paste this file
# Attach dist/sentinel-op-0.1.0.zip
```

`package.sh` writes `dist/sentinel-op-0.1.0.zip` (stdlib CLI, tests, sample records, license). It excludes `__pycache__`, `*.pyc`, `.git`, and `.venv`.

Then post one 15-second terminal GIF of:

```bash
bash demo.sh
```

## Included

- `sentinel.py` — stdlib-only CLI (init, record, list, verify, sign, publish)
- `test_sentinel.py`
- `.sentinel/` sample records
- MIT license
- VERSION 0.1.0
- `package.sh` — local zip, no tag required to build

## Not included (v0.2)

- PyPI package / pip install
- Public demo GIF (user records)
- Signed GitHub Release assets (needs the v0.1.0 tag push)
