# Sentinel-OP v0.1.0

Single-file CLI for cryptographic proof of human contribution over AI-generated files.

## Ship checklist (user, 2 min)

```bash
cd sentinel-op
git pull
git tag v0.1.0
git push origin v0.1.0
# GitHub → Releases → Draft from tag v0.1.0 → paste this file
```

Then post one 15-second terminal GIF of:

```bash
python3 sentinel.py init
python3 sentinel.py record --prompt "demo" --file README.md
python3 sentinel.py list
```

## Included

- `sentinel.py` — stdlib-only CLI (init, record, list, verify, sign, publish)
- `test_sentinel.py`
- `.sentinel/` sample records
- MIT license
- VERSION 0.1.0

## Not included (v0.2)

- PyPI package / pip install
- Public demo GIF (user records)
- Signed GitHub Release assets
