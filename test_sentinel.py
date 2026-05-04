"""
Tests for sentinel.py — Sentinel-OP Proof of Contribution CLI
Covers: init, record, verify (hash only), sign, verify (with GPG signature),
        TSA timestamps, list command.
"""

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

SENTINEL_PY = os.path.join(os.path.dirname(__file__), "sentinel.py")
GPG_AVAILABLE = shutil.which("gpg") is not None or shutil.which("gpg2") is not None
OPENSSL_AVAILABLE = shutil.which("openssl") is not None


def run_sentinel(args, cwd):
    result = subprocess.run(
        [sys.executable, SENTINEL_PY] + args,
        cwd=cwd,
        capture_output=True,
        text=True,
    )
    return result


class TestInit:
    def test_creates_sentinel_directory(self, tmp_path):
        result = run_sentinel(["init"], cwd=str(tmp_path))
        assert result.returncode == 0
        assert (tmp_path / ".sentinel").is_dir()
        assert (tmp_path / ".sentinel" / "records").is_dir()
        assert (tmp_path / ".sentinel" / "meta.json").is_file()

    def test_meta_json_has_expected_keys(self, tmp_path):
        run_sentinel(["init"], cwd=str(tmp_path))
        meta = json.loads((tmp_path / ".sentinel" / "meta.json").read_text())
        assert meta["sentinel_version"] == "2.0.0"
        assert "initialized_at" in meta
        assert "project_root" in meta

    def test_init_idempotent(self, tmp_path):
        run_sentinel(["init"], cwd=str(tmp_path))
        result = run_sentinel(["init"], cwd=str(tmp_path))
        assert result.returncode == 0
        assert "already initialized" in result.stdout

    def test_creates_gitignore(self, tmp_path):
        run_sentinel(["init"], cwd=str(tmp_path))
        assert (tmp_path / ".sentinel" / ".gitignore").is_file()


class TestRecord:
    def setup_method(self):
        self.tmp = tempfile.mkdtemp()
        run_sentinel(["init"], cwd=self.tmp)
        self.code_file = os.path.join(self.tmp, "mycode.py")
        with open(self.code_file, "w") as f:
            f.write("def hello(): return 'world'\n")

    def teardown_method(self):
        shutil.rmtree(self.tmp)

    def test_record_creates_manifest(self):
        result = run_sentinel(
            ["record", "--prompt", "Write a hello function", "--file", "mycode.py"],
            cwd=self.tmp,
        )
        assert result.returncode == 0
        records = list(Path(self.tmp, ".sentinel", "records").glob("*.jsonld"))
        assert len(records) == 1

    def test_manifest_contains_correct_hash(self):
        run_sentinel(
            ["record", "--prompt", "Write a hello function", "--file", "mycode.py"],
            cwd=self.tmp,
        )
        records = list(Path(self.tmp, ".sentinel", "records").glob("*.jsonld"))
        manifest = json.loads(records[0].read_text())
        stored_hash = manifest["sentinel:artifactRecord"]["sentinel:fileHash"]
        expected_hash = hashlib.sha256(b"def hello(): return 'world'\n").hexdigest()
        assert stored_hash == expected_hash

    def test_manifest_contains_prompt(self):
        prompt_text = "Write a hello world function in Python"
        run_sentinel(
            ["record", "--prompt", prompt_text, "--file", "mycode.py"],
            cwd=self.tmp,
        )
        records = list(Path(self.tmp, ".sentinel", "records").glob("*.jsonld"))
        manifest = json.loads(records[0].read_text())
        assert manifest["sentinel:humanIntent"]["sentinel:promptText"] == prompt_text

    def test_manifest_has_json_ld_context(self):
        run_sentinel(
            ["record", "--prompt", "test", "--file", "mycode.py"],
            cwd=self.tmp,
        )
        records = list(Path(self.tmp, ".sentinel", "records").glob("*.jsonld"))
        manifest = json.loads(records[0].read_text())
        assert "@context" in manifest
        assert "@type" in manifest
        assert manifest["@type"] == "sentinel:ProvenanceRecord"

    def test_manifest_has_signature_placeholder(self):
        run_sentinel(
            ["record", "--prompt", "test", "--file", "mycode.py"],
            cwd=self.tmp,
        )
        records = list(Path(self.tmp, ".sentinel", "records").glob("*.jsonld"))
        manifest = json.loads(records[0].read_text())
        sig = manifest["sentinel:digitalSignature"]
        assert sig["sentinel:status"] == "unsigned"
        assert sig["sentinel:signatureValue"] is None

    def test_record_nonexistent_file_exits_nonzero(self):
        result = run_sentinel(
            ["record", "--prompt", "test", "--file", "ghost.py"],
            cwd=self.tmp,
        )
        assert result.returncode != 0

    def test_multiple_records_for_same_file(self):
        run_sentinel(
            ["record", "--prompt", "First version", "--file", "mycode.py"],
            cwd=self.tmp,
        )
        run_sentinel(
            ["record", "--prompt", "Second version", "--file", "mycode.py"],
            cwd=self.tmp,
        )
        records = list(Path(self.tmp, ".sentinel", "records").glob("*.jsonld"))
        assert len(records) == 2

    def test_record_without_init_fails(self):
        bare = tempfile.mkdtemp()
        code = os.path.join(bare, "a.py")
        with open(code, "w") as f:
            f.write("x = 1\n")
        result = run_sentinel(
            ["record", "--prompt", "test", "--file", "a.py"],
            cwd=bare,
        )
        assert result.returncode != 0
        shutil.rmtree(bare)

    def test_record_without_tsa_has_no_timestamp_block(self):
        run_sentinel(
            ["record", "--prompt", "no tsa", "--file", "mycode.py"],
            cwd=self.tmp,
        )
        records = list(Path(self.tmp, ".sentinel", "records").glob("*.jsonld"))
        manifest = json.loads(records[0].read_text())
        assert "sentinel:trustedTimestamp" not in manifest

    def test_record_schema_version_is_2(self):
        run_sentinel(
            ["record", "--prompt", "version check", "--file", "mycode.py"],
            cwd=self.tmp,
        )
        records = list(Path(self.tmp, ".sentinel", "records").glob("*.jsonld"))
        manifest = json.loads(records[0].read_text())
        assert manifest["sentinel:schemaVersion"] == "2.0.0"


class TestRecordWithTSA:
    """Tests for --tsa flag. These require openssl."""

    def setup_method(self):
        self.tmp = tempfile.mkdtemp()
        run_sentinel(["init"], cwd=self.tmp)
        self.code_file = os.path.join(self.tmp, "tsa_code.py")
        with open(self.code_file, "w") as f:
            f.write("def timestamped(): return True\n")

    def teardown_method(self):
        shutil.rmtree(self.tmp)

    def test_tsa_flag_accepted_by_parser(self):
        """The --tsa flag should be accepted even if the TSA server is unreachable."""
        result = run_sentinel(
            ["record", "--prompt", "tsa test", "--file", "tsa_code.py",
             "--tsa", "http://localhost:1/fake"],
            cwd=self.tmp,
        )
        # Should still create a record (TSA failure is non-fatal)
        records = list(Path(self.tmp, ".sentinel", "records").glob("*.jsonld"))
        assert len(records) == 1

    def test_tsa_failure_still_creates_record(self):
        """TSA failure should not prevent record creation."""
        result = run_sentinel(
            ["record", "--prompt", "tsa fail", "--file", "tsa_code.py",
             "--tsa", "http://localhost:1/unreachable"],
            cwd=self.tmp,
        )
        assert result.returncode == 0
        records = list(Path(self.tmp, ".sentinel", "records").glob("*.jsonld"))
        manifest = json.loads(records[0].read_text())
        # Record created but no TSA block (since server unreachable)
        assert manifest["sentinel:artifactRecord"]["sentinel:fileHash"]

    def test_tsa_default_url_used_with_bare_flag(self):
        """--tsa with no argument should use the default URL."""
        # We can't actually hit the real TSA in tests reliably,
        # but we can verify the flag parsing works
        result = run_sentinel(
            ["record", "--help"],
            cwd=self.tmp,
        )
        assert "freetsa.org" in result.stdout

    def test_manifest_tsa_block_structure(self):
        """If we manually inject a TSA block, verify its expected structure."""
        run_sentinel(
            ["record", "--prompt", "struct test", "--file", "tsa_code.py"],
            cwd=self.tmp,
        )
        records = list(Path(self.tmp, ".sentinel", "records").glob("*.jsonld"))
        manifest = json.loads(records[0].read_text())

        # Manually add a TSA block to simulate successful fetch
        manifest["sentinel:trustedTimestamp"] = {
            "@type": "sentinel:RFC3161Timestamp",
            "sentinel:tsaUrl": "https://freetsa.org/tsr",
            "sentinel:tsrToken": base64.b64encode(b"fake-tsr-token").decode("ascii"),
            "sentinel:tsaTime": "Apr 29 15:30:00 2026 GMT",
            "sentinel:status": "fetched",
            "sentinel:verifiedLocally": False,
            "sentinel:tsrSizeBytes": 15,
        }
        records[0].write_text(json.dumps(manifest, indent=2))

        # Re-read and verify structure
        reloaded = json.loads(records[0].read_text())
        tsa = reloaded["sentinel:trustedTimestamp"]
        assert tsa["@type"] == "sentinel:RFC3161Timestamp"
        assert tsa["sentinel:tsaUrl"] == "https://freetsa.org/tsr"
        assert tsa["sentinel:status"] == "fetched"
        assert "sentinel:tsrToken" in tsa


class TestVerifyHashOnly:
    def setup_method(self):
        self.tmp = tempfile.mkdtemp()
        run_sentinel(["init"], cwd=self.tmp)
        self.code_file = os.path.join(self.tmp, "app.py")
        with open(self.code_file, "w") as f:
            f.write("print('sentinel')\n")

    def teardown_method(self):
        shutil.rmtree(self.tmp)

    def test_verify_intact_file_returns_zero(self):
        run_sentinel(
            ["record", "--prompt", "print sentinel", "--file", "app.py"],
            cwd=self.tmp,
        )
        result = run_sentinel(["verify", "--file", "app.py"], cwd=self.tmp)
        assert result.returncode == 0
        assert "VERIFIED" in result.stdout

    def test_verify_modified_file_returns_two(self):
        run_sentinel(
            ["record", "--prompt", "print sentinel", "--file", "app.py"],
            cwd=self.tmp,
        )
        with open(self.code_file, "a") as f:
            f.write("# tampered\n")
        result = run_sentinel(["verify", "--file", "app.py"], cwd=self.tmp)
        assert result.returncode == 2
        assert "MISMATCH" in result.stdout

    def test_verify_no_record_returns_one(self):
        unrecorded = os.path.join(self.tmp, "new.py")
        with open(unrecorded, "w") as f:
            f.write("x = 42\n")
        result = run_sentinel(["verify", "--file", "new.py"], cwd=self.tmp)
        assert result.returncode == 1

    def test_verify_uses_latest_record(self):
        run_sentinel(
            ["record", "--prompt", "v1", "--file", "app.py"],
            cwd=self.tmp,
        )
        with open(self.code_file, "w") as f:
            f.write("print('updated sentinel')\n")
        run_sentinel(
            ["record", "--prompt", "v2 updated", "--file", "app.py"],
            cwd=self.tmp,
        )
        result = run_sentinel(["verify", "--file", "app.py"], cwd=self.tmp)
        assert result.returncode == 0
        assert "VERIFIED" in result.stdout

    def test_verify_nonexistent_file_exits_nonzero(self):
        result = run_sentinel(["verify", "--file", "ghost.py"], cwd=self.tmp)
        assert result.returncode != 0

    def test_verify_unsigned_manifest_notes_unsigned_status(self):
        run_sentinel(
            ["record", "--prompt", "unsigned test", "--file", "app.py"],
            cwd=self.tmp,
        )
        result = run_sentinel(["verify", "--file", "app.py"], cwd=self.tmp)
        assert result.returncode == 0
        assert "unsigned" in result.stdout.lower() or "sign" in result.stdout.lower()

    def test_verify_shows_no_tsa_message(self):
        run_sentinel(
            ["record", "--prompt", "no tsa", "--file", "app.py"],
            cwd=self.tmp,
        )
        result = run_sentinel(["verify", "--file", "app.py"], cwd=self.tmp)
        assert result.returncode == 0
        assert "Trusted Timestamp: none" in result.stdout or "--tsa" in result.stdout


class TestVerifyWithTSA:
    """Tests for verify with TSA block present in manifest."""

    def setup_method(self):
        self.tmp = tempfile.mkdtemp()
        run_sentinel(["init"], cwd=self.tmp)
        self.code_file = os.path.join(self.tmp, "tsa_verify.py")
        with open(self.code_file, "w") as f:
            f.write("def verified(): return 'yes'\n")
        run_sentinel(
            ["record", "--prompt", "tsa verify test", "--file", "tsa_verify.py"],
            cwd=self.tmp,
        )
        records = list(Path(self.tmp, ".sentinel", "records").glob("*.jsonld"))
        self.manifest_path = records[0]

    def teardown_method(self):
        shutil.rmtree(self.tmp)

    def test_verify_detects_tsa_block(self):
        """Verify should detect and report trusted timestamp."""
        manifest = json.loads(self.manifest_path.read_text())
        manifest["sentinel:trustedTimestamp"] = {
            "@type": "sentinel:RFC3161Timestamp",
            "sentinel:tsaUrl": "https://freetsa.org/tsr",
            "sentinel:tsrToken": base64.b64encode(b"test-token").decode("ascii"),
            "sentinel:tsaTime": "Apr 29 15:30:00 2026 GMT",
            "sentinel:status": "fetched",
            "sentinel:verifiedLocally": False,
            "sentinel:tsrSizeBytes": 10,
        }
        self.manifest_path.write_text(json.dumps(manifest, indent=2))

        result = run_sentinel(["verify", "--file", "tsa_verify.py"], cwd=self.tmp)
        assert result.returncode == 0
        assert "TRUSTED TIMESTAMP DETECTED" in result.stdout
        assert "freetsa.org" in result.stdout


class TestSign:
    def setup_method(self):
        self.tmp = tempfile.mkdtemp()
        run_sentinel(["init"], cwd=self.tmp)
        self.code_file = os.path.join(self.tmp, "module.py")
        with open(self.code_file, "w") as f:
            f.write("def compute(): return 42\n")
        run_sentinel(
            ["record", "--prompt", "Compute function", "--file", "module.py"],
            cwd=self.tmp,
        )
        records = list(Path(self.tmp, ".sentinel", "records").glob("*.jsonld"))
        self.manifest_path = str(records[0])
        self.manifest_rel = os.path.relpath(self.manifest_path, self.tmp)

    def teardown_method(self):
        shutil.rmtree(self.tmp)

    def _gpg_present(self):
        return GPG_AVAILABLE

    def test_sign_nonexistent_manifest_exits_nonzero(self):
        result = run_sentinel(
            ["sign", "--manifest", "ghost.jsonld"],
            cwd=self.tmp,
        )
        assert result.returncode != 0

    def test_sign_invalid_json_exits_nonzero(self):
        bad_manifest = os.path.join(self.tmp, "bad.jsonld")
        with open(bad_manifest, "w") as f:
            f.write("not valid json {{{")
        result = run_sentinel(
            ["sign", "--manifest", bad_manifest],
            cwd=self.tmp,
        )
        assert result.returncode != 0

    def test_sign_updates_manifest_status(self):
        if not self._gpg_present():
            return
        result = run_sentinel(
            ["sign", "--manifest", self.manifest_path],
            cwd=self.tmp,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}\nstdout: {result.stdout}"
        manifest = json.loads(Path(self.manifest_path).read_text())
        sig = manifest["sentinel:digitalSignature"]
        assert sig["sentinel:status"] == "signed"
        assert sig["sentinel:signatureValue"] is not None
        assert "-----BEGIN PGP SIGNATURE-----" in sig["sentinel:signatureValue"]

    def test_sign_sets_signer_identity(self):
        if not self._gpg_present():
            return
        run_sentinel(
            ["sign", "--manifest", self.manifest_path],
            cwd=self.tmp,
        )
        manifest = json.loads(Path(self.manifest_path).read_text())
        sig = manifest["sentinel:digitalSignature"]
        assert "sentinel:signerIdentity" in sig
        assert sig["sentinel:signerIdentity"] != ""

    def test_sign_sets_signed_at_timestamp(self):
        if not self._gpg_present():
            return
        run_sentinel(
            ["sign", "--manifest", self.manifest_path],
            cwd=self.tmp,
        )
        manifest = json.loads(Path(self.manifest_path).read_text())
        sig = manifest["sentinel:digitalSignature"]
        assert "sentinel:signedAt" in sig

    def test_sign_output_confirms_success(self):
        if not self._gpg_present():
            return
        result = run_sentinel(
            ["sign", "--manifest", self.manifest_path],
            cwd=self.tmp,
        )
        assert "SIGNED" in result.stdout

    def test_sign_preserves_other_manifest_fields(self):
        if not self._gpg_present():
            return
        original = json.loads(Path(self.manifest_path).read_text())
        original_hash = original["sentinel:artifactRecord"]["sentinel:fileHash"]
        original_prompt = original["sentinel:humanIntent"]["sentinel:promptText"]

        run_sentinel(
            ["sign", "--manifest", self.manifest_path],
            cwd=self.tmp,
        )
        updated = json.loads(Path(self.manifest_path).read_text())
        assert updated["sentinel:artifactRecord"]["sentinel:fileHash"] == original_hash
        assert updated["sentinel:humanIntent"]["sentinel:promptText"] == original_prompt


class TestVerifyWithSignature:
    def setup_method(self):
        self.tmp = tempfile.mkdtemp()
        run_sentinel(["init"], cwd=self.tmp)
        self.code_file = os.path.join(self.tmp, "signed_module.py")
        with open(self.code_file, "w") as f:
            f.write("def signed(): return True\n")
        run_sentinel(
            ["record", "--prompt", "Signed module", "--file", "signed_module.py"],
            cwd=self.tmp,
        )
        records = list(Path(self.tmp, ".sentinel", "records").glob("*.jsonld"))
        self.manifest_path = str(records[0])

    def teardown_method(self):
        shutil.rmtree(self.tmp)

    def test_verify_signed_manifest_reports_signature_verified(self):
        if not GPG_AVAILABLE:
            return
        run_sentinel(
            ["sign", "--manifest", self.manifest_path],
            cwd=self.tmp,
        )
        result = run_sentinel(
            ["verify", "--file", "signed_module.py"],
            cwd=self.tmp,
        )
        assert result.returncode == 0
        assert "SIGNATURE VERIFIED" in result.stdout

    def test_verify_tampered_signature_exits_three(self):
        if not GPG_AVAILABLE:
            return
        run_sentinel(
            ["sign", "--manifest", self.manifest_path],
            cwd=self.tmp,
        )
        manifest = json.loads(Path(self.manifest_path).read_text())
        manifest["sentinel:digitalSignature"]["sentinel:signatureValue"] = (
            "-----BEGIN PGP SIGNATURE-----\nZZZZFAKEZZZZ\n-----END PGP SIGNATURE-----\n"
        )
        Path(self.manifest_path).write_text(json.dumps(manifest, indent=2))

        result = run_sentinel(
            ["verify", "--file", "signed_module.py"],
            cwd=self.tmp,
        )
        assert result.returncode == 3
        assert "SIGNATURE INVALID" in result.stdout

    def test_verify_missing_signature_value_warns(self):
        if not GPG_AVAILABLE:
            return
        run_sentinel(
            ["sign", "--manifest", self.manifest_path],
            cwd=self.tmp,
        )
        manifest = json.loads(Path(self.manifest_path).read_text())
        manifest["sentinel:digitalSignature"]["sentinel:signatureValue"] = None
        Path(self.manifest_path).write_text(json.dumps(manifest, indent=2))

        result = run_sentinel(
            ["verify", "--file", "signed_module.py"],
            cwd=self.tmp,
        )
        assert "WARNING" in result.stdout or result.returncode == 0


class TestList:
    """Tests for the `list` command."""

    def setup_method(self):
        self.tmp = tempfile.mkdtemp()
        run_sentinel(["init"], cwd=self.tmp)

    def teardown_method(self):
        shutil.rmtree(self.tmp)

    def test_list_empty_records(self):
        result = run_sentinel(["list"], cwd=self.tmp)
        assert result.returncode == 0
        assert "No provenance records found" in result.stdout

    def test_list_shows_single_record(self):
        code_file = os.path.join(self.tmp, "listed.py")
        with open(code_file, "w") as f:
            f.write("x = 1\n")
        run_sentinel(
            ["record", "--prompt", "list test", "--file", "listed.py"],
            cwd=self.tmp,
        )
        result = run_sentinel(["list"], cwd=self.tmp)
        assert result.returncode == 0
        assert "listed.py" in result.stdout
        assert "Total: 1 record(s)" in result.stdout

    def test_list_shows_multiple_records(self):
        for i in range(3):
            code_file = os.path.join(self.tmp, f"file{i}.py")
            with open(code_file, "w") as f:
                f.write(f"x = {i}\n")
            run_sentinel(
                ["record", "--prompt", f"record {i}", "--file", f"file{i}.py"],
                cwd=self.tmp,
            )
        result = run_sentinel(["list"], cwd=self.tmp)
        assert result.returncode == 0
        assert "Total: 3 record(s)" in result.stdout

    def test_list_shows_signature_status(self):
        code_file = os.path.join(self.tmp, "sig_list.py")
        with open(code_file, "w") as f:
            f.write("y = 2\n")
        run_sentinel(
            ["record", "--prompt", "sig list", "--file", "sig_list.py"],
            cwd=self.tmp,
        )
        result = run_sentinel(["list"], cwd=self.tmp)
        assert result.returncode == 0
        assert "unsigned" in result.stdout

    def test_list_shows_tsa_status(self):
        code_file = os.path.join(self.tmp, "tsa_list.py")
        with open(code_file, "w") as f:
            f.write("z = 3\n")
        run_sentinel(
            ["record", "--prompt", "tsa list", "--file", "tsa_list.py"],
            cwd=self.tmp,
        )
        # Inject TSA block
        records = list(Path(self.tmp, ".sentinel", "records").glob("*.jsonld"))
        manifest = json.loads(records[0].read_text())
        manifest["sentinel:trustedTimestamp"] = {
            "@type": "sentinel:RFC3161Timestamp",
            "sentinel:tsaUrl": "https://freetsa.org/tsr",
            "sentinel:tsrToken": base64.b64encode(b"token").decode("ascii"),
            "sentinel:tsaTime": "Apr 29 15:30:00 2026 GMT",
            "sentinel:status": "fetched",
            "sentinel:verifiedLocally": False,
            "sentinel:tsrSizeBytes": 5,
        }
        records[0].write_text(json.dumps(manifest, indent=2))

        result = run_sentinel(["list"], cwd=self.tmp)
        assert result.returncode == 0
        assert "fetched" in result.stdout

    def test_list_without_init_fails(self):
        bare = tempfile.mkdtemp()
        result = run_sentinel(["list"], cwd=bare)
        assert result.returncode != 0
        shutil.rmtree(bare)

    def test_list_handles_corrupt_manifest(self):
        """List should handle corrupt JSON files gracefully."""
        corrupt_file = os.path.join(self.tmp, ".sentinel", "records", "corrupt_test.jsonld")
        with open(corrupt_file, "w") as f:
            f.write("{{{invalid json")
        result = run_sentinel(["list"], cwd=self.tmp)
        assert result.returncode == 0
        assert "corrupt" in result.stdout.lower()


class TestHelp:
    def test_help_exits_zero(self):
        result = run_sentinel(["--help"], cwd="/tmp")
        assert result.returncode == 0

    def test_subcommand_help(self):
        for sub in ["init", "record", "verify", "sign", "publish", "list"]:
            result = run_sentinel([sub, "--help"], cwd="/tmp")
            assert result.returncode == 0

    def test_sign_help_mentions_manifest(self):
        result = run_sentinel(["sign", "--help"], cwd="/tmp")
        assert "manifest" in result.stdout.lower()

    def test_record_help_mentions_tsa(self):
        result = run_sentinel(["record", "--help"], cwd="/tmp")
        assert "tsa" in result.stdout.lower()

    def test_list_help(self):
        result = run_sentinel(["list", "--help"], cwd="/tmp")
        assert result.returncode == 0


class TestCanonicalPayload:
    """Tests to verify canonical payload excludes signature and TSA blocks."""

    def setup_method(self):
        self.tmp = tempfile.mkdtemp()
        run_sentinel(["init"], cwd=self.tmp)
        self.code_file = os.path.join(self.tmp, "canonical.py")
        with open(self.code_file, "w") as f:
            f.write("canonical = True\n")

    def teardown_method(self):
        shutil.rmtree(self.tmp)

    def test_canonical_payload_excludes_signature_and_tsa(self):
        """The canonical payload used for signing/TSA should not include sig or TSA blocks."""
        run_sentinel(
            ["record", "--prompt", "canonical test", "--file", "canonical.py"],
            cwd=self.tmp,
        )
        records = list(Path(self.tmp, ".sentinel", "records").glob("*.jsonld"))
        manifest = json.loads(records[0].read_text())

        # Add both blocks
        manifest["sentinel:trustedTimestamp"] = {"sentinel:status": "fetched"}
        manifest["sentinel:digitalSignature"] = {"sentinel:status": "signed"}

        # Import the function
        import importlib.util
        spec = importlib.util.spec_from_file_location("sentinel", SENTINEL_PY)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        canonical = mod._canonical_payload(manifest)
        canonical_dict = json.loads(canonical)

        assert "sentinel:digitalSignature" not in canonical_dict
        assert "sentinel:trustedTimestamp" not in canonical_dict
        assert "sentinel:recordId" in canonical_dict


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))


class TestPublish:
    """Tests for the `publish` command (IPFS integration)."""

    def setup_method(self):
        self.tmp = tempfile.mkdtemp()
        run_sentinel(["init"], cwd=self.tmp)
        self.code_file = os.path.join(self.tmp, "ipfs_code.py")
        with open(self.code_file, "w") as f:
            f.write("def decentralized(): return True\n")
        run_sentinel(
            ["record", "--prompt", "IPFS publish test", "--file", "ipfs_code.py"],
            cwd=self.tmp,
        )
        records = list(Path(self.tmp, ".sentinel", "records").glob("*.jsonld"))
        self.manifest_path = str(records[0])
        self.manifest_rel = os.path.relpath(self.manifest_path, self.tmp)

    def teardown_method(self):
        shutil.rmtree(self.tmp)

    def test_publish_help_mentions_manifest(self):
        result = run_sentinel(["publish", "--help"], cwd="/tmp")
        assert result.returncode == 0
        assert "manifest" in result.stdout.lower()

    def test_publish_nonexistent_manifest_exits_nonzero(self):
        """Publish should fail for a nonexistent manifest file."""
        # Create a fake ipfs binary so we get past the _require_ipfs check
        fake_ipfs = os.path.join(self.tmp, "ipfs")
        with open(fake_ipfs, "w") as f:
            f.write("#!/bin/bash\necho 'fake'\n")
        os.chmod(fake_ipfs, 0o755)

        env = os.environ.copy()
        env["PATH"] = self.tmp + ":" + env.get("PATH", "")
        result = subprocess.run(
            [sys.executable, SENTINEL_PY, "publish", "--manifest", "ghost.jsonld"],
            cwd=self.tmp,
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode != 0
        assert "not found" in result.stderr.lower()

    def test_publish_invalid_json_exits_nonzero(self):
        """Publish should fail for an invalid JSON manifest."""
        bad_manifest = os.path.join(self.tmp, "bad.jsonld")
        with open(bad_manifest, "w") as f:
            f.write("{{{not json")

        fake_ipfs = os.path.join(self.tmp, "ipfs")
        with open(fake_ipfs, "w") as f:
            f.write("#!/bin/bash\necho 'fake'\n")
        os.chmod(fake_ipfs, 0o755)

        env = os.environ.copy()
        env["PATH"] = self.tmp + ":" + env.get("PATH", "")
        result = subprocess.run(
            [sys.executable, SENTINEL_PY, "publish", "--manifest", bad_manifest],
            cwd=self.tmp,
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode != 0
        assert "invalid json" in result.stderr.lower()

    def test_publish_no_ipfs_shows_helpful_error(self):
        """When ipfs is not installed, publish should show install instructions."""
        # Ensure no ipfs is in PATH by using a clean PATH
        env = os.environ.copy()
        env["PATH"] = "/usr/bin:/bin"
        result = subprocess.run(
            [sys.executable, SENTINEL_PY, "publish", "--manifest", self.manifest_path],
            cwd=self.tmp,
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode != 0
        assert "ipfs" in result.stderr.lower()
        assert "kubo" in result.stderr.lower() or "pinata" in result.stderr.lower()

    def test_publish_with_mock_ipfs_success(self):
        """Simulate a successful IPFS publish using a mock ipfs binary."""
        fake_cid = "QmTestCID1234567890abcdefghijklmnop"
        fake_ipfs = os.path.join(self.tmp, "ipfs")
        with open(fake_ipfs, "w") as f:
            f.write(f"#!/bin/bash\necho '{fake_cid}'\n")
        os.chmod(fake_ipfs, 0o755)

        env = os.environ.copy()
        env["PATH"] = self.tmp + ":" + env.get("PATH", "")
        result = subprocess.run(
            [sys.executable, SENTINEL_PY, "publish", "--manifest", self.manifest_path],
            cwd=self.tmp,
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode == 0
        assert "PUBLISHED" in result.stdout
        assert fake_cid in result.stdout
        assert "ipfs.io" in result.stdout

    def test_publish_updates_manifest_with_ipfs_record(self):
        """After publish, the manifest should contain sentinel:ipfsRecord."""
        fake_cid = "QmUpdatedCID9876543210"
        fake_ipfs = os.path.join(self.tmp, "ipfs")
        with open(fake_ipfs, "w") as f:
            f.write(f"#!/bin/bash\necho '{fake_cid}'\n")
        os.chmod(fake_ipfs, 0o755)

        env = os.environ.copy()
        env["PATH"] = self.tmp + ":" + env.get("PATH", "")
        subprocess.run(
            [sys.executable, SENTINEL_PY, "publish", "--manifest", self.manifest_path],
            cwd=self.tmp,
            capture_output=True,
            text=True,
            env=env,
        )

        manifest = json.loads(Path(self.manifest_path).read_text())
        ipfs_block = manifest.get("sentinel:ipfsRecord")
        assert ipfs_block is not None
        assert ipfs_block["sentinel:ipfsCid"] == fake_cid
        assert ipfs_block["sentinel:status"] == "published"
        assert f"https://ipfs.io/ipfs/{fake_cid}" == ipfs_block["sentinel:gatewayUrl"]
        assert "sentinel:publishedAt" in ipfs_block

    def test_publish_preserves_existing_manifest_fields(self):
        """Publish should not alter existing fields like hash, prompt, or signature."""
        original = json.loads(Path(self.manifest_path).read_text())
        original_hash = original["sentinel:artifactRecord"]["sentinel:fileHash"]
        original_prompt = original["sentinel:humanIntent"]["sentinel:promptText"]

        fake_ipfs = os.path.join(self.tmp, "ipfs")
        with open(fake_ipfs, "w") as f:
            f.write("#!/bin/bash\necho 'QmPreserveTest'\n")
        os.chmod(fake_ipfs, 0o755)

        env = os.environ.copy()
        env["PATH"] = self.tmp + ":" + env.get("PATH", "")
        subprocess.run(
            [sys.executable, SENTINEL_PY, "publish", "--manifest", self.manifest_path],
            cwd=self.tmp,
            capture_output=True,
            text=True,
            env=env,
        )

        updated = json.loads(Path(self.manifest_path).read_text())
        assert updated["sentinel:artifactRecord"]["sentinel:fileHash"] == original_hash
        assert updated["sentinel:humanIntent"]["sentinel:promptText"] == original_prompt

    def test_publish_ipfs_failure_exits_nonzero(self):
        """If ipfs add fails, publish should exit with nonzero."""
        fake_ipfs = os.path.join(self.tmp, "ipfs")
        with open(fake_ipfs, "w") as f:
            f.write("#!/bin/bash\necho 'connection refused' >&2\nexit 1\n")
        os.chmod(fake_ipfs, 0o755)

        env = os.environ.copy()
        env["PATH"] = self.tmp + ":" + env.get("PATH", "")
        result = subprocess.run(
            [sys.executable, SENTINEL_PY, "publish", "--manifest", self.manifest_path],
            cwd=self.tmp,
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode != 0

    def test_publish_empty_cid_exits_nonzero(self):
        """If ipfs returns empty output, publish should fail gracefully."""
        fake_ipfs = os.path.join(self.tmp, "ipfs")
        with open(fake_ipfs, "w") as f:
            f.write("#!/bin/bash\necho ''\n")
        os.chmod(fake_ipfs, 0o755)

        env = os.environ.copy()
        env["PATH"] = self.tmp + ":" + env.get("PATH", "")
        result = subprocess.run(
            [sys.executable, SENTINEL_PY, "publish", "--manifest", self.manifest_path],
            cwd=self.tmp,
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode != 0


class TestListWithIPFS:
    """Tests for list command showing IPFS status."""

    def setup_method(self):
        self.tmp = tempfile.mkdtemp()
        run_sentinel(["init"], cwd=self.tmp)

    def teardown_method(self):
        shutil.rmtree(self.tmp)

    def test_list_shows_ipfs_none_by_default(self):
        code_file = os.path.join(self.tmp, "noipfs.py")
        with open(code_file, "w") as f:
            f.write("x = 1\n")
        run_sentinel(
            ["record", "--prompt", "no ipfs", "--file", "noipfs.py"],
            cwd=self.tmp,
        )
        result = run_sentinel(["list"], cwd=self.tmp)
        assert result.returncode == 0
        assert "IPFS" in result.stdout  # header
        assert "none" in result.stdout

    def test_list_shows_ipfs_published_status(self):
        code_file = os.path.join(self.tmp, "published.py")
        with open(code_file, "w") as f:
            f.write("x = 2\n")
        run_sentinel(
            ["record", "--prompt", "ipfs list", "--file", "published.py"],
            cwd=self.tmp,
        )
        records = list(Path(self.tmp, ".sentinel", "records").glob("*.jsonld"))
        manifest = json.loads(records[0].read_text())
        manifest["sentinel:ipfsRecord"] = {
            "@type": "sentinel:IPFSPublication",
            "sentinel:ipfsCid": "QmListTest123",
            "sentinel:gatewayUrl": "https://ipfs.io/ipfs/QmListTest123",
            "sentinel:publishedAt": "2026-04-29T16:45:00+00:00",
            "sentinel:status": "published",
        }
        records[0].write_text(json.dumps(manifest, indent=2))

        result = run_sentinel(["list"], cwd=self.tmp)
        assert result.returncode == 0
        assert "published" in result.stdout
