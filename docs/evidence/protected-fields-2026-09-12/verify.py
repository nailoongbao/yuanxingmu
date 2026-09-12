"""Offline artifact integrity only; no model requests or browser actions."""
import hashlib
import json
from pathlib import Path
root = Path(__file__).resolve().parent
manifest = json.loads((root / "SHA256SUMS.json").read_bytes())
for name, expected in manifest["files"].items():
    raw = (root / name).read_bytes()
    assert len(raw) == expected["bytes"] and hashlib.sha256(raw).hexdigest() == expected["sha256"], name
for mode, skipped in (("linux", 202), ("windows", 647)):
    result = json.loads((root / (mode + "-tests.json")).read_bytes())
    assert result["passed"] and result["exit_code"] == 0 and result["source_unchanged"]
    assert result["test_count"] == 984 and result["skipped"] == skipped
    assert result["log_sha256"] == hashlib.sha256((root / (mode + "-unittest.log")).read_bytes()).hexdigest()
ci = json.loads((root / "ci-verified.json").read_bytes())
assert ci["source_commit"] == manifest["source_commit"]
assert all(j["conclusion"] == "success" for r in ci["runs"] for j in r["jobs"])
print(json.dumps({"verified": True, "files": len(manifest["files"]), "model_requests": 0}))
