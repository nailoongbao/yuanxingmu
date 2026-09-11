"""Build a self-contained installer from reviewed source; no network or installation."""
from datetime import datetime, timezone
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
INPUTS = {"yxm_setup/" + name: "install/yxm_setup/" + name for name in (
    "__init__.py", "setup.py", "launcher.py", "pins.json", "openclaw-package.json", "openclaw-package-lock.json")}
INPUTS.update({name: name for name in ("LICENSE", "NOTICE.md", "LICENSES/Invariant-Apache-2.0.txt")})
ENTRY = b"from yxm_setup.setup import main\nraise SystemExit(main())\n"


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT)


def build(output, *, dev=False):
    head = git("rev-parse", "HEAD").decode().strip()
    if not dev and (git("diff", "--name-only").strip() or git("diff", "--cached", "--name-only").strip()):
        raise RuntimeError("Commit reviewed changes before a publishable build")
    data = {name: (ROOT / source).read_bytes() if dev else git("show", head + ":" + source) for name, source in INPUTS.items()}
    epoch = time.time() if dev else int(git("show", "-s", "--format=%ct", head))
    pins = json.loads(data["yxm_setup/pins.json"])
    metadata = {"schema_version": 1, "installer_version": pins["installer_version"], "runtime_version": pins["runtime_version"],
                "source_commit": None if dev else head, "publishable": not dev,
                "files": {name: {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()} for name, value in data.items()}}
    data["__main__.py"] = ENTRY
    data["bundle-manifest.json"] = (json.dumps(metadata, indent=2) + "\n").encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() or output.is_symlink():
        raise FileExistsError("Choose a new output filename; existing installer builds are preserved")
    stamp = datetime.fromtimestamp(epoch, timezone.utc).timetuple()[:6]
    with output.open("xb") as stream:
        stream.write(b"#!/usr/bin/python3\n")
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, content in sorted(data.items()):
                item = zipfile.ZipInfo(name, stamp)
                item.external_attr = 0o100644 << 16
                item.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(item, content)
    output.chmod(0o755)
    with zipfile.ZipFile(output) as archive:
        assert set(archive.namelist()) == set(data)
        assert all(archive.read(name) == content for name, content in data.items())
    result = {"file": str(output), "bytes": output.stat().st_size,
              "sha256": hashlib.sha256(output.read_bytes()).hexdigest(), **metadata}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--dev", action="store_true", help="Build uncommitted source for local validation; not publishable")
    args = parser.parse_args()
    build(args.output, dev=args.dev)
