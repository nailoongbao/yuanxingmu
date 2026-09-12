"""Fixed official Hermes source, independent Python environment, native UI builds."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import tomllib
import zipfile

from .launcher import LauncherError, hermes_runtime_files


def extract_tree(root: Path, archive: Path, location: str, prefix: str, *, max_files=30000, max_bytes=600 * 1024 ** 2):
    from . import setup

    destination = setup.below(root, location)
    destination.mkdir(mode=0o700)
    with tarfile.open(archive, "r:gz") as source:
        entries = source.getmembers()
        if len(entries) > max_files or sum(item.size for item in entries) > max_bytes:
            raise setup.InstallError("Hermes 源码解压大小异常。")
        names = set()
        # Validate the entire list before writing any member. Official source
        # has no links; reject links, devices, aliases and duplicate members.
        for item in entries:
            path = setup.member(item.name.rstrip("/"))
            canonical = path.as_posix()
            if (path.parts[0] != prefix or canonical in names
                    or not (item.isfile() or item.isdir())
                    or len(path.parts) == 1 and not item.isdir()):
                raise setup.InstallError("Hermes 源码包含不支持的路径或文件类型。")
            names.add(canonical)
        for item in entries:
            parts = setup.member(item.name.rstrip("/")).parts[1:]
            if not parts:
                continue
            target = setup.below(destination, "/".join(parts))
            if item.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
            else:
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with source.extractfile(item) as stream, target.open("xb") as output:
                    while data := stream.read(1024 * 1024):
                        output.write(data)
                target.chmod(0o700 if item.mode & 0o111 else 0o600)
    return destination


def extract_source(root: Path, archive: Path, spec: dict):
    from . import setup

    destination = extract_tree(root, archive, "hermes/source", "hermes-agent-" + spec["commit"])
    project = tomllib.loads((destination / "pyproject.toml").read_text(encoding="utf-8"))
    version = re.search(r'^__version__\s*=\s*[\'"]([^\'"]+)',
                        (destination / "hermes_cli/__init__.py").read_text(encoding="utf-8"), re.M)
    if (project["project"]["name"] != "hermes-agent" or project["project"]["version"] != spec["version"]
            or version is None or version.group(1) != spec["version"]):
        raise setup.InstallError("Hermes 源码版本与固定记录不符。")
    return destination


def extract_uv(root: Path, archive: Path, spec: dict):
    from . import setup

    target = setup.below(root, "hermes/bootstrap")
    target.mkdir(mode=0o700)
    name = "uv-" + spec["version"] + ".data/scripts/uv"
    with zipfile.ZipFile(archive) as wheel:
        entries = [item for item in wheel.infolist() if item.filename == name]
        if (len(entries) != 1 or entries[0].file_size > 100 * 1024 ** 2
                or stat.S_ISLNK(entries[0].external_attr >> 16)):
            raise setup.InstallError("固定的 uv 安装包内容不符。")
        setup.atomic(target / "uv", wheel.read(entries[0]), 0o700)
    return target / "uv"


def environment(root: Path):
    from . import setup

    for name in ("build-home", "cache", "tmp"):
        target = setup.below(root, "hermes/" + name)
        target.mkdir(mode=0o700, exist_ok=True)
        setup.private(target, directory=True)
    config = setup.below(root, "hermes/npm-user.conf")
    global_config = setup.below(root, "hermes/npm-global.conf")
    setup.atomic(config, b"")
    setup.atomic(global_config, b"")
    env = {
        "HOME": str(root / "hermes/build-home"),
        "PATH": str(root / "tools/node-v24.16.0-linux-x64/bin") + ":/usr/bin:/bin",
        "LANG": "C.UTF-8", "TMPDIR": str(root / "hermes/tmp"),
        "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
        "HERMES_HOME": str(root / "hermes/build-home/hermes"),
        "UV_CONFIG_FILE": str(root / "hermes/uv.toml"), "UV_NO_PROGRESS": "1", "UV_PYTHON_DOWNLOADS": "never",
        "UV_LINK_MODE": "copy", "UV_CACHE_DIR": str(root / "hermes/cache/uv"),
        "UV_PROJECT_ENVIRONMENT": str(root / "hermes/env"),
        "npm_config_userconfig": str(config), "npm_config_globalconfig": str(global_config),
        "npm_config_cache": str(root / "hermes/cache/npm"),
        "npm_config_registry": "https://registry.npmjs.org/", "npm_config_update_notifier": "false",
    }
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"):
        if key in os.environ:
            env[key] = os.environ[key]
    return env


def secure_uv_lock(root: Path):
    """uv uses a world-writable lock inside the private venv; retain it privately."""
    from . import setup

    path = setup.below(root, "hermes/env/.lock")
    if path.exists():
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise setup.InstallError("Hermes Python 环境的锁文件类型或归属发生变化。")
        path.chmod(0o600)


def install(root: Path, pins: dict, cache=None):
    from . import setup

    if not (3, 12) <= sys.version_info < (3, 14):
        raise setup.InstallError("固定的 Hermes 环境需要系统 Python 3.12 或 3.13。")
    spec = pins["hermes"]
    # All downloads are verified before clearing our own incomplete component.
    source_archive = setup.fetch(root, spec, cache)
    uv_archive = setup.fetch(root, pins["uv"], cache)
    npm_archive = setup.fetch(root, pins["hermes_npm"], cache)
    setup.clear_partial(root, "hermes")
    setup.below(root, "hermes").mkdir(mode=0o700)
    source = extract_source(root, source_archive, spec)
    uv = extract_uv(root, uv_archive, pins["uv"])
    npm_root = extract_tree(root, npm_archive, "hermes/bootstrap/npm", "package", max_files=5000, max_bytes=40 * 1024 ** 2)
    if json.loads((npm_root / "package.json").read_text(encoding="utf-8")).get("version") != pins["hermes_npm"]["version"]:
        raise setup.InstallError("Hermes 专用 npm 版本与固定记录不符。")
    env = environment(root)
    constraints = setup.below(root, "hermes/build-constraints.txt")
    setup.atomic(constraints, b"setuptools==83.0.0\nwheel==0.48.0\npackaging==26.0\n")
    setup.atomic(root / "hermes/uv.toml", b'build-constraint-dependencies = ["setuptools==83.0.0", "wheel==0.48.0", "packaging==26.0"]\n')
    locked = {name: setup.record(source / name) for name in ("pyproject.toml", "uv.lock", "package.json", "package-lock.json")}
    # Copies avoid resolving away a venv interpreter on discovery, and allow
    # the launcher's ordinary-file checks to cover the executable itself.
    setup.command(root, "准备Hermes独立Python", ["/usr/bin/python3", "-I", "-B", "-m", "venv",
        "--without-pip", "--copies", str(root / "hermes/env")], env=env, timeout=60)
    setup.command(root, "安装Hermes固定Python依赖", [str(uv), "sync", "--frozen", "--no-default-groups",
        "--no-dev", "--extra", "web", "--no-managed-python", "--python", "/usr/bin/python3",
        "--project", str(source)], env=env, timeout=900)
    setup.command(root, "核对HermesPython依赖", [str(uv), "pip", "check", "--python", str(root / "hermes/env/bin/python")],
                  env=env, timeout=60)
    node = root / "tools/node-v24.16.0-linux-x64/bin/node"
    npm = npm_root / "bin/npm-cli.js"
    base = [str(node), str(npm), "--prefix", str(source)]
    setup.command(root, "安装Hermes网页与终端依赖", [*base, "ci", "--workspace", "web", "--workspace", "ui-tui",
        "--include-workspace-root=false", "--no-audit", "--no-fund"], env=env, timeout=900)
    for workspace, label in (("ui-tui", "终端"), ("web", "网页")):
        setup.command(root, "构建Hermes官方" + label, [*base, "run", "--workspace", workspace, "build"], env=env, timeout=600)
    if any(setup.record(source / name) != expected for name, expected in locked.items()):
        raise setup.InstallError("Hermes 构建改变了上游依赖记录，安装未完成。")
    # Import the actual installed packages, without calling a model or starting
    # a gateway. The native-page smoke test is a separate, explicit operation.
    code = ("import importlib.metadata as m,json,socket,sys;"
            "sys.addaudithook(lambda event,args: (_ for _ in ()).throw(RuntimeError('network forbidden during import check')) "
            "if event in {'socket.connect','socket.getaddrinfo','socket.sendto'} else None);"
            "import hermes_cli,hermes_cli.main,hermes_cli.web_server,agent.terminal_env_provider,tools.environments.base;"
            "assert m.version('hermes-agent')==sys.argv[1]==hermes_cli.__version__;"
            "print(json.dumps({'hermes':m.version('hermes-agent'),'python':sys.version.split()[0],'model_calls':0}))")
    setup.command(root, "检查Hermes原生模块", [str(root / "hermes/env/bin/python"), "-I", "-B", "-c", code, spec["version"]],
                  env=env, timeout=60)
    secure_uv_lock(root)
    setup.atomic(root / "hermes/SOURCE.json", (json.dumps({
        "release": spec["release"], "version": spec["version"], "commit": spec["commit"],
        "archive_sha256": spec["sha256"], "archive_bytes": spec["bytes"], "dependency_locks": locked,
        "uv_version": pins["uv"]["version"], "npm_version": pins["hermes_npm"]["version"], "python": sys.version.split()[0],
        "npm_workspaces": ["web", "ui-tui"], "build_constraints": constraints.read_text(encoding="utf-8"),
    }, indent=2) + "\n").encode())
    try:
        names = hermes_runtime_files(root)
    except (LauncherError, OSError) as exc:
        raise setup.InstallError("Hermes 运行文件不完整或包含意外链接。") from exc
    names |= {"hermes/SOURCE.json", "hermes/build-constraints.txt", "hermes/uv.toml"}
    return {name: setup.record(root / name) for name in sorted(names)}
