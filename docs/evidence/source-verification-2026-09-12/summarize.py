"""Assemble evidence without rerunning tests or changing product files."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import zipfile


HERE = Path(__file__).resolve().parent


def read(name):
    return json.loads((HERE / name).read_text(encoding="utf-8"))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(name, value):
    (HERE / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


linux, windows = read("linux-wsl-unittest.json"), read("windows-unittest.json")
first, final = read("wheel-verification.json"), read("final/wheel-verification.json")
tested = read("linux-wsl-source-before.json")
packaged = read("final/wheel-source-before.json")
installed = read("final/wheel-installed.json")
assert linux["successful"] and windows["successful"] and final["successful"]
assert tested == read("windows-source-before.json")
assert not linux["source_changes_during_run"] and not windows["source_changes_during_run"]
assert not final["source_changes_during_build"]
differences = sorted(name for name in tested.keys() | packaged.keys() if tested.get(name) != packaged.get(name))
assert differences == ["yuanxingmu/integrations/hermes/VALIDATION.zh-CN.md"], differences

wheel = HERE / "final" / final["wheel"]
code = []
with zipfile.ZipFile(wheel) as archive:
    for name, expected in packaged.items():
        package, _, relative = name.partition("/")
        if package not in {"defensecheck", "yuanxingmu"} or not name.endswith(".py"):
            continue
        actual = hashlib.sha256(archive.read(name)).hexdigest()
        destination = Path(installed["imports"][package]).parent / relative
        assert actual == expected["sha256"] == sha(destination), name
        code.append({"path": name, "source_sha256": expected["sha256"], "wheel_sha256": actual,
                     "installed_sha256": sha(destination), "installed_path": str(destination)})
save("final/python-code-hashes.json", code)

groups = {}
for asset in installed["assets"]:
    path = asset["path"]
    group = "workbench" if "/dashboard/web/" in path else "hermes" if "/hermes/" in path else "mastra" if "/mastra/" in path else "openclaw"
    groups.setdefault(group, []).append(path)
assert "yuanxingmu/dashboard/web/alerts.js" in groups["workbench"]

summary = {
    "recorded_at": datetime.now(timezone.utc).isoformat(),
    "result": "passed",
    "identity": "Local uncommitted source snapshots, identified by per-file SHA256 manifests; this is not a release or an attack benchmark.",
    "scope": "Windows and Linux/WSL complete unittest discovery, fresh pure-Python wheel build, fresh isolated installation, external-directory CLI and packaged-file verification.",
    "not_performed": ["model inference", "real external delivery", "Hermes/npm full installation", "additional SDK end-to-end suites", "GPU compilation", "release publication"],
    "suites": {name: {key: value[key] for key in ("tests_run", "passed", "skipped", "failures", "errors", "expected_failures", "unexpected_successes", "elapsed_seconds", "python", "source_file_count", "source_changes_during_run", "log", "log_sha256")}
               for name, value in (("linux-wsl", linux), ("windows", windows))},
    "skip_details": {"linux-wsl": "linux-wsl-unittest.json", "windows": "windows-unittest.json"},
    "suite_source_maps_match_across_platforms": True,
    "test_to_final_package_source_differences": differences,
    "difference_reason": "Hermes validation documentation changed during the first packaging attempt; executable source was unchanged, so tests were not repeated for that documentation update.",
    "package": {"version": final["package_version"], "wheel": "final/" + final["wheel"],
                "sha256": final["wheel_sha256"], "bytes": final["wheel_bytes"],
                "assets_checked": final["assets_checked"], "asset_groups": groups,
                "python_source_files_checked_in_wheel_and_install": len(code),
                "cli_checks_passed": len(final["cli_checks"]), "javascript_syntax_checks_passed": final["javascript_syntax_checks"],
                "source_changes_during_final_build": final["source_changes_during_build"],
                "evidence": "final/wheel-verification.json", "installed_evidence": "final/wheel-installed.json",
                "python_code_hashes": "final/python-code-hashes.json", "source_manifest": "final/wheel-source-before.json"},
    "attempts": [{"evidence": "wheel-verification.json", "accepted": False,
                  "reason": "Source snapshot changed during otherwise successful build/install/CLI/asset checks.",
                  "changed_files": first["source_changes_during_build"]},
                 {"evidence": "final/wheel-verification.json", "accepted": True,
                  "reason": "Rebuilt latest documentation after source freeze; all verification passed with unchanged source hashes."}],
    "source_manifest_sha256": {name: sha(HERE / name) for name in ("linux-wsl-source-before.json", "windows-source-before.json", "final/wheel-source-before.json")},
    "notification_documentation": "Current 28/28 queue checks include deterministic clock changes and format migration; stop the old Workbench before migrating the same queue from format 1 to 2.",
}
save("source-verification.json", summary)

report = f"""# 本地源码与安装包最终验收

验收日期：2026-09-12。结果：通过。证据对应本地工作目录的源文件哈希；不是发布版本的安全评级，也不是攻击次数或模型识别率。

| 环境 | 发现用例 | 实际通过 | 跳过 | 失败／错误 |
|---|---:|---:|---:|---:|
| Linux / WSL，Python 3.12.3 | {linux['tests_run']} | {linux['passed']} | {linux['skipped']} | 0 / 0 |
| Windows，Python 3.12.9 | {windows['tests_run']} | {windows['passed']} | {windows['skipped']} | 0 / 0 |

两边都运行全部 `unittest` 发现用例；没有跳过失败用例重算结果。Linux 的跳过项是 159 项需独立 SDK 环境的检查及 19 项需可选真实 Hermes 安装的检查。Windows 还受 Linux 文件系统/进程接口限制，并有 1 项创建符号链接权限不足。逐条用例、原因及原始输出见 [Linux 结果](linux-wsl-unittest.json)、[Windows 结果](windows-unittest.json)、[Linux 日志](linux-wsl-unittest.log)和[Windows 日志](windows-unittest.log)。

两边测试前后的 {linux['source_file_count']} 份源文件哈希均未变化，跨平台的源文件映射相同。随后仅随包的 Hermes 验证说明更新；首轮打包因此标记为 `source changed` 并保留[原始记录](wheel-verification.json)。冻结文件后已重建最新内容；这项文档更新没有触发与它无关的测试重跑。

最终 wheel 为 **{final['package_version']}**。从新的源码副本构建，在新的隔离环境安装，从仓库外验证 `defensecheck`、`yuanxingmu` 及工作台、Hermes 初始化帮助，共 4 项命令检查。{len(code)} 份 Python 源文件在源码、wheel、已安装目录中的 SHA256 全部相同；{final['assets_checked']} 个随包文件全部存在、非空且与源码逐字节一致，包括 Hermes 插件 PY/YAML、Mastra MJS/JSON、OpenClaw 插件及工作台全部 9 个文件（含 `alerts.js`）。17 个已安装 JS/MJS 文件另通过语法检查。

- [最终安装包](final/{final['wheel']})，SHA256：`{final['wheel_sha256']}`。
- [最终打包记录](final/wheel-verification.json)、[安装位置和文件哈希](final/wheel-installed.json)、[Python 文件哈希](final/python-code-hashes.json)、[构建与命令日志](final/wheel-build-install.log)。
- [汇总 JSON](source-verification.json)、[最终源码清单](final/wheel-source-before.json)、[复验脚本](verify_source.py)。

此次未调用模型、未向真实第三方发送消息、未全量安装 Hermes/npm，未增加运行独立 SDK 全套或进行 GPU 编译。测试中的网络端点与模型响应为本地测试对象。此前真实 Agent/模型的证据应单独阅读，不能由本报告替代。

后台提醒文档已更新为当前 **28/28**。使用原提醒队列升级时，先停止旧工作台，再启动新版完成格式 1 → 2 的迁移；不能让新旧版本同时写同一队列。
"""
(HERE / "REPORT.zh-CN.md").write_text(report, encoding="utf-8")
print(json.dumps({"result": "passed", "source_files": len(packaged), "python_files": len(code),
                  "assets": {name: len(paths) for name, paths in groups.items()}, "wheel_sha256": final["wheel_sha256"]}))
