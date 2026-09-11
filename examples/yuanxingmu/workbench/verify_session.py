"""Read-only audit of the recorded workbench / OpenClaw / Qwen user workflow.

Default mode diagnoses without writing. --final --output NEW_DIRECTORY also
rehashes the local model and freezes a small, credential-checked evidence set.
This verifies one recorded workflow, not a threat benchmark or defense rate.
The databases, catalog, credentials and full configuration are never copied.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import difflib
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import sys


PROFILE_ID = "7e298dee755443d78b7473de59a43572"
EXECUTION_PROFILE_ID = "1796bbe03a234085a434fcff460baf28"
TASK_ID = "task_af286dac2ded473cb424c37163adf272"
FAMILY_ID = "f85dacd5a3b248839f8e0dd0fb2359c9"
SESSION_ID = "1712db83-c596-4d49-b91b-1018311af415"
QUOTE_SHA256 = "878342d30c8f5adcba7f8c8b88d0b95826a9955c5eb0d36331143658c1640635"
OBSERVATIONS = ("stopped-before-reopen", "reopened", "revoked-running", "final-stopped")
VERSION_PAIR = (
    "973918d2f9ccc14666bc0dbe04ce6e745693c4ae8912c9cbf8233adb539bc547",
    "713370512e556b4b346d34a3a864d96654b72498e152dd7d2246e56c4f21cc97",
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def encoded(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def jsonl(rows) -> bytes:
    return b"".join(encoded(row) + b"\n" for row in rows)


def read_json(path: Path):
    return json.loads(path.read_bytes())


def pick(value, keys):
    return {key: value[key] for key in keys if key in value}


def moment(value) -> float:
    if isinstance(value, (int, float)):
        return value / 1000 if value > 10 ** 11 else value
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


@contextmanager
def readonly(path: Path):
    db = sqlite3.connect(path.resolve(strict=True).as_uri() + "?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA query_only=ON")
    db.execute("BEGIN")
    try:
        yield db
    finally:
        db.close()


def text_content(message):
    content = message.get("content", "")
    if isinstance(content, str):
        return content
    return "\n".join(item.get("text", "") for item in content if item.get("type") == "text")


def reference(row):
    return {"session_id": row["session_id"], "seq": row["seq"], "event_id": row["event"].get("id")}


def lifecycle_projection(value):
    return pick(value, ("status", "task_id", "supervisor_pid", "supervisor_start",
                        "gateway_pid", "gateway_start", "cleanup_confirmed"))


def job_projection(row):
    profile = row.get("result", {}).get("profile", {})
    result = pick(row, ("id", "profile_id", "action", "status", "created_at", "finished_at"))
    public = pick(profile, ("id", "name", "created_at", "model_id", "status", "revoked", "pending"))
    public["documents"] = [pick(item, ("name", "filename", "bytes")) for item in profile.get("documents", [])]
    result["result"] = {"profile": public}
    return result


def process_observation(pid, started):
    result = {"pid": pid, "recorded_start_ticks": str(started), "state": None,
              "observed_start_ticks": None, "same_live_instance": None}
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        result.update(state=fields[0], observed_start_ticks=fields[19],
                      same_live_instance=fields[19] == str(started) and fields[0] != "Z")
    except (FileNotFoundError, ProcessLookupError):
        result["same_live_instance"] = False
    return result


def native_records(profile):
    path = profile / "openclaw-state/agents/main/agent/openclaw-agent.sqlite"
    with readonly(path) as db:
        sessions = [dict(row) for row in db.execute(
            "SELECT session_id,session_key,previous_session_id,reason,created_at,model_provider,model "
            "FROM session_windows ORDER BY created_at")]
        rows = list(db.execute("SELECT session_id,seq,event_json,created_at FROM transcript_events "
                               "ORDER BY created_at,seq"))
    messages = []
    for row in rows:
        event = json.loads(row["event_json"])
        if event.get("type") == "message":
            messages.append({**dict(row), "event_json_sha256": digest(row["event_json"].encode("utf-8")),
                             "event": event})
    return sessions, messages, len(rows)


def authority_records(profile):
    with readonly(profile / "broker-state/authority.sqlite3") as db:
        tasks = [dict(row) for row in db.execute(
            "SELECT t.id AS task_id,t.family_id,t.parent_id,t.revoked,f.revision "
            "FROM authority_tasks t JOIN authority_families f ON f.id=t.family_id ORDER BY t.id")]
        labels = [row[0] for row in db.execute(
            "SELECT label FROM authority_labels WHERE family_id=? ORDER BY label", (FAMILY_ID,))]
        resources = {row["resource_id"]: json.loads(row["labels"]) for row in db.execute(
            "SELECT resource_id,labels FROM authority_resources WHERE family_id=?", (FAMILY_ID,))}
        destinations = {row["destination_id"]: json.loads(row["labels"]) for row in db.execute(
            "SELECT destination_id,labels FROM authority_destinations WHERE family_id=?", (FAMILY_ID,))}
        grants = [row[0] for row in db.execute(
            "SELECT resource_id FROM authority_resource_grants WHERE task_id=? ORDER BY resource_id", (TASK_ID,))]
        destination_grants = [row[0] for row in db.execute(
            "SELECT destination_id FROM authority_destination_grants WHERE task_id=? ORDER BY destination_id", (TASK_ID,))]
        events = [dict(row) for row in db.execute(
            "SELECT event_id,task_id,action,allowed,reason,details,created_at FROM authority_events ORDER BY event_id")]
    for row in events:
        row["details"] = json.loads(row["details"])
    return {"tasks": tasks, "labels": labels, "resources": resources, "destinations": destinations,
            "resource_grants": grants, "destination_grants": destination_grants}, events


def source_inventory(profile, repo, manifest):
    entries = []
    for name, expected in sorted(manifest["files"].items()):
        if not (name.startswith("trusted-core/yuanxingmu/") or name.startswith("plugin/")):
            continue
        raw = (profile / name).read_bytes()
        relative = name.removeprefix("trusted-core/") if name.startswith("trusted-core/") else "yuanxingmu/integrations/openclaw/" + name
        current = (repo / relative).read_bytes()
        actual, current_hash = digest(raw), digest(current)
        entry = {"runtime_path": name, "checkout_path": relative, "recorded_sha256": expected,
                 "runtime_sha256": actual, "checkout_sha256": current_hash,
                 "runtime_matches_recorded_binding": actual == expected, "runtime_equals_checkout": actual == current_hash}
        if actual != current_hash:
            entry["diff"] = "".join(difflib.unified_diff(
                raw.decode("utf-8").splitlines(True), current.decode("utf-8").splitlines(True),
                fromfile="recorded-runtime/" + relative, tofile="current-checkout/" + relative))
            entry["only_version_constant_changed"] = relative == "yuanxingmu/__init__.py" \
                and (actual, current_hash) == VERSION_PAIR \
                and raw.replace(b'__version__ = "0.2.0a1"', b'__version__ = "0.4.0a1"') == current
        entries.append(entry)
    return entries


def model_provenance(manifest_path, process_path, profile_model, verify_bytes):
    source = read_json(manifest_path)
    record = read_json(process_path)
    download = source["download"]
    asset = next(item for item in download["assets"] if item["kind"] == "model")
    executable = Path(download["server_binary"])
    live = process_observation(record["pid"], record["start_ticks"])
    proc = Path("/proc") / str(record["pid"])
    live.update(command_matches=False, executable_matches=False)
    if live["same_live_instance"]:
        command = [item.decode("utf-8") for item in (proc / "cmdline").read_bytes().split(b"\0") if item]
        live["command_matches"] = command == record["command"]
        live["executable_matches"] = (proc / "exe").resolve(strict=True) == executable.resolve(strict=True)
    command = record["command"]
    def option(name):
        return command[command.index(name) + 1] if name in command else None
    parameters = {name: option(name) for name in ("--alias", "--host", "--port", "--ctx-size", "--parallel",
                                                 "--threads", "--n-gpu-layers", "--chat-template-kwargs", "--reasoning-budget")}
    parameters.update(offline="--offline" in command, jinja="--jinja" in command)
    return {
        "source_manifest_sha256": file_digest(manifest_path),
        "source_manifest_role": "Model download/runtime provenance only; its old PID is not the current-run process.",
        "current_run_process_record_sha256": file_digest(process_path),
        "model_repository": download["model_repository"], "model_revision": download["model_revision"],
        "model_alias": source["model_alias"], "model_asset": pick(asset, ("name", "url", "size", "sha256")),
        "model_file_size_matches": Path(asset["path"]).stat().st_size == asset["size"],
        "model_bytes_rehashed_and_match": file_digest(Path(asset["path"])) == asset["sha256"] if verify_bytes else None,
        "runtime_release": download["runtime_release"], "runtime_version": source["runtime_version_text"],
        "runtime_sha256": download["server_binary_sha256"],
        "runtime_bytes_rehashed_and_match": file_digest(executable) == download["server_binary_sha256"],
        "backend": source["server_backend"], "thinking_enabled": source["thinking_enabled"],
        "safe_command_parameters": parameters,
        "current_command_matches_source_command": command == source["server_command"],
        "current_command_model_matches_asset": option("--model") == asset["path"],
        "profile_matches_service": profile_model == {"url": source["base_url"], "id": source["model_alias"]},
        "live_process": live,
        "separate_installation_probe": "Not included in native transcript or tool-call counts.",
    }


def pair_tools(messages, broker, authority):
    calls, results = [], {}
    for row in messages:
        message = row["event"]["message"]
        if message.get("role") == "assistant" and isinstance(message.get("content"), list):
            for item in message["content"]:
                if item.get("type") == "toolCall":
                    calls.append({"tool_call_id": item["id"], "name": item["name"], "arguments": item.get("arguments", {}),
                                  "native_call": reference(row), "call_time": row["event"]["timestamp"],
                                  "run_id": message.get("__openclaw", {}).get("runId")})
        elif message.get("role") == "toolResult":
            results.setdefault((row["session_id"], message["toolCallId"]), []).append(row)
    for call in calls:
        candidates = results.get((call["native_call"]["session_id"], call["tool_call_id"]), [])
        call["native_result_count"] = len(candidates)
        if len(candidates) != 1:
            continue
        row = candidates[0]
        message = row["event"]["message"]
        details = message.get("details", {})
        call.update(native_result=reference(row), result=details, result_time=row["event"]["timestamp"],
                    result_tool_name_matches=message.get("toolName") == call["name"],
                    result_run_id_matches=message.get("__openclaw", {}).get("runId") == call["run_id"])
        event_id = details.get("event_id")
        matches = [(index, item) for index, item in enumerate(broker)
                   if item.get("task_id") == TASK_ID and item.get("operation") == "read"
                   and item.get("allowed") == details.get("allowed") and item.get("reason") == details.get("reason")
                   and (event_id is None or item.get("event_id") == event_id)
                   and abs(moment(item["time"]) - moment(call["result_time"])) < 2
                   and all(item.get(key) == details[key] for key in ("task_id", "resource_id", "resource_labels", "labels", "revision") if key in details)]
        call["broker_matches"] = [{"line": index + 1, "method": "event_id_and_time" if event_id is not None else "operation_reason_and_unique_two_second_window",
                                   "time_delta_seconds": round(moment(call["result_time"]) - moment(item["time"]), 6)} for index, item in matches]
        events = [item for item in authority if item["task_id"] == TASK_ID and item["action"] == "record_read"
                  and bool(item["allowed"]) == details.get("allowed") and item["reason"] == details.get("reason")
                  and (event_id is None or item["event_id"] == event_id)
                  and abs(moment(item["created_at"]) - moment(call["result_time"])) < 2
                  and all(details.get(key) == value for key, value in item["details"].items())]
        call["authority_matches"] = [{"event_id": item["event_id"],
                                      "method": "event_id_and_time" if event_id is not None else "operation_reason_and_unique_two_second_window",
                                      "time_delta_seconds": round(moment(call["result_time"]) - moment(item["created_at"]), 6)} for item in events]
    return calls, sum(len(rows) for rows in results.values())


def chinese_report(report):
    answer = report["task_result"]["answer"]["text"]
    return ("# 元星木工作台：这次实机操作核对\n\n"
            "这次通过浏览器自动化操作真实的元星木工作台，建立“整理春季活动预算”，打开真实 OpenClaw 聊天页面，"
            "让本地 Qwen3-4B 读取一份练习报价。模型读到场地 6000 元、物料 2800 元、摄影 1200 元，"
            "算出总计 **10,000 元**，并提醒确认供应商和报价。这不是用户招募测试。\n\n"
            "| 用户操作 | 本次实际结果 |\n| --- | --- |\n"
            "| 新建并打开 | 工作台记录创建和启动完成；原生聊天中确有模型发起的读取。 |\n"
            "| 整理预算 | 读取结果与原始资料逐字相同；三个费用和总计正确。 |\n"
            "| 停止后重新打开 | 使用同一任务和权限记录，原资料摘要与 private 限制保留。 |\n"
            "| 收回权限后再读取 | 模型重新调用读取工具，权限服务实际返回 task_revoked；并非只凭模型口头拒绝。 |\n"
            "| 最后停止 | 工作台与生命周期记录均为已停止，清理完成；审计时两次启动所记录的原进程实例均已退出。 |\n\n"
            "共保留 **1 个原生会话、8 条原生消息、2 次读取调用及其结果**。重开沿用原会话，没有新增聊天会话。"
            "本轮没有发送或命令执行调用，没有外部攻击内容，也没有测试公开外发。它验证普通用户操作流程，"
            "不能用来计算攻击成功率、通用防御率或比较产品排名。\n\n"
            "## 模型的原始回答\n\n" + answer + "\n\n"
            "## 录像与最终代码的差异\n\n"
            "录制实例的 24 个执行核心和插件文件均与该实例创建时记录的摘要相符。与审计时仓库比较，"
            "23 个完全相同；唯一差异是版本常量由 0.2.0a1 改为 0.4.0a1，逐行记录见 "
            "[source-differences.patch](source-differences.patch)。没有把整份运行目录复制进证据包。\n\n"
            "工作台管理界面另有变化：录制期间修过表单校验和页面更新；录制后又修复了状态查询并发时的短暂误报，"
            "为每个实例串行执行管理操作，并在操作未结束时保留最后一次真实观测状态。"
            "这些界面与管理服务文件不属于上述 24 个冻结文件，录像不能代表最终发布的完整界面代码。"
            "本报告用原生消息、权限事件、操作记录和进程身份相互核对实际结果。\n\n"
            "## 需要理解的边界\n\n"
            "- 收回权限阻止后续受控读取；它不会抹去聊天中已经读到的内容，也不会立即停止所有计算。本次随后另行点击停止。\n"
            "- 模型提到“重新申请权限”只是自然语言建议。本版已撤销的任务不能恢复，需要新建任务。\n"
            "- 本次采用本地 CPU 推理，不涉及云模型或 GPU。模型来源为 Qwen/Qwen3-4B-GGUF，版本 "
            "bc640142c66e1fdd12af0bd68f40445458f3869b，文件 Qwen3-4B-Q4_K_M.gguf；最终导出重新核对了模型和推理程序摘要。\n"
            "- 当前模型进程由本轮 model.json 记录核对启动时间、命令和程序位置；旧安装记录只用于说明模型下载来源，旧 PID 不当作本轮进程。\n"
            "- 撤销后的工具结果没有事件 ID。这里按读取操作、拒绝原因和唯一的两秒时间窗口关联，未虚构共同事件 ID。\n\n"
            "[report.json](report.json) 给出逐项检查与原生消息序号；[native-messages.jsonl](native-messages.jsonl) "
            "保留原始消息事件文本及摘要；[quote.txt](quote.txt) 是完整练习资料。"
            "[artifact-manifest.json](artifact-manifest.json) 列出其余证据文件的字节数与 SHA256。"
            "未导出数据库、完整配置、原 catalog、模型密钥或网关令牌；导出前后均扫描了实际凭证值。\n").encode("utf-8")


def assemble(args):
    profile = args.profile.resolve(strict=True)
    repo = args.repo.resolve(strict=True)
    manifest = read_json(profile / "profile.json")
    if profile.name != PROFILE_ID or manifest["task_id"] != TASK_ID or manifest["family_id"] != FAMILY_ID:
        raise RuntimeError("Profile/task/family does not match this recorded workflow")
    catalog = read_json(profile.parent.parent / "catalog.json")
    catalog_profile = catalog["profiles"][PROFILE_ID]
    jobs = sorted((job_projection(row) for row in catalog["jobs"].values()), key=lambda row: (row["created_at"], row["id"]))
    observations = []
    for label in OBSERVATIONS:
        path = args.observations / (label + ".json")
        raw = path.read_bytes()
        value = json.loads(raw)
        if value.get("label") != label:
            raise RuntimeError("Observation label does not match its filename")
        row = pick(value, ("label", "time", "profile_id", "task_id", "family_id", "status", "document_sha256"))
        row["source_file_sha256"] = digest(raw)
        row["task"] = pick(value["task"], ("task_id", "active", "revoked", "labels", "revision"))
        row["lifecycle"] = lifecycle_projection(value["lifecycle"])
        row["source_sha256"] = dict(value["source_sha256"])
        row["jobs"] = sorted((job_projection(item) for item in value["jobs"]), key=lambda item: (item["created_at"], item["id"]))
        observations.append(row)
    quote = (profile / "documents/quote.txt").read_bytes()
    broker_raw = (profile / "broker-state/broker-events.jsonl").read_bytes()
    broker = [json.loads(line) for line in broker_raw.splitlines() if line.strip()]
    broker_public = [pick(row, ("time", "task_id", "operation", "allowed", "reason", "resource_id", "resource_labels", "labels", "revision", "event_id")) for row in broker]
    adapter_raw = (profile / "gateway-audit/adapter-events.jsonl").read_bytes()
    adapter = [json.loads(line) for line in adapter_raw.splitlines() if line.strip()]
    adapter_public = [pick(row, ("time", "event", "runtimeId", "sessionKey", "scopeKey")) for row in adapter]
    sessions, messages, native_count = native_records(profile)
    authority, authority_events = authority_records(profile)
    calls, result_count = pair_tools(messages, broker, authority_events)
    sources = source_inventory(profile, repo, manifest)
    differences = [row for row in sources if not row["runtime_equals_checkout"]]
    model = model_provenance(args.model_manifest, args.model_process_record, manifest["model"], args.final)
    lifecycle = lifecycle_projection(read_json(profile / "lifecycle.json"))
    identities = sorted({(row["lifecycle"][name + "_pid"], str(row["lifecycle"][name + "_start"]))
                         for row in observations for name in ("supervisor", "gateway")})
    processes = [process_observation(pid, started) for pid, started in identities]
    rows_by_seq = {row["seq"]: row for row in messages}
    answer_row, denial_row = rows_by_seq.get(7), rows_by_seq.get(12)
    answer = text_content(answer_row["event"]["message"]) if answer_row else ""
    denial = text_content(denial_row["event"]["message"]) if denial_row else ""
    amounts = [int(value) for value in re.findall(r"^(?:场地|物料|摄影)：(\d+) 元$", quote.decode("utf-8"), re.MULTILINE)]
    providers = sorted({(row["event"]["message"].get("provider"), row["event"]["message"].get("model"))
                        for row in messages if row["event"]["message"].get("role") == "assistant"})
    source_map = {row["checkout_path"]: row["runtime_sha256"] for row in sources if row["runtime_path"].startswith("trusted-core/")}
    tasks = authority["tasks"]
    final_task = tasks[0] if len(tasks) == 1 else {}
    revoke = [row for row in authority_events if row["action"] == "revoke"]
    read_call = calls[0] if len(calls) == 2 else {}
    denied_call = calls[1] if len(calls) == 2 else {}
    start_jobs = [row for row in jobs if row["action"] == "start"]
    stop_jobs = [row for row in jobs if row["action"] == "stop"]
    stat = profile.stat()
    checks = {
        "one_catalog_profile_and_bound_execution_profile": list(catalog["profiles"]) == [PROFILE_ID]
            and manifest["profile_id"] == EXECUTION_PROFILE_ID and Path(manifest["profile"]).resolve() == profile
            and catalog_profile["identity"] == [stat.st_dev, stat.st_ino]
            and catalog_profile["manifest_sha256"] == file_digest(profile / "profile.json"),
        "quote_matches_recorded_binding": len(quote) == 161 and digest(quote) == QUOTE_SHA256
            and manifest["files"]["documents/quote.txt"] == QUOTE_SHA256
            and catalog_profile["documents"] == [{"bytes": 161, "filename": "quote.txt", "name": "quote"}],
        "initial_scope_is_private_quote_with_no_destinations": manifest["documents"] == ["quote"] and manifest["destinations"] == []
            and authority["resources"] == {"quote": ["private"]} and authority["destinations"] == {}
            and authority["resource_grants"] == ["quote"] and authority["destination_grants"] == []
            and len(authority_events) == 4
            and authority_events[0]["details"] == {"destinations": {}, "initial_labels": ["private"], "resources": {"quote": ["private"]}, "revision": 0},
        "one_original_session_and_eight_messages": len(sessions) == 1 and sessions[0]["session_id"] == SESSION_ID
            and sessions[0]["session_key"] == "agent:main:main" and native_count == 13 and len(messages) == 8
            and [row["seq"] for row in messages] == [1, 4, 5, 7, 8, 9, 10, 12],
        "native_model_identity_matches_configured_model": providers == [("yuanxingmu-model", "yuanxingmu-qwen3-4b")]
            and all(row["model_provider"] == "yuanxingmu-model" and row["model"] == "yuanxingmu-qwen3-4b" for row in sessions),
        "exactly_two_read_calls_with_native_broker_and_authority_results": len(calls) == 2 and result_count == 2 and len(broker) == 2
            and all(row["name"] == "yuanxingmu_read" and row["arguments"] == {"resource": "quote"}
                    and row.get("native_result_count") == 1 and row.get("result_tool_name_matches") and row.get("result_run_id_matches")
                    and len(row.get("broker_matches", [])) == 1 and len(row.get("authority_matches", [])) == 1 for row in calls),
        "authorized_read_returns_exact_quote": read_call.get("result", {}).get("allowed") is True
            and read_call.get("result", {}).get("event_id") == 2 and read_call.get("result", {}).get("content") == quote.decode("utf-8"),
        "answer_lists_correct_amounts_total_and_confirmation": amounts == [6000, 2800, 1200] and sum(amounts) == 10000
            and all(value in answer for value in ("6000", "2800", "1200", "10,000", "供应商", "确认"))
            and answer_row is not None and answer_row["event"]["message"].get("__openclaw", {}).get("runId") == read_call.get("run_id"),
        "six_workbench_jobs_succeeded_in_expected_order": len(jobs) == 6
            and [row["action"] for row in jobs] == ["create", "start", "stop", "start", "revoke", "stop"]
            and all(row["profile_id"] == PROFILE_ID and row["status"] == "succeeded" for row in jobs)
            and [(row["result"]["profile"].get("status"), row["result"]["profile"].get("revoked")) for row in jobs]
                == [("stopped", False), ("ready", False), ("stopped", False), ("ready", False), ("ready", True), ("stopped", True)],
        "observation_jobs_equal_catalog_projections": all(row["jobs"] == jobs[:count] for row, count in zip(observations, (3, 4, 5, 6))),
        "same_task_family_quote_and_core_sources_across_reopen": all(row["profile_id"] == PROFILE_ID and row["task_id"] == TASK_ID
            and row["family_id"] == FAMILY_ID and row["task"]["task_id"] == TASK_ID and row["task"]["labels"] == ["private"]
            and row["lifecycle"]["task_id"] == TASK_ID and row["document_sha256"] == QUOTE_SHA256 and row["source_sha256"] == source_map
            for row in observations) and len(source_map) == 13,
        "observations_show_stop_reopen_revoke_stop": [(row["status"], row["task"]["active"], row["task"]["revoked"]) for row in observations]
            == [("stopped", True, False), ("ready", True, False), ("ready", False, True), ("stopped", False, True)]
            and all(row["lifecycle"]["status"] == row["status"] for row in observations)
            and observations[0]["lifecycle"].get("cleanup_confirmed") is True
            and observations[3]["lifecycle"].get("cleanup_confirmed") is True,
        "reopen_keeps_revision_then_revoke_advances_it": observations[1]["task"].get("revision") == 1
            and observations[2]["task"].get("revision") == 2,
        "authority_finally_revoked_at_revision_two": final_task == {"task_id": TASK_ID, "family_id": FAMILY_ID, "parent_id": None, "revoked": 1, "revision": 2}
            and authority["labels"] == ["private"] and [row["action"] for row in authority_events] == ["create_root", "record_read", "revoke", "record_read"]
            and all(row["task_id"] == TASK_ID for row in authority_events),
        "revoke_precedes_new_user_request_and_denied_read": len(revoke) == 1 and revoke[0]["reason"] == "subtree_revoked"
            and revoke[0]["allowed"] == 1 and denied_call.get("result") == {"allowed": False, "reason": "task_revoked"}
            and 8 in rows_by_seq and moment(revoke[0]["created_at"]) < moment(rows_by_seq[8]["event"]["timestamp"])
                < moment(denied_call["call_time"]) < moment(denied_call["result_time"])
            and "不要沿用之前读到的内容" in text_content(rows_by_seq[8]["event"]["message"])
            and "无法读取" in denial,
        "adapter_reuses_same_runtime_and_session_on_both_starts": len(adapter) == 2
            and all(row.get("event") == "native_backend_created" and row.get("sessionKey") == "agent:main:main" for row in adapter)
            and len({row.get("runtimeId") for row in adapter}) == 1 and len({row.get("scopeKey") for row in adapter}) == 1
            and len(start_jobs) == 2 and len(stop_jobs) == 2
            and all(moment(start["finished_at"]) < moment(row["time"]) < moment(stop["created_at"])
                    for start, row, stop in zip(start_jobs, adapter, stop_jobs)),
        "final_lifecycle_matches_stopped_observation": lifecycle == observations[-1]["lifecycle"]
            and lifecycle.get("cleanup_confirmed") is True and lifecycle.get("status") == "stopped",
        "all_four_recorded_process_instances_exited": len(processes) == 4 and all(row["same_live_instance"] is False for row in processes),
        "all_24_runtime_sources_match_frozen_binding": len(sources) == 24 and all(row["runtime_matches_recorded_binding"] for row in sources),
        "only_checkout_difference_is_version_constant": len(differences) == 1 and differences[0].get("only_version_constant_changed") is True,
        "model_provenance_and_current_process_match": model["profile_matches_service"] and model["model_file_size_matches"]
            and model["runtime_bytes_rehashed_and_match"] and model["current_command_matches_source_command"]
            and model["current_command_model_matches_asset"] and model["live_process"]["same_live_instance"] is True
            and model["live_process"]["command_matches"] and model["live_process"]["executable_matches"],
    }
    if args.final:
        checks["model_bytes_rehashed_and_match"] = model["model_bytes_rehashed_and_match"] is True
    report = {
        "schema_version": 1, "status": "verified" if all(checks.values()) else "incomplete",
        "audit_time_utc": datetime.now(timezone.utc).isoformat(), "final_export": args.final,
        "scope": "One ordinary-user workflow through the real workbench / native OpenClaw / local Qwen, operated by browser automation. This is not a recruited-user study. No threat evaluation, defense rate, sending trial, or product ranking.",
        "identities": {"workbench_profile_id": PROFILE_ID, "execution_profile_id": manifest["profile_id"], "task_id": TASK_ID, "family_id": FAMILY_ID},
        "profile_name": catalog_profile["name"], "evidence_checks": checks,
        "failed_checks": [key for key, passed in checks.items() if not passed],
        "sessions": sessions, "native_event_count": native_count, "native_message_count": len(messages),
        "native_tool_result_count": result_count, "native_model_identities": providers, "tools": calls,
        "task_result": {"document": {"name": "quote", "bytes": len(quote), "sha256": digest(quote)}, "amounts": amounts,
                        "calculated_total": sum(amounts), "answer": {"native_reference": reference(answer_row), "text": answer} if answer_row else None,
                        "after_revocation_answer": {"native_reference": reference(denial_row), "text": denial} if denial_row else None},
        "final_authority": authority, "final_lifecycle": lifecycle, "process_observations": processes,
        "model_provenance": model,
        "runtime_source_summary": {"files": len(sources), "equal_to_checkout": sum(row["runtime_equals_checkout"] for row in sources),
                                   "differences": [row["checkout_path"] for row in differences], "full_runtime_source_copied": False},
        "management_ui_recording_limits": [
            "Form validation and DOM updates were revised during recording.",
            "After recording, concurrent status queries were fixed with per-profile operation locking and last-observed-state display while pending.",
            "Management UI/server files are not in the 24-file frozen execution core/plugin inventory. The whole recording is not claimed to match final release code.",
            "A transient UI state misreport occurred; actual outcomes are cross-checked against native transcript, authority, lifecycle and public jobs."],
        "limitations": [
            "The root agent operated the real workbench and OpenClaw browser pages through Playwright; no human participants were recruited for a user study.",
            "One synthetic budget document and one native session; two reads only. No send, exec, prompt-injection payload, new session or adversarial search was tested here.",
            "Reopening preserves the same task, family and document binding; no authorized reread was recorded between reopening and revocation.",
            "Revocation does not erase prior context or immediately stop all computation. A separate stop followed.",
            "The model's suggestion to apply for permission is natural language only; this version cannot restore the revoked task.",
            "The denied native result has no event ID. Association uses read operation, refusal reason and a unique two-second time window.",
            "Source hashes and captured records establish local consistency, not an independent external attestation."],
        "input_digests": {"broker_raw_sha256": digest(broker_raw), "adapter_raw_sha256": digest(adapter_raw),
                          "public_jobs_projection_sha256": digest(jsonl(jobs)),
                          "selected_native_message_references_sha256": digest(encoded([pick(row, ("session_id", "seq", "event_json_sha256")) for row in messages]))},
        "verifier_sha256": file_digest(Path(__file__)),
        "credential_scan": {"known_profile_credentials": 2, "values_or_value_hashes_exported": False,
                            "policy": "Scan every proposed and written artifact against the two actual credential values, including stripped and JSON-escaped forms."},
    }
    native_export = [pick(row, ("session_id", "seq", "created_at", "event_json", "event_json_sha256")) for row in messages]
    artifacts = {
        "native-messages.jsonl": jsonl(native_export), "broker-events.jsonl": jsonl(broker_public),
        "authority-events.jsonl": jsonl(authority_events), "operator-jobs.jsonl": jsonl(jobs),
        "observations.jsonl": jsonl(observations), "adapter-events.jsonl": jsonl(adapter_public), "quote.txt": quote,
        "source-inventory.json": encoded(sources) + b"\n",
        "source-differences.patch": "\n".join(row["diff"] for row in differences).encode("utf-8"),
        "report.json": encoded(report) + b"\n", "REPORT.zh-CN.md": chinese_report(report),
    }
    return report, artifacts


def scan_credentials(profile, artifacts):
    forbidden = set()
    for name in ("model-key", "gateway-token"):
        raw = (profile / name).read_bytes()
        if not raw.strip():
            raise RuntimeError("Empty credential cannot be checked")
        forbidden.update((raw, raw.strip()))
        forbidden.add(json.dumps(raw.strip().decode("utf-8"), ensure_ascii=False)[1:-1].encode("utf-8"))
        # Credential hashes are also excluded from the evidence, including the
        # hashes recorded in the private profile manifest.
        forbidden.update((digest(raw).encode(), digest(raw.strip()).encode()))
    for name, payload in artifacts.items():
        if any(value in payload for value in forbidden if value):
            raise RuntimeError("Credential or credential digest detected in artifact: " + name)
        if b"dashboard_url" in payload or b"#token=" in payload:
            raise RuntimeError("Private dashboard-link field detected in artifact: " + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--observations", required=True, type=Path)
    parser.add_argument("--model-manifest", required=True, type=Path)
    parser.add_argument("--model-process-record", required=True, type=Path)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument("--final", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if bool(args.output) != args.final:
        parser.error("--final and --output must be supplied together")
    if not sys.platform.startswith("linux"):
        parser.error("Run under Linux/WSL to inspect recorded process identities read-only")
    if args.final:
        output = args.output.resolve()
        if output.exists():
            parser.error("Output already exists; frozen evidence is never overwritten")
        live_root = args.profile.resolve().parent.parent
        if output == live_root or live_root in output.parents:
            parser.error("Output must be outside the observed workbench")
    report, artifacts = assemble(args)
    artifacts["artifact-manifest.json"] = encoded({name: {"bytes": len(raw), "sha256": digest(raw)}
                                                  for name, raw in artifacts.items()}) + b"\n"
    scan_credentials(args.profile, artifacts)
    if args.final and report["status"] == "verified":
        output.mkdir(parents=True, exist_ok=False)
        for name, raw in artifacts.items():
            (output / name).write_bytes(raw)
        written = {path.name: path.read_bytes() for path in output.iterdir()}
        scan_credentials(args.profile, written)
        if written != artifacts:
            raise RuntimeError("Written artifacts do not match prepared evidence")
        inventory = json.loads(written["artifact-manifest.json"])
        if any(len(written[name]) != entry["bytes"] or digest(written[name]) != entry["sha256"] for name, entry in inventory.items()):
            raise RuntimeError("Written artifact manifest verification failed")
    print(json.dumps({"status": report["status"], "final_export": args.final,
                      "checks_passed": sum(report["evidence_checks"].values()), "checks_total": len(report["evidence_checks"]),
                      "failed_checks": report["failed_checks"], "sessions": len(report["sessions"]), "tool_calls": len(report["tools"]),
                      "native_messages": report["native_message_count"], "calculated_total": report["task_result"]["calculated_total"],
                      "runtime_source_summary": report["runtime_source_summary"], "current_model_process": report["model_provenance"]["live_process"],
                      "model_bytes_rehashed_and_match": report["model_provenance"]["model_bytes_rehashed_and_match"],
                      "files": len(artifacts), "total_bytes": sum(map(len, artifacts.values())),
                      "output": str(args.output) if args.final and report["status"] == "verified" else None}, ensure_ascii=False, indent=2))
    return 0 if report["status"] == "verified" else 2


if __name__ == "__main__":
    raise SystemExit(main())
