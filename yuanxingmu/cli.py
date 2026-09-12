"""Host CLI. Worker-facing operations are in yuanxingmu.client."""
import argparse
import json
import os
from pathlib import Path
import shutil
import sys


def main():
    parser = argparse.ArgumentParser(prog="yuanxingmu", description="Yuanxingmu / 元星木 — authority outside the agent")
    commands = parser.add_subparsers(dest="command", required=True)
    doctor = commands.add_parser("doctor", help="Check actual Linux isolation availability")
    doctor.add_argument("--bwrap", type=Path)
    demo = commands.add_parser("demo", help="Run isolated synthetic workers and verify independent receipts")
    demo.add_argument("--output", required=True, type=Path)
    demo.add_argument("--bwrap", type=Path)
    desk = commands.add_parser("desk", help="打开元星木本地工作台，在页面中管理 OpenClaw 和 Hermes")
    desk.add_argument("--install-root", type=Path, default=Path.home() / "yuanxingmu")
    desk.add_argument("--data", type=Path, help="工作台自己的新目录；默认是安装目录下的 workbench")
    desk.add_argument("--port", type=int, default=18910)
    desk.add_argument("--node", type=Path)
    desk.add_argument("--openclaw-package", type=Path)
    desk.add_argument("--hermes-python", type=Path)
    desk.add_argument("--hermes-source", type=Path)
    desk.add_argument("--action-targets", type=Path, help="宿主登记的消息、上传、表单和文件操作对象 JSON；不会交给 AI")
    desk.add_argument("--skill", action="append", default=[], metavar="NAME=PATH", help="登记可在页面中选择的技能目录；只加载选中的固定快照")
    desk.add_argument("--bwrap", type=Path)
    desk.add_argument("--no-browser", action="store_true")
    run = commands.add_parser("run", help="Run a command with a persistent task and operator-owned policy")
    run.add_argument("--policy", required=True, type=Path)
    run.add_argument("--state", required=True, type=Path)
    run.add_argument("--task", required=True)
    run.add_argument("--new-task", action="store_true", help="Explicitly create a trusted new root; omit when resuming")
    run.add_argument("--workspace", required=True, type=Path)
    run.add_argument("--bwrap", type=Path)
    run.add_argument("worker_command", nargs=argparse.REMAINDER)
    sdk = commands.add_parser("sdk-run", help="在已有工作的防护内运行完整 SDK 会话；原生网页需先停止")
    sdk.add_argument("--profile", required=True, type=Path)
    sdk.add_argument("--framework", choices=("smolagents", "langgraph", "openai_agents"), default="smolagents", help="使用固定版本的受保护运行入口")
    sdk.add_argument("--sdk-python", required=True, type=Path, help="选定框架独立 venv 的 bin/python")
    sdk.add_argument("--session", required=True, help="本工作内的会话名称；新会话沿用原权限")
    sdk.add_argument("--prompt-file", required=True, type=Path, help="本次任务的 UTF-8 文本文件")
    sdk.add_argument("--resume", action="store_true", help="恢复同名会话，保留工具编号及权限")
    sdk.add_argument("--max-steps", type=int, default=12)
    sdk.add_argument("--max-tokens", type=int, default=2048)
    sdk.add_argument("--timeout", type=int, default=600)
    openclaw = commands.add_parser("openclaw", help="创建和使用受保护的 OpenClaw")
    actions = openclaw.add_subparsers(dest="action", required=True)
    init = actions.add_parser("init", help="连接自己的模型，建立独立实例")
    init.add_argument("--profile", required=True, type=Path)
    init.add_argument("--model-url", required=True, help="OpenAI-compatible endpoint, including /v1")
    init.add_argument("--model-id", required=True)
    init.add_argument("--api-key-env", help="从指定环境变量读取模型密钥；不传密钥值到命令行")
    init.add_argument("--document", action="append", default=[], metavar="NAME=PATH", help="导入 UTF-8 文本快照；可重复")
    init.add_argument("--destinations", type=Path, help="操作者选择的固定接收位置 JSON 文件；默认不能发送")
    init.add_argument("--node", type=Path)
    init.add_argument("--openclaw-package", type=Path)
    init.add_argument("--bwrap", type=Path)
    init.add_argument("--port", type=int, default=18911)
    init.add_argument("--context-window", type=int, default=32768)
    init.add_argument("--max-tokens", type=int, default=2048)
    init.add_argument("--objective", help="固定工作目标；提供后启用五层检查")
    init.add_argument("--defense-policy", type=Path, help="宿主防护设置 JSON，必须包含 objective")
    init.add_argument("--skill", action="append", default=[], metavar="NAME=PATH")
    init.add_argument("--reviewed-mail", action="store_true")
    init.add_argument("--action-targets", type=Path)
    for name, help_text in (("start", "启动或重新打开原来的实例"), ("status", "查看模型、资料与权限状态"),
                            ("revoke", "永久收回这个实例的资料读取和发送权限"), ("stop", "关闭本实例及其运行中的命令")):
        action = actions.add_parser(name, help=help_text)
        action.add_argument("--profile", required=True, type=Path)
    hermes = commands.add_parser("hermes", help="创建和使用受保护的 Hermes 官方网页")
    hermes_actions = hermes.add_subparsers(dest="action", required=True)
    hermes_init = hermes_actions.add_parser("init")
    for name in ("profile", "hermes-python", "hermes-source", "node", "bwrap", "destinations", "defense-policy", "action-targets"):
        hermes_init.add_argument("--" + name, type=Path, required=name in {"profile", "hermes-python", "hermes-source"})
    hermes_init.add_argument("--model-url", required=True)
    hermes_init.add_argument("--model-id", required=True)
    hermes_init.add_argument("--api-key-env")
    hermes_init.add_argument("--document", action="append", default=[], metavar="NAME=PATH")
    hermes_init.add_argument("--skill", action="append", default=[], metavar="NAME=PATH")
    hermes_init.add_argument("--objective")
    hermes_init.add_argument("--reviewed-mail", action="store_true")
    hermes_init.add_argument("--port", type=int, default=18912)
    hermes_init.add_argument("--context-window", type=int, default=65536)
    hermes_init.add_argument("--max-tokens", type=int, default=2048)
    for native_init in (init, hermes_init):
        native_init.add_argument("--action-automation", type=Path, help="创建时固定的自动执行范围 JSON；需同时启用防护和操作对象")
        native_init.add_argument("--judge-url", help="可选：独立检查模型的地址")
        native_init.add_argument("--judge-model-id", help="独立检查模型的名称")
        native_init.add_argument("--judge-api-key-env", help="从这个环境变量读取检查模型密钥")
        native_init.add_argument("--judge-timeout", type=float, default=30, help="检查等待秒数，最多45秒")
    for name in ("start", "status", "stop", "revoke"):
        hermes_actions.add_parser(name).add_argument("--profile", required=True, type=Path)
    defense = commands.add_parser("defense", help="查看或修改每层防护设置；新版本支持运行中修改")
    defense_actions = defense.add_subparsers(dest="action", required=True)
    for name in ("get", "set", "reset", "restore"):
        command = defense_actions.add_parser(name)
        command.add_argument("--profile", required=True, type=Path)
        if name == "restore":
            command.add_argument("--baseline-sha256", required=True, help="从 defense get 核对的创建时设置摘要")
            command.add_argument("--expected-policy-sha256", required=True, help="从 defense get 核对的当前设置摘要；过期时拒绝恢复")
        if name == "set":
            for layer in ("input", "memory", "command", "alignment", "foundation"):
                command.add_argument("--" + layer, dest="layer_" + layer, choices=("on", "off"))
                command.add_argument("--" + layer + "-mode", choices=("inherit", "enforce", "observe"), help="这一层的处理方式；inherit 跟随默认方式")
            command.add_argument("--mode", choices=("enforce", "observe"), help="未单独设置的层采用的默认处理方式")
            command.add_argument("--foundation-config", choices=("on", "off"), help="基础配置规则与配置语义检查")
            command.add_argument("--skill-semantic", choices=("on", "off"), help="技能语义与用途对照；安全快照仍保留")
            command.add_argument("--skill-rules", choices=("on", "off"), help="技能规则检查；安全快照仍保留")
    args = parser.parse_args()
    try:
        def selected_skills():
            result = {}
            for item in args.skill:
                name, separator, path = item.partition("=")
                if not separator or not path or name in result:
                    raise ValueError("--skill 需要不重复的 NAME=PATH")
                result[name] = Path(path).expanduser().absolute()
            return result
        if args.command == "defense":
            from .protection import configure_profile
            changes = None
            if args.action == "set":
                changes = {layer + "_enabled": getattr(args, "layer_" + layer) == "on" for layer in ("input", "memory", "command", "alignment", "foundation") if getattr(args, "layer_" + layer) is not None}
                if args.mode is not None:
                    changes["mode"] = args.mode
                for layer in ("input", "memory", "command", "alignment", "foundation"):
                    selected = getattr(args, layer + "_mode")
                    if selected is not None:
                        changes[layer + "_mode"] = selected
                for name in ("foundation_config", "skill_semantic", "skill_rules"):
                    if getattr(args, name) is not None:
                        changes[name + "_enabled"] = getattr(args, name) == "on"
            options = {"intent": "restore_creation", "baseline_sha256": args.baseline_sha256,
                       "expected_policy_sha256": args.expected_policy_sha256} if args.action == "restore" else {}
            result = configure_profile(args.profile, changes, reset=args.action == "reset", **options)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        if args.command == "desk":
            from .dashboard.server import Runtime, serve
            install_root = args.install_root.expanduser()
            runtime = Runtime.discover(install_root, node=args.node, openclaw_package=args.openclaw_package, bwrap=args.bwrap,
                                       hermes_python=args.hermes_python, hermes_source=args.hermes_source)
            targets = json.loads(args.action_targets.read_text(encoding="utf-8")) if args.action_targets else None
            return serve(args.data or install_root / "workbench", runtime, port=args.port, open_browser=not args.no_browser, action_targets=targets, skill_sources=selected_skills())
        if args.command in {"openclaw", "hermes"}:
            from .openclaw import init_profile, start_profile, control_profile
            if args.action == "init":
                documents = {}
                for item in args.document:
                    name, separator, path = item.partition("=")
                    if not separator or not path or name in documents:
                        raise ValueError("--document 需要不重复的 NAME=PATH")
                    documents[name] = Path(path).expanduser()
                key = "local-unused"
                if args.api_key_env:
                    key = os.environ.get(args.api_key_env, "")
                    if not key:
                        raise ValueError("指定的模型密钥环境变量不存在或为空。")
                elif args.model_url.startswith("https:"):
                    if not sys.stdin.isatty():
                        raise ValueError("请用 --api-key-env 指定保存模型密钥的环境变量。")
                    from getpass import getpass
                    key = getpass("模型 API 密钥（输入不会显示）：")
                node = args.node or shutil.which("node")
                bwrap = args.bwrap or shutil.which("bwrap")
                package = getattr(args, "openclaw_package", None)
                if not package and args.command == "openclaw":
                    executable = shutil.which("openclaw")
                    package = Path(executable).resolve().parent if executable else None
                if not node or not bwrap or (args.command == "openclaw" and not package):
                    raise RuntimeError("需要 Node.js、bubblewrap 和 OpenClaw 2026.9.4；也可用 --node / --bwrap / --openclaw-package 指定路径。")
                destinations = json.loads(args.destinations.read_text(encoding="utf-8")) if args.destinations else {}
                policy = json.loads(args.defense_policy.read_text(encoding="utf-8")) if args.defense_policy else None
                if args.objective:
                    policy = {**(policy or {}), "objective": args.objective}
                targets = json.loads(args.action_targets.read_text(encoding="utf-8")) if args.action_targets else None
                automation = json.loads(args.action_automation.read_text(encoding="utf-8")) if args.action_automation else None
                extra = {"openclaw_package": Path(package)} if args.command == "openclaw" else {"hermes_python": args.hermes_python, "hermes_source": args.hermes_source}
                if args.command == "hermes":
                    from .hermes import init_profile
                judge_config = None
                if args.judge_url or args.judge_model_id or args.judge_api_key_env:
                    if not args.judge_url or not args.judge_model_id:
                        raise ValueError("独立检查模型需同时填写 --judge-url 与 --judge-model-id。")
                    judge_key = os.environ.get(args.judge_api_key_env, "") if args.judge_api_key_env else ""
                    if args.judge_api_key_env and not judge_key:
                        raise ValueError("指定的检查模型密钥环境变量为空。")
                    judge_config = {"url": args.judge_url, "id": args.judge_model_id,
                                    "api_key": judge_key, "timeout_seconds": args.judge_timeout}
                elif args.judge_timeout != 30:
                    raise ValueError("--judge-timeout 需要同时指定独立检查模型地址和名称。")
                result = init_profile(args.profile.expanduser(), node=Path(node), bwrap=Path(bwrap), **extra,
                    model_url=args.model_url, model_id=args.model_id, api_key=key, documents=documents,
                    destinations=destinations, port=args.port, context_window=args.context_window, max_tokens=args.max_tokens,
                    defense_policy=policy, judge_config=judge_config, selected_skills=selected_skills(), reviewed_mail=args.reviewed_mail,
                    reviewed_actions=targets is not None, action_targets=targets, action_automation=automation)
            elif args.action == "start":
                result = start_profile(args.profile.expanduser())
            else:
                result = control_profile(args.profile.expanduser(), args.action)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        if args.command == "run":
            from .run import run_command
            command = args.worker_command[1:] if args.worker_command[:1] == ["--"] else args.worker_command
            if not command:
                parser.error("run requires a worker command after --")
            return run_command(policy=args.policy, state=args.state, task=args.task, new_task=args.new_task,
                               workspace=args.workspace, command=command, bwrap=args.bwrap)
        if args.command == "sdk-run":
            from .sdk_runtime import cli
            result = cli(args)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if result["status"] == "completed" else 2
        if args.command == "doctor":
            from .sandbox import sandbox_available
            result = sandbox_available(bwrap=args.bwrap)
            print(json.dumps(result, indent=2))
            return 0 if result["available"] else 2
        from .demo import run_demo
        result = run_demo(args.output, bwrap=args.bwrap)
        print(json.dumps({"status": result["status"], "checks": result.get("checks"), "output": str(args.output.resolve())}, indent=2))
        return 0 if result["status"] == "passed" else 1
    except (OSError, RuntimeError, ValueError) as exc:
        print(json.dumps({"status": "error", "reason": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
