# Hermes 的元星木执行环境

这个示例通过 Hermes 官方执行环境插件入口，让原来的终端和文件工具在 bubblewrap 中运行。长期凭证和私密源文件留在宿主，任务通过一个固定的 Unix socket 请求 broker 读资料或发送内容。

实际接入链是：

```text
Hermes terminal_tool / read_file_tool / write_file_tool
  → 官方 terminal environment provider 工厂
  → 官方 BaseEnvironment.execute
  → 元星木 worker / bubblewrap
  → 任务独有的 broker socket
```

`__init__.py` 实现官方 `TerminalEnvironmentProvider` 和 `BaseEnvironment` 扩展。`run_probe.py` 用真实 `PluginContext.register_terminal_environment_provider` 注册后端，并调用未修改的 Hermes 原生工具函数。文件工具在终端之前调用，用来确认文件工具自己建立环境时也采用这个后端。

## 已验证的结果

测试版本为 Hermes tag `v2026.9.7`、提交 `2237be355906fbe6065ce1815711eee52b2d646e`；该提交的 Python distribution 版本为 `0.21.1`。执行环境为 Ubuntu/WSL、Python 3.12.3、bubblewrap 0.9.0。

2026-09-11 的最终运行通过 16 项断言：12 次原生工具调用产生 17 次真实隔离执行，3 个原生环境实例均已清理，所有执行器进程已回收。版本和散列见 [observed-results.json](observed-results.json)。

| 任务动作 | 实际观察 |
|---|---|
| 原生文件工具写、读工作区；终端读取同一文件 | 正常完成 |
| 原生文件工具直接读宿主合成私密文件 | 失败，未返回文件内容 |
| 经 broker 读取私密材料 | 成功，并记录任务已读状态 |
| 读后向公开收件方发送 | broker 拒绝，没有收件记录 |
| 改为允许的内部发送 | 成功，收件一次 |
| 终端运行 Python，直接连接宿主收件端口 | `ConnectionRefusedError` |
| 原生 `cleanup_vm` 后重新建立环境，再向公开收件方发送 | 仍拒绝 |
| 另一个任务、独立工作区发送公开内容 | 成功，收件一次 |
| 宿主撤销任务后，原生文件工具继续写入 | 拒绝，文件未产生 |
| 宿主工作目录放置伪造 `yuanxingmu` 包后运行 | 伪造包未在宿主执行，外部标记文件未产生 |

独立收件服务最终仅收到“内部修正”和“独立公开任务”两条消息；收件 request ID 与原生工具返回值匹配。被测适配器、broker、执行器和实际导入的 Hermes 源文件在运行前后散列一致。

所有材料、目的端和凭证样式值均为合成测试数据。没有调用模型，没有真实账户或生产服务。Hermes 原有命令审批保持开启：`skip_container_guards=False`，原生终端调用没有使用 `force=True`。

## 复跑

使用已安装上述 Hermes 提交的 Linux Python 环境。根项目应为当前工作目录，输出目录必须是新的。参数指向可信宿主选择的 bubblewrap 可执行文件：

```bash
python -I -B examples/yuanxingmu/hermes/run_probe.py \
  --bwrap /absolute/path/to/bwrap \
  --output /absolute/path/to/new-hermes-probe
```

程序创建自己的 `HERMES_HOME`、配置文件、broker 状态、私密源、两个独立工作区和收件记录，不改个人 Hermes 配置。它检查实际导入源码的 Git 提交；版本不一致会停止。证据保存在输出目录的 `result.json`、`receiver.jsonl` 和 `broker-state/`。

本次本机环境是 `/home/liyihao24/codex-agent-defense-hosts-20260911/hermes/env/bin/python`，最终证据目录是 `/home/liyihao24/codex-yuanxingmu-tools/hermes-example-03/`。bubblewrap 可执行文件为 `/home/liyihao24/codex-yuanxingmu-tools/bubblewrap-0.9.0/usr/bin/bwrap`，只下载并解包了 Ubuntu 包，没有更改系统安装。

## 可信宿主如何接入

可信宿主先用 `Broker.create_task` 建立任务，再用 `Broker.bind_workspace` 绑定独立工作区，用 `Broker.serve` 建立该任务专属 socket。随后将 Hermes 的任务 ID 映射为：

```python
TaskBinding(
    security_task_id=broker_task_id,
    workspace=task_workspace,
    broker_socket=task_socket,
    readonly_paths=(client_package_directory,),
    env={"PYTHONPATH": client_package_parent},
)
```

用这些绑定构造 `YuanxingmuProvider`，经 Hermes 官方插件上下文注册。没有绑定的任务不能自动取得默认身份。每条命令启动前还会向固定 socket 核对任务身份和活动状态；broker 不可达、任务已撤销或身份不匹配时，命令不会启动。

包含 `plugin.yaml` 和 `register(ctx)` 供宿主插件加载。`register` 从 `plugins.entries.yuanxingmu.settings.host_config` 或明确的 `YUANXINGMU_HERMES_CONFIG` 读取宿主配置路径。配置文件结构为：

```json
{
  "bwrap": "/absolute/path/to/bwrap",
  "tasks": {
    "hermes-task-id": {
      "security_task_id": "existing-broker-task-id",
      "workspace": "/absolute/path/to/owned-workspace",
      "broker_socket": "/absolute/path/to/task.sock",
      "readonly_paths": [],
      "env": {}
    }
  }
}
```

这些字段是宿主授权，不接受模型生成的挂载、身份或 socket。配置不能放入任务可写工作区。新任务必须使用独立工作区，不能把已有私密内容的工作区交给一个未读私密资料的新身份。

示例在导入执行器前固定可信代码根目录，并拒绝已从异源加载的同名模块；接入代码直接调用已导入的 `worker.start`，不会在进入沙箱前从工作目录运行 `python -m yuanxingmu.worker`。复制插件到其他目录时，宿主须设置 `YUANXINGMU_CORE_ROOT` 为可信安装中包含 `yuanxingmu/` 的绝对目录。独立收件进程也使用 `python -I -c` 加固定代码路径启动。

本次实际验证的是程序化官方注册和原生工具运行；没有执行 `hermes plugins enable` 的个人配置流程。

## 当前范围

本示例验证终端前台执行、文件读写，以及原生执行环境清理后重建。没有验证自主模型攻击、原生 `delegate_task`、Hermes 会话历史恢复、后台进程工具、PTY 或 `execute_code`。命令之间只保留工作区和已观察到的当前目录；不保留 shell 的 export/alias 或临时目录。

Hermes 的 browser、web、MCP、消息发送、模型 provider 等宿主出口不在此适配的保护范围。模型服务仍可能收到工具结果与上下文；宿主程序和人也能看到输出。不能把这个终端/文件结果写成“整个 Hermes Agent 已完全防泄密”。

底层使用共享内核的 bubblewrap；没有增加资源配额或证明能防内核漏洞。命令审批、输出限长和中断等待复用 Hermes 原实现；适配器不把宿主 `SUDO_PASSWORD` 注入任务。

官方接口说明：[Terminal Environment Provider Plugins](https://github.com/NousResearch/hermes-agent/blob/2237be355906fbe6065ce1815711eee52b2d646e/website/docs/developer-guide/terminal-environment-plugin.md)。
