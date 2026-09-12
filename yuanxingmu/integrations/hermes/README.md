# Hermes 官方界面接入

这个接入运行 Hermes 自带的网页界面、终端界面和 Agent。元星木在外面限制它能接触哪些文件、网络和权限，在终端执行前再增加一层隔离。Hermes 的页面和对话流程来自官方项目。

当前支持并实际验证的是 Hermes `v2026.9.11`，包版本 `0.21.2`，上游提交 `939e45c91d751fadd94dcd1b873ac3cb44846213`。需要 Linux、可用的 bubblewrap、独立 Python 虚拟环境、Node，以及已经构建的官方 `hermes_cli/web_dist/index.html` 和 `ui-tui/dist/entry.js`。Windows 可通过 WSL 运行。

## 如何启动

网页工作台的 Hermes 选项使用同一套配置创建和启停接口。直接调用 Python 时，运行环境路径由操作者提供：

```python
from pathlib import Path
from yuanxingmu.hermes import init_profile
from yuanxingmu.openclaw import start_profile, control_profile

profile = Path('/home/me/yuanxingmu-profiles/hermes-demo')
init_profile(
    profile,
    node=Path('/opt/node/bin/node'),
    hermes_python=Path('/opt/hermes/env/bin/python'),
    hermes_source=Path('/opt/hermes/source'),
    bwrap=Path('/usr/bin/bwrap'),
    model_url='http://127.0.0.1:18109/v1',
    model_id='my-model',
    api_key='local-unused',  # 本地模型示例；远端凭据只交给宿主。
    documents={'quote': Path('/home/me/private/quote.txt')},
    selected_skills={},  # 默认不加载技能；可显式选择小型技能目录。
    reviewed_mail=True,
    port=18921,
    context_window=65536,
)
result = start_profile(profile)
print(result['dashboard_url'])
# 用完后：control_profile(profile, 'stop')
```

`openclaw.py` 中的启停服务由两个接入共同使用。已有配置使用 `start_profile` 恢复，不能再次调用 `init_profile` 覆盖它。每个配置属于一个操作者；不要把它当成多人权限隔离服务。

官方 Hermes 要求至少 64,000 个上下文 token。配置中的窗口必须与模型服务实际提供的窗口一致。验收使用的 Qwen3-4B 原生窗口为 40,960，通过 YaRN 扩展到 65,536；这只完成短对话接入验证，没有完成长上下文质量验证。

## 模型能用的工具

| 工具 | 作用 |
| --- | --- |
| 官方 `terminal`、文件工具 | 只在此配置的工作目录中执行，通过元星木终端后端 |
| `yuanxingmu_status` | 查询宿主保存的当前权限 |
| `yuanxingmu_read` | 读取操作者导入的指定资料 |
| `yuanxingmu_send` | 请求发送到操作者事先配置的位置，宿主再次检查权限 |
| `yuanxingmu_prepare_email` | 保存待用户核对的邮件草稿，不发送 |
| `yuanxingmu_action_targets` | 列出操作者允许起草的操作目标 |
| `yuanxingmu_prepare_action` | 起草消息、上传、表单或文件修改，等待宿主侧确认 |

后两项需启用 `reviewed_actions`；邮件草稿需启用 `reviewed_mail`。没有配置目标时，工具不会自行扩大目标范围。这组工具数量较少，使用官方 `tools.tool_search.enabled: off` 配置直接展示完整参数。

## 权限在哪里生效

- 网页、终端界面和 Agent 的整个进程树进入独立网络环境，只保留宿主提供的指定通道。终端工具再进入独立的执行环境。
- 模型服务密钥、原始资料目录、权限数据库和人工确认 socket 留在宿主。Hermes 只拿到固定的资料、操作和模型服务入口。
- 配置创建时即标为私有。新聊天、恢复会话和内部任务编号改变都沿用同一份宿主权限，不能靠换编号恢复发送权限。
- 真实邮件和其他操作的最终确认在宿主工作台。工具参数不接受批准标记或任意网址。
- 启用 `defense_policy` 后，宿主检查命令和返回内容。原生工具的前置钩子先跑确定性规则，最终命令在终端后端接受一次语义判断；等待批准时不重复判断。文件工具若实际执行多个命令，每个命令分别检查。明确禁止的操作直接停止；需要核对的最终执行参数送到宿主工作台，批准只消费一次。超时、取消、撤权和不确定回执都停止执行。

语义检查默认使用工作模型。要单独配置检查模型，可在启用 `defense_policy` 时向 `init_profile` 传入 `judge_config={"url": "http://127.0.0.1:18110/v1", "id": "my-judge-model", "api_key": "local-unused", "timeout_seconds": 30}`。检查模型的配置及密钥留在宿主，纳入配置完整性校验，不进入 Hermes 环境或挂载目录。省略此项不会改变原有默认行为。该配置已通过组件测试，尚未在新 Hermes 原生实例中验证。

## 已验证与未验证

2026-09-12 的基础接入验收通过真正网页输入请求，官方 Agent 实际完成终端执行、权限查询、私有资料读取、邮件草稿保存和操作目标查询。草稿在宿主数据库中为 `pending`，没有批准或发送尝试。运行时也核对了网页及 Node/Python 进程的网络隔离和不可见文件。最新 26 项 Hermes 专项组件测试使用官方 Hermes Python 环境通过，其中包含最终命令只判断一次、批准后单次消费，以及每个底层文件命令分别检查。

开启全部防护后的后续原生验证，实际拦住了合成的指令注入、长期记忆改写、`sudo` 命令和外发内部底价草稿；危险技能在启动前被拒绝。另一个实例验证了回答检查及暂停后新建聊天仍不调用模型和工具。同时出现了正常操作误报和无效命令，原生界面中的“待批准 → 人工批准 → 执行一次”仍未通过。详见[公开验证记录](VALIDATION.zh-CN.md)。

这些是明确样本的集成验证，没有运行冻结攻击集，不能给出模型攻击阻断率。最近的命令重复判断修正和独立检查模型配置只有组件证据，尚未使用新的 Hermes 原生实例完整复验。通用操作的实际提交由宿主组件测试；本次没有执行真实发送、上传或删除。

Hermes 原生人工审批支持会话记忆和自动放行模式，当前接入不使用它们批准宿主的 `review`。宿主确认绑定本次真实会话、工具调用及执行参数，300 秒后过期，消费后即使执行失败也不能复用。带防护的原生执行缺少调用上下文时会停止。进程管理工具还有独立前置检查，其 `review` 当前直接停止。

新配置默认空技能库，可通过 `selected_skills` 显式选择小型技能目录。宿主保存完整只读快照，并覆盖 Hermes 实际技能目录；上游内置及可选技能库被空目录覆盖，启动同步、项目技能发现和外部技能目录均禁用。官方 Skills 页和运行时挂载已验证只显示选中的 1 项技能，三处挂载均只读。旧配置没有快照时，基础检查仍返回 `skills_pinned: false`。Agent 通过原生 `read_file` 读取所选快照。

## 上游依据

- [官方发布](https://github.com/NousResearch/hermes-agent/releases/tag/v2026.9.11)
- [官方终端后端接口](https://github.com/NousResearch/hermes-agent/blob/939e45c91d751fadd94dcd1b873ac3cb44846213/agent/terminal_env_provider.py)
- [官方工具和审批钩子](https://github.com/NousResearch/hermes-agent/blob/939e45c91d751fadd94dcd1b873ac3cb44846213/hermes_cli/plugins.py)
- [官方工具发现配置](https://github.com/NousResearch/hermes-agent/blob/939e45c91d751fadd94dcd1b873ac3cb44846213/hermes_cli/config_defaults.py)
