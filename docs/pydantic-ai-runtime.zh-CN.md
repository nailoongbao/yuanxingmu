# 在防护中运行 PydanticAI 任务

`yuanxingmu sdk-run --framework pydantic_ai` 使用真实 PydanticAI `Agent` 运行任务。Agent 流程在隔离进程中读取已登记资料、调用固定工具并保存进度；模型推理由原配置的模型服务处理，发送消息、上传文本和提交表单仍由元星木宿主检查、执行和记录。

这是 main 源码的固定运行入口，尚未进入 runtime `0.7.0a2` 或 installer `0.4.0a2` 下载包。它沿用已有 Hermes/OpenClaw 工作实例的任务、资料限制、保护字段与自动额度。同名会话、另开的 SDK 会话和切换框架都不会创建新的任务授权。

## 安装与运行

先准备一个已启用分层防护、保护字段及回答缓冲的工作实例，并停止其原生服务。使用 Linux/WSL 系统 Python，在工作实例目录之外建立 SDK 环境：

```bash
/usr/bin/python3 -m venv ~/yuanxingmu-pydantic-ai
~/yuanxingmu-pydantic-ai/bin/python -m pip install -r docs/pydantic-ai-runtime-requirements.txt

yuanxingmu sdk-run \
  --framework pydantic_ai \
  --profile /absolute/path/to/profile \
  --sdk-python /absolute/path/to/pydantic-ai-venv/bin/python \
  --session customer-summary \
  --prompt-file /absolute/path/to/task.txt \
  --max-steps 12 \
  --max-tokens 2048 \
  --timeout 600
```

固定依赖为 `pydantic-ai-slim 2.43.0`、`pydantic-graph 2.43.0` 和 `pydantic 2.13.5`。解释器须来自 `/usr` 下的系统 Python；宿主只读取依赖元数据，SDK 在受限进程中导入。模型沿用原工作实例的配置，通过宿主的 Chat Completions 通道连接，真实模型密钥留在宿主。

启动前会重新核对固定工具清单与原工作配置。如果原来的 `allowed_tools` 只允许 Hermes/OpenClaw 原生工具，清单不匹配会阻止启动；入口不会自行扩大权限。

## 工具与自动执行

| 工具 | 用途 |
|---|---|
| `yuanxingmu_read` | 读取已登记且原任务允许访问的资料。 |
| `yuanxingmu_describe` | 查看原任务的权限与限制。 |
| `yuanxingmu_action_targets` | 查看已登记的操作对象。 |
| `yuanxingmu_propose_action` | 保存等待宿主复核的操作提案。 |
| `yuanxingmu_draft_email` | 保存邮件草稿，不发送邮件。 |
| `yuanxingmu_request_action` | 仅在原工作已有自动范围时提供，申请消息、文本上传或表单操作。 |

自动范围在任务创建时设定。范围内的正常操作不需要逐项点击批准，宿主仍逐次检查内容、目标、额度及撤销状态。工具参数使用原生严格校验；发送给模型的固定对象声明会展开局部引用，执行端不会把字符串猜成对象。任一调用不符合固定工具名称、参数结构和类型要求，整批在首个工具执行前拒绝；目标、内容、额度等宿主检查仍逐项进行，后续调用被拒绝时，前面的合法操作可能已完成。

这个入口没有即时 `send`、任意终端、宿主审批工具、外部工具服务器或动态子 Agent。保存文件操作提案也不等于自动修改宿主文件。

## 暂停和恢复

PydanticAI 原生延迟工具状态用于保存进度。程序核对宿主记录后，自动继续同一批工具；这些内部批准标记不代表用户授权，也不需要用户反复确认。

同名会话加 `--resume` 恢复。未完成会话必须沿用原任务文本；已完成会话的相同任务直接返回保存的答案，宿主仍重新检查回答。换成新任务文本可以继续对话，但使用原任务的权限和剩余额度。同名会话不能换 SDK 或解释器继续。

原生接口在恢复已批准批次时会重新调用其中的工具。接入层为这些调用保留宿主生成的原编号，重新核对原模型回复和当前权限；宿主按原编号查询已记录的操作结果，接入层保留原工具结果供模型继续。恢复可能产生重复查询，不应理解为网络操作从未被再次请求。

权限拒绝、范围或额度不足等确定结果可以交给模型处理。恢复时，原来获准的调用若已不再允许，会停止。操作仍在执行、结果未确认、任务暂停或撤销、通信或存储出错时，后续工具和模型调用停止。不会把不确定结果包装成普通工具回复让模型继续，也不会自动重试未确认的模型请求。

检查点保存 PydanticAI 原生消息 JSON、暂停位置，以及两次暂停之间的模型请求和工具结果。恢复时验证原生历史与宿主调用记录的对应关系；不能通过修改批准状态、工具编号或参数扩大权限。时间戳和原生运行 UUID 不用作授权身份。检查点可能含对话和资料正文，应作为工作数据保存。

宿主对相同任务组、目标和规范化内容的未确认自动操作另有精确重复检查。它不能识别所有语义改写后的重复业务。

## 验证与范围

独立的 [GLM‑5.2 两轮实测](evidence/pydantic-ai-runtime-2026-09-13/REPORT.zh-CN.md)保留第一轮未知工具名拒绝、第二轮相同源码和完整提示下的三项自动操作。第二轮重开无重复提交，撤销后停止；操作者回复中的技术字段与收据时间戳倒序也如实记录。同一冻结源码的 15 个 SDK 测试模块在 Linux 上 201/201 通过、零跳过，其中 PydanticAI 专用测试为 38 项。

专用测试使用实际 PydanticAI、Unix Broker 和本机接收端，模型服务为确定性测试服务：

```bash
PYTHONPATH=.:tests ~/yuanxingmu-pydantic-ai/bin/python -m unittest \
  tests.test_pydantic_ai_runtime \
  tests.test_pydantic_ai_runtime_automatic \
  tests.test_pydantic_ai_runtime_faults -v
```

这个固定入口不接管任意已有 PydanticAI 应用、用户自定义工具、结构化输出、媒体输入输出、远程会话、流式响应或多 Agent 流程。原生工具适配仍可单独使用，但单独注册工具不会启用整个进程的隔离。进程组 CPU、内存和工作目录磁盘总配额仍未实现。
