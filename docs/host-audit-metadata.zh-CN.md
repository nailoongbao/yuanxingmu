# HostModel 的可选审计关联信息

此接口用于受信任宿主对接需要请求关联信息的模型网关。默认 `audit_metadata_provider=None`，不增加审计请求头。它是源码中的开发接口，尚未包含在已经发布的 runtime `0.7.0a2` 或 installer `0.4.0a2` 下载文件中，也没有工作台界面开关。

已有宿主可以在构造 `HostModel` 时选择使用内置工厂：

```python
from yuanxingmu.gateway_network import HostModel, new_audit_metadata

# runtime、model_url、api_key、output_guard、model_store 沿用已有宿主配置。
bridge = HostModel(
    runtime,
    model_url=model_url,
    api_key=api_key,
    output_guard=output_guard,
    model_store=model_store,
    audit_metadata_provider=new_audit_metadata,
)
```

工厂每次生成一个不依赖任务、目标或资料标签的随机关联标识。启用后的返回值必须恰好包含：

| 字段 | 格式 |
| --- | --- |
| `X-YXM-Audit-Correlation-ID` | `corr-` 加 32 位小写十六进制字符；内置工厂使用 16 个随机字节 |
| `X-YXM-Audit-Protocol-Version` | 固定为 `1.0` |

自定义 provider 是不接收 Worker 输入的宿主回调，须返回普通 `dict[str, str]`。格式校验不能证明自定义值没有包含秘密；宿主应使用新生成的随机关联标识，保持回调轻量，不把它用作授权判断或外部副作用入口。关联标识用于对应日志，不是身份凭据。

## 请求处理顺序

先运行现有任务与受保护内容预检查，再生成并验证审计字段。由于宿主回调可能耗时，启用时会在回调返回后再次预检查当前状态；随后才登记模型请求并连接上游。Worker 入站头始终不参与上游头部构造，宿主 `Authorization` 和其他基础头保持原来的来源。

缺字段、多余字段、版本不符、非法关联标识或 provider 异常会返回固定的 HTTP 500 错误码；此时未连接上游、未调用 journal 的 `begin`，修正本地配置后可以重试相同请求。错误内容不包含回调异常详情。暂停或撤权被预检查发现时，继续返回原有的宿主拒绝结果，也不登记或发送请求。

普通 `/v1/chat/completions` 请求在查询 journal 前校验元数据，因此即使随后命中本地缓存，也可能调用 provider；这不代表产生了上游模型请求。显式的 `/v1/chat/completions/replay` 路径只按既有规则读取已完成结果，不调用 provider。已登记并实际尝试过的网络故障继续保留原有 pending/unknown 语义，本功能不会删除未知结果来强行重试。

这些约束只针对新增审计头，模型请求正文仍沿用现有检查和发送路径。暂停不能撤回已经发送的内容。

## 验证

`tests/test_yuanxingmu_gateway_network.py` 包含跨平台字段校验及 Linux 真实 Unix/TCP 传输检查：默认无审计字段、Worker 伪造头被丢弃、宿主认证头不变、连续请求获得不同关联标识、拒绝时没有 TCP 连接或 journal 登记。

`tests/test_yuanxingmu_audit_metadata_state.py` 使用真实 Broker、ModelStore 和本机合成上游，检查本地配置错误后相同请求可重试、回调期间撤权、请求前撤权，以及显式 replay 不调用 provider。Unix 传输和 POSIX journal 用例在 Windows 明确跳过；字段校验仍在 Windows 运行。所有这些检查都不调用真实模型。
