# 元序星核网关与元星木 HostModel 端网协同试点验收报告

本报告记录了基于元星木当前主干（Commit `876043a`）源码环境，针对 Issue #6 中维护者与贡献者共同敲定的 **4 项端网协同试点验收契约** 的可复现验证结果。

## 验证环境说明
- **运行环境**：Debian 13 (Trixie) amd64 / Linux 6.8 内核 / Python 3.13.5
- **组件边界**：
  - 真实组件：`yuanxingmu.authority.Broker`、`yuanxingmu.gateway_network.HostModel`、`yuanxingmu.sdk_model_store.ModelStore`、`yuanxingmu.sdk_runtime._SdkOutputGuard`
  - 替代组件：本地合成 HTTP 网关端点（监听 `127.0.0.1` 随机端口），无外部网络、无生产密钥、无真实模型调用。

## 契约核验与实测断言结果

| 契约项 | 核心断言内容 | 实测结果 |
|---|---|---|
| **契约 1：严格关联头透传** | 宿主生成 `corr-<32位小写hex>` 与 `1.0` 协议版本；模拟网关完整接收并保留该请求头；TCP 连接数与 HTTP 请求数严格为 1。 | **PASS**（网关收到精确值；`tcp_connections == 1`, `request_count == 1`） |
| **契约 2：单向隔离与伪造头剥离** | Worker 伪造自定义头 `X-Worker-Spoofed` 在进入上游前被彻底剥离；网关响应回显携带的 Correlation-ID 经 HostModel 重建后**未回传给 Worker**。 | **PASS**（网关未收到伪造头；Worker 响应头不含关联 ID） |
| **契约 3：撤权与前置短路** | （1）请求前已撤权任务，provider 未调用，上游连接/请求数为 0；（2）provider 回调期间并发撤权，宿主二次校验阻断，上游连接/请求数为 0，journal 未增加。 | **PASS**（两类撤权均实现：`tcp_connections == 0`, `request_count == 0`, journal 前后字节一致） |
| **契约 4：显式 Replay 逐字节幂等** | 首次成功响应与 `/v1/chat/completions/replay` 响应状态码及正文字节**逐字节一致**；replay 期间 provider 未被调用、未创建新 ticket、journal 未变、上游连接/请求数为 0。 | **PASS**（`first_body == replay_body`；`tcp_connections == 0`，journal 前后字节一致） |

## 明确结论范围
本试点验证严格限定在元星木当前源码与本地模拟网关之间的合成接口契约，不推导真实生产网关的互操作性、全系统执行隔离或不可篡改证明。
