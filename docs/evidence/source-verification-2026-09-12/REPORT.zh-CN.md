# 本地源码与安装包最终验收

验收日期：2026-09-12。结果：通过。证据对应本地工作目录的源文件哈希；不是发布版本的安全评级，也不是攻击次数或模型识别率。

| 环境 | 发现用例 | 实际通过 | 跳过 | 失败／错误 |
|---|---:|---:|---:|---:|
| Linux / WSL，Python 3.12.3 | 719 | 541 | 178 | 0 / 0 |
| Windows，Python 3.12.9 | 719 | 204 | 515 | 0 / 0 |

两边都运行全部 `unittest` 发现用例；没有跳过失败用例重算结果。Linux 的跳过项是 159 项需独立 SDK 环境的检查及 19 项需可选真实 Hermes 安装的检查。Windows 还受 Linux 文件系统/进程接口限制，并有 1 项创建符号链接权限不足。逐条用例、原因及原始输出见 [Linux 结果](linux-wsl-unittest.json)、[Windows 结果](windows-unittest.json)、[Linux 日志](linux-wsl-unittest.log)和[Windows 日志](windows-unittest.log)。

两边测试前后的 159 份源文件哈希均未变化，跨平台的源文件映射相同。随后仅随包的 Hermes 验证说明更新；首轮打包因此标记为 `source changed` 并保留[原始记录](wheel-verification.json)。冻结文件后已重建最新内容；这项文档更新没有触发与它无关的测试重跑。

最终 wheel 为 **0.5.0a1**。从新的源码副本构建，在新的隔离环境安装，从仓库外验证 `defensecheck`、`yuanxingmu` 及工作台、Hermes 初始化帮助，共 4 项命令检查。57 份 Python 源文件在源码、wheel、已安装目录中的 SHA256 全部相同；29 个随包文件全部存在、非空且与源码逐字节一致，包括 Hermes 插件 PY/YAML、Mastra MJS/JSON、OpenClaw 插件及工作台全部 9 个文件（含 `alerts.js`）。17 个已安装 JS/MJS 文件另通过语法检查。

- 本地构建文件 `final/dist/agent_defense_check-0.5.0a1-py3-none-any.whl`，SHA256：`f9dfe75b0abde8e628c3dfec0cf257fc014b20d302bac2a14800aaff5dfddec6`。此开发构建没有作为发行资产发布，也不随源码提交；它与同版本号的旧公开安装包不同。
- [最终打包记录](final/wheel-verification.json)、[安装位置和文件哈希](final/wheel-installed.json)、[Python 文件哈希](final/python-code-hashes.json)、[构建与命令日志](final/wheel-build-install.log)。
- [汇总 JSON](source-verification.json)、[最终源码清单](final/wheel-source-before.json)、[复验脚本](verify_source.py)。

此次未调用模型、未向真实第三方发送消息、未全量安装 Hermes/npm，未增加运行独立 SDK 全套或进行 GPU 编译。测试中的网络端点与模型响应为本地测试对象。此前真实 Agent/模型的证据应单独阅读，不能由本报告替代。

后台提醒文档已更新为当前 **28/28**。使用原提醒队列升级时，先停止旧工作台，再启动新版完成格式 1 → 2 的迁移；不能让新旧版本同时写同一队列。
