# 暂停与恢复独立回归：2026-09-12

本轮通过 **10 项 Broker / Workbench HTTP 测试和 37 项浏览器断言**。没有运行模型、原生 Agent、待审批命令或实际桌面通知。

## Broker 与 Workbench HTTP

运行：`python3 -B -m unittest discover -s tests -p test_yuanxingmu_quarantine_broker.py -v`。

[测试文件](../tests/test_yuanxingmu_quarantine_broker.py) 使用真实 Unix socket、SQLite 状态和 localhost Workbench HTTP 服务。防护判定由明确命名的 `QuarantineGuardFixture` 提供；Workbench 的运行时就绪检查是既有测试 fixture，不启动 OpenClaw。

已覆盖：

- 子任务发现阻断原因后，整个任务族暂停，独立根任务保持可用。
- Worker 不能查询或恢复暂停；子任务的 host socket 也不能恢复整个任务族。
- 恢复必须使用当前 epoch、incident ID 和明确确认词；旧状态、伪造任务、重复恢复均被拒绝。
- 暂停作废未使用工具许可、邮件草稿和操作提案；恢复后原记录不能再次执行。
- 暂停写入失败时 Broker 进入存储故障状态，停止后续操作，拒绝恢复并保留 dirty marker。
- 故障后重启为全部原有根任务建立持久暂停；主机只能逐任务族恢复，资料标签保留。
- 正常重启仍保留已有暂停及原 incident。
- 仅观察的判定和单次人工审批不会擅自变成整个任务族暂停；永久撤销不能通过恢复解除。
- close 的目录 fsync 失败后释放进程锁，保留或重建 marker，重开必须暂停；对旧对象再次 close 不能删除新实例的 marker。
- 真实 HTTP 恢复检查登录凭证、Origin、字段类型、最新 incident；同一请求 key 只产生一次恢复审计。
- 真实 HTTP 能观察存储故障重启形成的暂停，并在正确主机确认后恢复。

Broker 用例禁止 TCP 连接。HTTP 用例仅允许当前测试 Workbench 的 localhost 端口与临时 profile 的 host socket，并拒绝模型和外部连接、外部 DNS；没有越界网络尝试。

## 浏览器暂停与恢复

运行：`playwright-cli -s=quarantine-check run-code --filename tests/test_yuanxingmu_quarantine_ui.mjs`。

[测试文件](../tests/test_yuanxingmu_quarantine_ui.mjs) 加载真实 `protection.js` 和 `styles.css`，API 与 Notification 使用明确的浏览器 fixture。没有真实通知弹出，也没有浏览器到真实 Broker 的恢复操作。实际 HTTP 恢复由上一组测试独立验证。

37 项断言检查全部未处理原因展示、最新 incident 对齐、缺失/错配/重复/截断记录禁恢复、撤销与存储故障、明确勾选、并发新 incident 不替换已审查状态、未知结果只查询原请求、组件重建不重复 POST、浏览器存储失败时不提交，以及授权重置清空显示。

通知检查确认只在用户点击按钮后申请权限，同一 epoch 只提醒一次，新 epoch 可再次提醒；标题和正文不含任务名或原因内容，永久撤销的任务不触发通知。此处用测试 Notification 类记录调用，不能据此声称真实浏览器或操作系统必定送达通知。

测试发现并推动修复了长串无空格原因撑出移动端弹窗的问题。最终普通段落和完整命令均能换行，390 px 页面及实际弹窗宽度断言通过。桌面和移动端截图已目检；最终控制台 0 错误、0 警告，测试浏览器会话已关闭。

暂停只能阻止后续授权，不能撤回已消费许可或证明已开始的外部操作已经停止。上述测试不构成模型攻击识别率或完整进程隔离验证。
