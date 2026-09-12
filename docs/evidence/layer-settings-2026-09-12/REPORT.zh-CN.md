# 逐层模式与扫描开关组件验证

日期：2026-09-12。本记录是逐层模式和两个基础扫描开关实现后的检查点；后续功能改动须另行验证。

Linux/WSL 的以下六个相关套件 **160/160 通过，没有跳过或失败**：

```bash
PYTHONPATH=tests python3 -m unittest \
  test_yuanxingmu_guards test_yuanxingmu_guard_broker \
  test_yuanxingmu_live_settings test_yuanxingmu_dashboard \
  test_yuanxingmu_model_output test_yuanxingmu_openclaw -v
```

Windows 单独运行 `python -m unittest discover -s tests -p test_yuanxingmu_guards.py -q`：48 项，37 通过，11 项因要求 Linux 安全文件读取而跳过。

新增和补充的行为回归覆盖：

- 单层观察、显式拦截优先于全局观察、恢复继承、关闭层不伪称拦截；实际审计方式与执行一致。
- 观察输入时保留原文；审计失败仍停止；回答观察不能绕过撤权。
- 技能语义关闭后配置模型仍调用，配置认证检查、恶意技能规则、符号链接拒绝仍执行；配置扫描关闭后技能语义仍可拒绝。
- 跳过项明确记录，不把允许启动说成全部检查完成。
- 默认新字段不改变原始持久绑定，策略变化仍需要正确的主机更新；旧实例拒绝不支持的设置。
- 真实管理 HTTP 和 Unix socket 保存新模式、取消旧审批、重开后保留、暂停不解除、部分写入失败即停止。
- Workbench 管理的实例不能由 CLI 直接修改而导致配置摘要失步：明确错误发生在任何写入之前，页面仍可读取。独立实例的真实 CLI 子进程修改与重置通过。

浏览器运行真实 `protection.js`，主机 API 为内存测试对象：

| 回归脚本 | 通过项数 |
|---|---:|
| `tests/test_yuanxingmu_layer_settings_ui.mjs` | 12 |
| `tests/test_yuanxingmu_tool_review_ui.mjs` | 23 |
| `tests/test_yuanxingmu_quarantine_ui.mjs` | 37 |

通过 Playwright CLI 的 `run-code --filename` 顺序运行。新检查核对单层状态、模式优先级、两个扫描开关、重置须保存、旧实例只发送原六个设置字段，以及 390 像素宽度下的界面。检查了 `output/playwright/layer-settings-mobile.png` 与 `layer-settings-controls-mobile.png`。

这些是组件和管理流程检查。模型服务返回的是预设测试判定，没有访问真实模型、原生 Agent 会话或运行危险命令，不属于五层实机攻击验收。

首轮 137 项中的两个新增用例分别因“手动改 feature 未同步测试目录摘要”和“CLI 修改工作台实例后摘要失步”失败。前者修正为明确模拟旧实例的测试前提；后者修复为写入前拒绝 CLI 修改，增加文件不变回归后重新运行六套件得到上述 160/160。没有把首轮失败写成通过。

各模块数量、日志摘要和此检查点源码哈希见 [verification.json](verification.json)。源码哈希在验证之后采集，不声称完成了测试前后源码一致性比较。完整本地日志为 `wsl-unittest.log`；默认 Git 忽略日志文件。
