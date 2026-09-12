# 工具审批回归记录：2026-09-12

本轮通过 11 项真实 Broker 回归和 23 项浏览器界面断言。两组测试没有调用模型，也没有执行待审批命令。它们验证审批边界、一次许可和界面行为，不代表模型攻击识别率或完整 Agent 对话验收。

## 真实 Broker：11 项

运行 `python3 -B -m unittest discover -s tests -p test_yuanxingmu_tool_review_broker.py -v`，Linux / WSL，11 项通过。测试使用真实持久化 Broker、Authority 和 Unix socket；裁判由明确标记的 `SwitchingGuardFixture` 提供受控结果。

- Worker socket 不能查看审批列表或详情，不能允许或拒绝；伪造 host 字段被拒绝。
- 主机决定需要正确的确认词和操作摘要；等待状态查询不消耗许可。
- 四个并发连接共 32 次领取，只有一次获得许可，只有一次消费审计记录。
- 领取响应丢失后，原许可仍不可再次领取。
- 命令、工作目录、标准输入、工具名称、来源、附加参数、摘要或任务变化不能复用许可。
- 同一调用身份更换参数返回冲突，不再次询问裁判。
- 等待、已允许、已拒绝、已消费和已过期记录不会借助后续裁判的允许重新进入执行；最初的 block 同样保持终态。
- 决定和领取时均检查过期。
- 真实关闭并重开 Broker 后，等待及已允许许可失效。
- 撤销父任务后，后代任务不能继续申请、被审批或领取许可。

源码：[test_yuanxingmu_tool_review_broker.py](../tests/test_yuanxingmu_tool_review_broker.py)。

## 浏览器审批界面：23 项

运行 `playwright-cli -s=tool-review-check run-code --filename tests/test_yuanxingmu_tool_review_ui.mjs`，23 项断言通过，控制台 0 个错误、0 个警告。

测试加载真实 `protection.js` 和 `styles.css`，使用浏览器路由提供受控页面与 API fixture；没有真实审批服务或命令执行。浏览器 origin 下的 `sessionStorage` 正常启用，其他请求被阻止。

- 必须勾选核对框；完整显示命令、cwd 和 stdin；命令里的 HTML 作为文字呈现。
- 缺失参数、错误记录 ID、非法摘要、已撤销任务及 block 记录不出现可用的批准按钮。
- 首次批准响应丢失后，刷新和组件重建都保留原请求；只能查询原 key，不重复 POST。
- 浏览器只保存请求身份，不保存命令正文。
- 已批准显示为等待领取的许可，不表示命令已执行成功。
- 确定的 HTTP 拒绝不会卡在未接受的请求上；重新决定必须重新勾选核对。
- 本地请求身份存储失败时不会先发送批准；恢复后没有残留的未提交请求。
- 防护开关设置使用同样的原请求查询流程，不因未知结果重复写入。
- 390 px 宽度下页面和实际命令文本块都无横向溢出；桌面和移动端截图已目检。
- 授权重置清空命令展示。

源码：[test_yuanxingmu_tool_review_ui.mjs](../tests/test_yuanxingmu_tool_review_ui.mjs)。

## 操作对象设置补充回归

`test_yuanxingmu_targets_ui.mjs` 本轮 43 项断言通过，控制台 0 个错误、0 个警告。新增检查确认对象 ID 上限为 64、首字符为字母或数字，与主机 `_name` 相符；名称长度保持 128。通过 DOM 直接塞入超长 ID 仍在 POST 前拒绝。这同样是浏览器 API fixture，不能替代实际 Workbench 服务验收。

审批和对象设置的测试浏览器会话均已关闭。
