# 创建时自动授权与操作记录界面验证

验证日期：2026-09-12。

本报告验证生产 HTML 和 JavaScript 在 Chromium 浏览器中的行为。全部 HTTP 请求被测试夹具拦截，未连接模型、原生 Agent 或真实发送服务；不能据此声称原生自动操作已经验收。

## 结果

| 浏览器验证 | 通过 |
| --- | ---: |
| `tests/test_yuanxingmu_automation_ui.mjs` | 50 / 50 |
| `tests/test_yuanxingmu_automatic_actions_ui.mjs` | 32 / 32 |
| 原人工操作回归：`tests/test_yuanxingmu_actions_ui.mjs` | 26 / 26 |
| 创建模型设置回归：`tests/test_yuanxingmu_judge_ui.mjs` | 18 / 18 |

合计 126 项。JavaScript 语法检查与已修改文件的差异空白检查通过。

## 已覆盖行为

- 默认不授权任何目标；不开启或没有明确选择时，创建请求不附自动授权字段。
- 通过已认证的 `GET /api/action-targets` 读取目标，只允许消息、上传和表单；最多 32 个登记目标。每个目标须明确允许接收本次工作的资料。
- 明示“通过防护检查后，本次授权范围内自动完成”。固定最多 8 次、每次最多 8192 字节、本工作共 65536 字节。
- 创建请求携带目标对应的 `binding_digest`。目标变更或移除时清除相关勾选，不能自动接受新配置。
- 网络中断后的内部重试、HTTP 结果不明后的手工重试，均复用原请求正文和幂等键。创建尚未确定时不能扩大授权范围。
- 对象刷新未完成时拒绝提交已选择的范围；退出认证、成功创建后清除选择；过时异步结果不能重新填回授权。
- 不把接收接口路径、查询参数、headers、keys 加入创建正文或渲染到目标列表；浏览器存储不保存选择和目标绑定。
- 自动操作记录显示“本次授权范围内自动执行”，单独人工确认记录显示“本人确认后执行”；缺少来源的旧记录不补造来源。
- 自动操作的执行中、提交已确认、结果不明、未开始状态均保留区别。已经消耗的自动尝试没有重发按钮。
- 操作详情的网络目标只显示 origin，完整待核对内容保持可读。手机宽度 390px 无横向溢出。

## 复现

在仓库根目录启动独立的 Playwright CLI 会话，然后分别运行以上四个文件：

```powershell
npx --yes --package @playwright/cli playwright-cli -s=yxm-automation-consent open about:blank --headed
npx --yes --package @playwright/cli playwright-cli -s=yxm-automation-consent run-code --filename=tests/test_yuanxingmu_automation_ui.mjs --raw
npx --yes --package @playwright/cli playwright-cli -s=yxm-automation-consent run-code --filename=tests/test_yuanxingmu_automatic_actions_ui.mjs --raw
npx --yes --package @playwright/cli playwright-cli -s=yxm-automation-consent run-code --filename=tests/test_yuanxingmu_actions_ui.mjs --raw
npx --yes --package @playwright/cli playwright-cli -s=yxm-automation-consent run-code --filename=tests/test_yuanxingmu_judge_ui.mjs --raw
```

前两项测试把本地截图写入 `output/playwright/automation-*.png` 和 `output/playwright/automatic-action-record-*.png`。这些是合成 API 的界面证据，不是实机功能视频。

## 本次验证的源文件 SHA-256

| 文件 | SHA-256 |
| --- | --- |
| `yuanxingmu/dashboard/web/automation.js` | `298b73316145f2dc90b0921d37aeed963edc2e0aab58c136c5d1502a89f1a4b2` |
| `yuanxingmu/dashboard/web/app.js` | `af59de713a01dcd1648895fbd9e52de9c9ed638e65cb17e085339be594099bf8` |
| `yuanxingmu/dashboard/web/index.html` | `ccfb838877776be8127b227f4def73b74da20863d3861720400ae72f46c2a1bc` |
| `yuanxingmu/dashboard/web/actions.js` | `7b07302cb2ccd7c78d4047a3f766027cbc6b4d30aa57c27b48f19e5a9a1de276` |
| `tests/test_yuanxingmu_automation_ui.mjs` | `496753e6847604e50260a813d563c931867be5f51a03ef205975a800f511bcc8` |
| `tests/test_yuanxingmu_automatic_actions_ui.mjs` | `42f2df42a395873b1078fc127461f53a8f7b7715706d4b3957a9e010948a5c3e` |
