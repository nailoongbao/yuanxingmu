# 经用户核对的邮件：实现边界与测试

这份说明面向开发者，描述邮件功能的源码边界。某个发布版本是否包含它，以该版本的文件和验收记录为准。真实模型在 OpenClaw 原生界面中的邮件演示需要另行验收；下列测试不等于已经完成这项演示，也不证明模型能抵御所有攻击。

AI 只能调用 `yuanxingmu_prepare_email` 提出收件人、主题和正文。插件通过该任务固定的 `broker.sock` 保存草稿，没有批准或发送邮件的工具。用户在元星木工作台核对发件账户、收件人、主题和全文后，工作台通过宿主的 `review.sock` 确认具体草稿。后者不挂载进 Gateway 或 worker；工作台管理 API 另外检查访问凭证、Host、Origin 和操作字段。

功能必须在建立工作时启用：`init_profile(..., reviewed_mail=True)` 写入 `reviewed_email_v1`，Broker 使用 `reviewed_mail=True`，插件配置使用 `reviewedMail: true`。缺少标记的旧 profile 不会自动获得该工具或修改原来的权限记录。新的工作台工作可以启用邮件核对；已有工作需要保留，不能靠手改旧配置绕过校验。

邮件范围固定为一个明确的 ASCII 邮箱、一份纯文本正文，没有附件、HTML 内容类型、CC、BCC 或额外收件人。主题最多 200 个 Unicode 字符，正文规范化为 LF 后最多 64 KiB UTF-8；正文允许 LF 和 TAB，拒绝其他控制字符。服务端负责完整校验，插件的参数 schema 和快速检查不能替代它。邮箱域名转小写，local part 保留；草稿摘要绑定规范化后的三个字段。

发件服务器、端口、用户名、密码或授权码、发件地址来自可信宿主的 `MailAccount`，不接受模型工具参数覆盖。工作台将账户保存在宿主私有的 `catalog.json`，目录和文件受本机权限检查，密码不通过读取账户 API 返回，也不进入 Gateway 挂载、模型参数或审计事件。这里是受文件权限保护的本地保存，没有实现密钥链或静态加密；宿主及同一系统用户下的可信进程仍能读取它。用户选择的模型服务仍会接收对话及模型使用的资料。

生产传输只使用 `smtplib.SMTP_SSL`，验证证书链和服务器名称，TLS 至少为 1.2。没有明文 SMTP、STARTTLS 降级或关闭证书验证的账户选项。MIME 使用 `text/plain; charset=utf-8`；解码后的正文 UTF-8 字节与批准的正文一致，包括末尾是否有换行。信封和邮件头都只有批准的一个收件人。

确认时校验任务、草稿 ID、版本、摘要和账户版本。发送前先在 SQLite 持久化唯一 attempt，再进行一次 `sendmail`。同一草稿换 HTTP 操作标识、重复点击或重新连接，都不会创建第二次发送。插件重试同一个 session key 与 tool call ID 会复用草稿请求键；新的工具调用可能建立新草稿，仍需重新人工核对。稳定的 Message-ID 只用于关联，不提供 SMTP 去重保证。

| 状态 | 含义和允许的后续操作 |
| --- | --- |
| `pending` | 草稿待核对，可以编辑、取消或明确确认。编辑会更新版本和摘要。 |
| `cancelled` | 草稿已取消，不会被重复确认重新发送。 |
| `sending` | attempt 已保存，结果尚未记录。不能再次提交发送。 |
| `acknowledged` | SMTP 服务端已明确接收 DATA，不代表投递到收件箱或已被阅读。 |
| `unconfirmed` | 连接开始后的失败，或中断后不能确认的结果。可能已经提交，不自动重发。 |
| `not_started` | 传输在建立 SMTP 连接之前失败。这次确认仍已消耗 attempt，不可重放或直接编辑后再次发送。 |

Broker 独占状态目录，并持有同一把锁直到发送结果处理结束。撤权先取得锁，则拒绝后续发送；发送先取得锁，撤权等待该次尝试结束。撤权不能撤回已经提交的邮件。结果保存失败时保留 `sending`；新 Broker 确认旧进程不再拥有目录后，把遗留 attempt 恢复为 `unconfirmed`，不会重发。单封邮件的人工确认不清除 `private` 标签，不扩大原来的普通发送授权。

审计只记录草稿标识、摘要、版本、状态等元数据，不记录主题、正文、邮箱地址、账户凭据或 SMTP 回复文本。草稿全文单独保存在宿主私有数据库中，供用户核对。未知的 worker 操作名也不能原样进入审计字段。

可从仓库根目录运行这些检查；Linux、系统 Python 3.12+、Node、可用的 bubblewrap，以及用于生成临时测试证书的 OpenSSL 对相应测试是必要条件。跳过某项环境测试不等于通过。

```bash
python3 -B -m unittest discover -s tests -p 'test_yuanxingmu_mail*.py' -v
python3 -B -m unittest discover -s tests -p 'test_yuanxingmu_dashboard.py' -v
node --test tests/test_yuanxingmu_openclaw_mail_tools.mjs
```

- [传输测试](../tests/test_yuanxingmu_mail_transport.py)：参数和证书检查，以及真实本机 TLS SMTP 的唯一信封、原文字节、断连不重试、服务器回复脱敏。它不向公网发送邮件，不使用用户账户。
- [草稿状态测试](../tests/test_yuanxingmu_mail_drafts.py)：真实 SQLite 的任务绑定、编辑版本、单次 attempt、恢复和审计。
- [Broker 集成测试](../tests/test_yuanxingmu_mail_broker.py)：真实 Unix socket、并发撤权、重复确认、结果保存失败与恢复。其中一项通过 Broker 发送到本机 TLS SMTP，仅替换信任 CA；另一项使用真实 `gateway_command` 挂载和 bubblewrap namespace，运行 Python 探针，证明能提交草稿但看不到、连不上宿主 `review.sock`。该探针没有运行 OpenClaw 或模型。
- [插件执行测试](../tests/test_yuanxingmu_openclaw_mail_tools.mjs)：真实 Node 执行插件注册及工具函数，通过本机 Unix socket 核对字段、请求键与各状态说明；Broker 回复是明确的测试替身。配套 Python 入口会让普通 `unittest discover` 包含这一组检查。
- [工作台测试](../tests/test_yuanxingmu_dashboard.py)：本机 HTTP 管理接口的鉴权、账户版本、正文变更、重复发送、未知结果及撤权处理；运行环境由测试 fixture 提供。

原生验收应另存模型与 OpenClaw 版本、原生工具调用、用户核对画面及独立 SMTP 收件记录，确认批准前没有发送、批准后只提交一份相符正文、重复确认和重启不多发。没有这些证据时，不把上述单元或集成测试描述为完整的原生模型邮件演示。
