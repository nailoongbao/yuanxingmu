# Contributing to Yuanxingmu / 参与元星木开发

Changes that help an agent finish authorized work while preventing a concrete unwanted action are especially useful. Small fixes, clearer setup steps and reproducible failures are welcome too.

最有用的改动，是让 AI 顺利完成已授权的工作，同时阻止一种具体的越权行为。安装问题、清楚的使用说明和可复现的失败也值得提交。

## Explain the result / 说明实际变化

- Describe what the user does, what happens today, and what your change makes happen. A feature name alone does not explain the behavior.
- For a defense change, include an allowed task and the unwanted action it addresses. Check the actual file, receiver or recorded operation; an agent saying “done” is not sufficient evidence.
- Run checks appropriate to the changed behavior. State the platform and dependency versions, and distinguish passed, skipped and unexecuted checks. Documentation changes normally need link and factual checks, not a new model run.
- Use synthetic data and controlled local receivers for examples. Keep credentials, management links and private machine configuration out of commits, screenshots, logs and recordings.

请说明用户如何触发问题、改动后的实际行为，以及如何验证。防护改动应同时检查正常任务和要阻止的操作；以真实文件、接收端或执行记录为准，不能只看 AI 的成功回复。只运行与改动相称的检查，并分别列出通过、跳过和未执行项。示例使用合成资料与本机接收端，避免提交密钥、管理链接或私人配置。

## Keep descriptions accurate / 文案与实现一致

- Use the button names and options that actually exist in the interface.
- Preserve the difference between software isolation and physical isolation, private file permissions and encryption, task pause and process termination, or server acceptance and final delivery.
- Do not turn a false positive, leak, incomplete task or skipped check into a success by rewriting its description. Existing recordings and failure evidence keep their original results; a later fix gets a separate result.
- A successful test establishes that case on the recorded versions. It does not establish an attack prevention rate, arbitrary framework support or superiority over another product.

按钮名称、数据保存方式和操作状态须与代码一致。权限限制不是加密，任务暂停不等于所有进程已停止，接收服务确认也不等于最终送达。不要通过改写文字，把误拦、泄露或未完成的步骤变成成功。修复后的新结果另行记录，保留旧失败；单个样本不能扩大为通用防御率或全面超过其他项目的结论。

## Useful starting points / 从这里开始

- [Framework support and its current scope](docs/framework-support.zh-CN.md)
- [Automatic work within a chosen scope](docs/automatic-work.zh-CN.md)
- [Protected fields and their limits](docs/protected-fields.zh-CN.md)
- [Feature comparison and evidence](docs/agentward-coverage.zh-CN.md)

Keep a PR focused on one behavior or one documentation topic. If a change depends on an unreleased package, say so and keep download instructions consistent with the actual release.

一份 PR 尽量处理一个行为或一个文档主题。功能依赖尚未发布的安装包时，请明确说明，并让下载步骤与真实发行状态一致。
