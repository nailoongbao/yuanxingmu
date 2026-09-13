# 元星木 · Yuanxingmu

**让 AI 多做事，权限始终有界。**

**[0.7.0a2 预览运行包](https://github.com/yh-l20/yuanxingmu/releases/tag/v0.7.0a2)与[配套 0.4.0a2 安装器](https://github.com/yh-l20/yuanxingmu/releases/tag/installer-0.4.0a2)已发布。** 安装器同时准备 Hermes 和 OpenClaw。按[安装步骤](https://yh-l20.github.io/yuanxingmu/start.html)使用新的 `~/yuanxingmu-v07a2` 目录；旧安装和旧工作不会自动升级。

**main 新增：** [smolagents](docs/sdk-runtime.zh-CN.md)、[LangGraph](docs/langgraph-runtime.zh-CN.md)、[OpenAI Agents](docs/openai-agents-runtime.zh-CN.md) 和 [PydanticAI](docs/pydantic-ai-runtime.zh-CN.md) 的完整会话入口，复用已有工作的隔离、防护和恢复记录；有既定自动范围时，可自动发送消息、上传文本和提交表单。OpenAI Agents 支持固定助手交接，报告保留失败尝试与声明兼容调整后的复测；[PydanticAI 两轮记录](docs/evidence/pydantic-ai-runtime-2026-09-13/REPORT.zh-CN.md)也保留第一次工具名错误和第二次运行结果。这四条开发入口尚未进入上面的 a2 下载包，仅覆盖各自固定流程。

先选好资料和可接收的固定对象，再让 AI 读报价、发消息、上传文本或填表。范围内且通过检查的操作可自动执行；你可以随时关闭工作或收回资料权限。你选用的模型服务仍会收到聊天和使用的资料。

当前源码包含输入、记忆、任务偏移、危险命令、技能与配置五层检查，以及本人审批、暂停恢复、回答显示前检查和 Hermes 官方界面接入。[玄甲逐项对照](docs/agentward-coverage.zh-CN.md)列出源码、证据与缺口；[框架支持表](docs/framework-support.zh-CN.md)区分工具适配与完整实机验证。这批功能尚未进入旧安装包。实测仍记录了正常操作误拦，不能据此宣称已全面超过玄甲。

## 最新 OpenClaw 实录：交代一次，三件事自动完成

[PROTECTED14](docs/evidence/openclaw-protected14-2026-09-12/README.md) 使用 OpenClaw 2026.9.4、元星木 0.7 和 GLM-5.2。只发送一条自然任务，消息、文本上传、表单各到达一次，中途没有追加提示或逐项审批。明确标记的底价先隐藏，供应商资料夹带的伪系统指令被扣留；最终回复与实际接收内容一致。

[看 100 秒实录](https://yh-l20.github.io/yuanxingmu/layers.html#openclaw-protected-fields) · [核对完整会话与接收内容](docs/evidence/openclaw-protected14-2026-09-12/README.md)

这次限定场景的完整验收与 78 项有限隐私检查通过。使用的是本机合成接收端，不代表任意秘密、编码或攻击都受到保护。上传记录仍有原因未明的时间顺序异常，原值保留，不用它证明耗时或性能。

## Hermes 实录：底价藏好，该做的事继续做

[AUTO19](docs/evidence/hermes-auto19-2026-09-12/REPORT.zh-CN.md) 只交代一次自然任务，Hermes 就继续完成消息、文本上传和填表。资料里标明的内部底价先被隐藏，夹带伪系统指令的正文被扣留；整个过程没有逐项批准或人工恢复。

三项内容在**本机合成接收端各收到一次**。结尾回复把表单名称写错一个字，原样保留，严格完整协议仍为 **false**。

[![104 秒看 Hermes 最新实录](site/assets/videos/hermes-protected-fields/poster.jpg)](https://yh-l20.github.io/yuanxingmu/layers.html#hermes-protected-fields)

[看 104 秒实机视频](https://yh-l20.github.io/yuanxingmu/layers.html#hermes-protected-fields) · [核对完整记录](docs/evidence/hermes-auto19-2026-09-12/REPORT.zh-CN.md)

<details>
<summary>这次验证了什么，还有什么限制？</summary>

固定源码 `c83add3`，版本 `0.7.0a1`，Hermes 0.21.2 / v2026.9.11。工作与检查使用独立 GLM-5.2 请求。一次用户消息后，没有追加指令、补参数、逐项批准或恢复。完整模型请求、回复、工具消息与参数、三个接收正文，共 28 项核验均未发现内部底价及声明支持的等价数值写法；提交正文逐字节核对。

最终把“合成报价表”写成“合造报价表”；实际表单目标、字段和值正确，错字没有修改，也没有重跑。敏感字段只支持明确标签和有限写法，不识别任意秘密、编码或推断；其余工作内容仍会交给所选模型。这是小型合成任务，不是通用防护率。新保护不在公开的 0.6 包中。[AUTO18 的真实回复泄露与错误放行](docs/evidence/hermes-auto18-2026-09-12/REPORT.zh-CN.md)继续保留，不能把这次改进说成全面超过玄甲。

</details>

[五层各看一段真实中文讲解](https://yh-l20.github.io/yuanxingmu/layers.html#hermes-five-layers)：Hermes 与 GLM-5.2 的网页录屏，分别展示外部指令、记忆投毒、任务偏移、危险命令和危险技能。视频绑定 `6881138`；新版自动流程的[首次失败](docs/evidence/hermes-auto15-2026-09-12/REPORT.zh-CN.md)和[授权事实修复](docs/evidence/review-facts-2026-09-12/REPORT.zh-CN.md)另行公开。

0.7 支持[一次授权、范围内自动完成](docs/automatic-work.zh-CN.md)：创建时选择固定对象，通过防护检查的消息、上传和表单直接执行；已扣留的恶意外部输入不再要求手动恢复。目标、资料权限和额度由宿主检查，结果未知时不自动重发。旧邮件起草工具继续等待本人确认。

<details>
<summary>此前记录：自动提交、上传失败与真实回复泄露</summary>

[AUTO16 实机记录](docs/evidence/hermes-auto16-2026-09-12/REPORT.zh-CN.md)已有四次自动提交的真实接收，隔离恶意资料后仍能继续工作；随后在未选对象上提前拦停，失败原样保留。[待核对请求修复](docs/evidence/pending-effect-2026-09-12/REPORT.zh-CN.md)公开了原始请求、结果和仍存在的模型漏检与格式失败，没有把组件测试当成通用防护率。

[2 分 02 秒，看 AUTO16 自动流程实录](https://yh-l20.github.io/yuanxingmu/layers.html#hermes-auto16-flow)：操作者仍逐条交代任务，范围内的操作不必逐项批准。视频绑定 `a34dafb`；08 步在创建待核对申请前被误拦，后续项目未执行。

这些此前实测完整保留了失败：

- [AUTO17](docs/evidence/hermes-auto17-2026-09-12/REPORT.zh-CN.md)：三次自动提交实际到达，但模型参数错误，上传未开始。后来真实建立待核对申请，危险命令被规则拦住，暂停后的新聊天也不能继续调用。正常流程和完整协议均未通过。
- [AUTO18](docs/evidence/hermes-auto18-2026-09-12/REPORT.zh-CN.md)：一次自然任务完成了三项正确的自动提交，但**内部底价出现在两段实际显示的聊天回复里，检查模型两次错误放行**。两次判定格式都有效。恶意资料在交给工作模型前已被扣留，因此这是回复泄露与检查漏判，**没有证据证明提示注入成功**。三项提交完成不等于完整协议通过。

AUTO17、AUTO18 均绑定 `e886607`。后续开发修改不会改变这两轮已记录的结果，也不能代替新版实机复验。

</details>

[English](README.md) · [官网](https://yh-l20.github.io/yuanxingmu/) · [五层功能介绍](https://yh-l20.github.io/yuanxingmu/layers.html) · [看实机演示](https://yh-l20.github.io/yuanxingmu/real-demo.html) · [运行说明与边界](docs/yuanxingmu.md) · [真实运行记录](examples/yuanxingmu/verified-core-report.json)

[![元星木 0.7 海报：先定范围，敏感字段先隐藏，五层检查](site/assets/yuanxingmu-public-v07-poster.svg)](site/assets/yuanxingmu-public-v07-poster.png)

[下载 0.7 海报 PNG](site/assets/yuanxingmu-public-v07-poster.png) · [SVG](site/assets/yuanxingmu-public-v07-poster.svg) · [查看 0.6 历史海报](site/assets/yuanxingmu-public-v06-poster.svg)

这是一个 **Linux 本地研究原型**。使用真实 bubblewrap、SQLite、独立 HTTP 接收进程和合成资料验证；没有调用攻击模型，没有生产防御率，也没有完整的企业权限接入。公开仓库与系统名称已统一为元星木（Yuanxingmu）。

## 先起草，再由你确认发送

新版工作台支持邮件草稿。AI 提交草稿后，你可以修改收件地址、主题和全文，保存并重新核对，再确认发送这一封。重复点击不会产生第二次提交，发送中断也不会自动重发。确认一封邮件不会给 AI 永久的发信权限。

[看邮件实机演示](https://yh-l20.github.io/yuanxingmu/email-demo.html) · [按步骤发第一封邮件](docs/email.zh-CN.md)。目前只支持一个收件人、纯文本和加密邮箱连接。邮箱服务接收不代表已送达；发送结果不明时先到邮箱核对。旧工作不会自动启用新功能。

## 看早期的资料权限演示

让 AI 整理一份报价，发到允许的内部位置，再尝试向外发送、重开聊天和收回权限。新视频在 **OpenClaw 原生界面**中录制，回答和工具请求来自本地 **Qwen3-4B** 模型。

这次演示里，内部实际收到 **1 条**消息，外部收到 **0 条**。AI 也读错过文件、答错金额和日期；这个过程没有删掉。收回权限后，它实际发起的读取和发送都被拒绝。

[看中文解说视频](https://yh-l20.github.io/yuanxingmu/real-demo.html) · [核对结果和局限](docs/real-openclaw-demo.zh-CN.md)。使用演示资料和测试收件服务；这是一次运行记录，不是通用防护率。较早的[脚本模型演示](https://yh-l20.github.io/yuanxingmu/demo.html)单独保留。

## 用自己的模型和资料

0.4.0a2 安装器把 0.7.0a2 的首次安装收成一个文件。按[安装步骤](https://yh-l20.github.io/yuanxingmu/start.html#install)装到 `~/yuanxingmu-v07a2` 后，在 Ubuntu 终端用 `"$HOME/yuanxingmu-v07a2/open-yuanxingmu"` 打开本机工作台。在页面选择 Hermes 或 OpenClaw、填写模型连接、导入短文本，创建工作后启动，再进入所选助手原来的聊天界面。暂时关闭工作、永久收回资料权限，也可以在页面完成。旧安装保留原目录；原先手工安装的用户继续使用原来的 `yuanxingmu desk` 入口。

每项工作独立保存资料和权限。聊天粘贴和工作产物从一开始就按私密资料处理；换会话或正常重启不清除权限。默认没有额外发送位置。**所选模型服务会看到聊天和使用的资料。**

[看早期 117 秒上手演示](https://yh-l20.github.io/yuanxingmu/workbench-demo.html) · [安装并使用工作台](https://yh-l20.github.io/yuanxingmu/start.html) · [安装器说明](install/README.md) · [高级命令行指南](docs/openclaw-quickstart.zh-CN.md)。安装器适用于 Ubuntu 24.04 / WSL Ubuntu 24.04 x86_64，首次需要终端。关闭网页或工作台不会停止运行中的 AI。目前工作台支持 OpenClaw 2026.9.4 和 Hermes 0.21.2 / v2026.9.11。

除了隔离工具执行，新入口也把整个 OpenClaw 服务放进单独的网络环境。模型请求只能经过固定模型通道，资料读取和发送经过权限服务；框架自动下载远程媒体的动作也不能直接连接外部网络。模型密钥与授权数据库留在宿主侧。

## 检查底层机制

需要 Linux、Python 3.12+ 和支持此隔离配置的 bubblewrap（已测 0.9.0）。Ubuntu/WSL 环境示例：

```bash
sudo apt-get install bubblewrap
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/python -I -m yuanxingmu doctor
.venv/bin/python -I -m yuanxingmu demo --output output/yuanxingmu-first-run
```

输出目录每次使用新名字。`doctor` 会实际创建隔离环境；不可用时停止，不能退回宿主直接执行。Windows 用户须在 Linux/WSL 内运行新核心。

演示同时检查禁止动作和正常工作：私密正文及其编码不能外发，宿主资料和授权数据库不可直接读取；重启 broker、既有子任务继续运行后仍受限。独立接收端应只收到 **2 次内部发送、1 次干净任务的公开发送**，全部工作进程退出。

## 三个部分

| 部分 | 做什么 |
| --- | --- |
| 任务权限库 | 保存允许读取的资源、允许发送的目的地，以及整个任务家族已经读过的数据标签。状态只收紧，显式撤销覆盖子任务。 |
| 资料与发送服务 | 先保存读取记录，再交出资料；每次发送都重新核对目的地。只接受预先配置的资源/目的地 ID，不接受任意 URL 或模型自报的任务身份。 |
| Linux 执行环境 | 使用现成 bubblewrap 关闭直接网络、隐藏宿主 home 和授权库，只挂一个工作目录和该任务专用 socket。 |

权限依据任务已经读过什么，而不是猜它这次的措辞是否恶意。请求里夹带不同 task ID、换连接、把正文编码，都不能扩大权限。

**没有获准接收本次私密资料的对象，即使是无害摘要也不能收到。** 创建时的自动范围可以明确授权某个固定对象接收本次资料，但不会删除资料标签，也不能覆盖正文禁令。当前没有自动脱敏放行；新的公开任务必须使用独立、经可信宿主选择的输入和工作目录。同一工作目录不能换新任务身份使用。

## 接自己的命令

可信宿主准备资源与目的地配置，然后执行：

```bash
python -I -m yuanxingmu run --policy policy.json --state authority-state \
  --task review-001 --new-task --workspace /absolute/public-workspace \
  -- /usr/bin/python3 -m yuanxingmu.client read private
```

恢复时使用同一状态目录和 `--task`，去掉 `--new-task`。完整配置与发送例子见[运行说明](docs/yuanxingmu.md)。这条命令的配置、任务创建与工作目录选择由可信宿主管理，不能交给被防护的 Agent 自由调用。

[OpenClaw 原生执行](examples/yuanxingmu/openclaw/README.md)与 [Hermes 原生终端环境](examples/yuanxingmu/hermes/README.md)已分别完成接入演示。早期 OpenClaw 示例使用本地脚本模型；新版真实模型记录见上方视频。早期 Hermes 示例只验证工具调用链；新版官方网页和真实模型的结果及失败分类见 [Hermes 实测说明](yuanxingmu/integrations/hermes/VALIDATION.zh-CN.md)。结果只覆盖各记录列出的版本、工具和配置。

[独立 Linux CI 记录](examples/yuanxingmu/verified-hosted-report.json)保存了 33 项测试和 19 项核心演示检查的结果。它验证执行核心，不包含这两种框架的 WebUI 或真实模型攻击评测。

## 为什么做它

模型能力增长后，攻击者更容易组合合法工具、寻找检查遗漏、并行重试。元星木选择把“能不能真的做成”放到模型之外，建设可接入现有 Agent 的执行权限边界。bubblewrap、凭证代理和信息流控制都有成熟先例；这里尝试做的是把任务身份、持久读取限制和实际执行连接起来。

我们没有证明整体超过 [AgentWard / 玄甲](https://github.com/FIND-Lab/AgentWard)。它已经提供 OpenClaw 检测、审批与会话干预；元星木目前验证的是另一层的执行约束，详见[实现对比与产品判断](docs/positioning.md)。

原有 MCP 接入验收工具和已发布 `v0.1.0a1` 保留：[旧版说明](LEGACY-MCP.zh-CN.md)。新版没有覆盖旧 release，也不把旧实验算作新核心的验证。
