# Agent Defense Check

**检查 Agent 的工具有没有接上防御，生成具体配置修改，再看接收端有没有真的收到数据。**

[English](README.md) · [验证记录](docs/verification.md)

这是一个早期本地原型。首个工作流解决一个具体的接入问题：读内部资料和向外发送分别经过两个网关连接；如果规则服务只检查各自的历史，就看不见“先读、再发送”这件完整的事。

候选修改保留两个原服务，用现成 FastMCP 把它们接到同一个原装 Invariant Gateway 后面，再按照聚合后的工具名生成一条明确支持的规则。

```text
原配置                               候选配置
客户端 → 网关 → 内部读取服务          客户端 → 网关 → FastMCP → 内部读取服务
客户端 → 网关 → 对外发送服务                                 → 对外发送服务
           两段历史                               一段受检查的历史
```

Windows 和 Ubuntu/WSL 示例里，三个危险发送从 **修复前收到 3 次，变为修复后收到 0 次**；两次改为内部发送，以及一个新的公开发送任务，仍全部收到。用的是**真实第三方运行时、两个独立假数据服务**。这能验证这条接入方式的效果，尚不能证明真实企业部署或模型攻击防御已经完成，详见[验证记录](docs/verification.md)。

另有可复跑的 [LangChain 1.4.0 接入示例](examples/langchain/README.md)：应用关闭连接后继续使用旧工具，确实出现了一次私密外发；给工具绑定任务期限后，旧工具在重连之前就被拒绝，任务内的正常改正仍能完成。已测的默认 stdio 保持连接方式原本就能拦住违规发送，不能把这件事宣传为默认配置有漏洞。

## 在 Windows 运行演示

已运行的完整演示环境是 Windows、Python 3.12，包含中文和空格路径。在仓库目录执行，先确认 `python` 指向 Python 3.12。两个环境分别安装 Gateway 和聚合组件，避免依赖冲突。

```powershell
python -m venv .venv-gateway
& .\.venv-gateway\Scripts\python.exe -m pip install -r requirements-gateway.txt .

python -m venv .venv-aggregation
& .\.venv-aggregation\Scripts\python.exe -m pip install -r requirements-aggregation.txt

$gatewayPython = (Resolve-Path .\.venv-gateway\Scripts\python.exe).Path
$aggregationPython = (Resolve-Path .\.venv-aggregation\Scripts\python.exe).Path
& $gatewayPython -m defensecheck demo --gateway-python $gatewayPython --aggregation-python $aggregationPython --output .\output\first-run
```

每次使用新的输出目录。演示会保存前后配置、规则、调用记录、接收端回执、进程观察和结果。安装后演示只使用本地假资料，不调用模型、真实邮箱或生产服务。

## 在 Linux 运行演示

公开 `v0.1.0a1` 源码包已在 Ubuntu 24.04.3 / WSL2 / Python 3.12.3 完整运行。两个新建环境的 `pip check` 均通过，6 个后端进程均由 Linux pidfd 确认退出；[结果摘要](examples/verified-linux-demo-report.json)记录了范围与安装条件。

```bash
python3.12 -m venv .venv-gateway
.venv-gateway/bin/python -m pip install -r requirements-gateway.txt .
python3.12 -m venv .venv-aggregation
.venv-aggregation/bin/python -m pip install -r requirements-aggregation.txt
.venv-gateway/bin/python -m defensecheck demo \
  --gateway-python .venv-gateway/bin/python \
  --aggregation-python .venv-aggregation/bin/python \
  --output output/first-run
```

安装后的演示也已在 [GitHub 的 Ubuntu 24.04.5 / Python 3.12.14 环境通过](https://github.com/yh-l20/agent-defense-check/actions/runs/34605839564)：危险回执同样从 3 次降为 0 次，3 次正常发送成功。[下载核验摘要](examples/verified-hosted-linux-demo-report.json)记录了实际提交与产物；手动工作流保留完整证据 30 天。

## 接入自己的配置

`inspect` 只读现有 JSON 配置，不启动命令、不调用工具、不查询线上规则，也不打印环境变量值：

```powershell
& $gatewayPython -m defensecheck inspect .\client.json --source internal:get_inbox --sink mail:send_email
```

它只会给出 `not_tested` 的静态线索。两个连接分开，还需要实际测试才能确认防御缺口。

`plan` 生成可审查的候选配置：

```powershell
& $gatewayPython -m defensecheck plan .\client.json --source internal:get_inbox --sink mail:send_email --policy .\exported-active.policy --allowed-domain ourcompany.com --aggregation-python $aggregationPython --target-project reviewed-candidate --output .\output\candidate
```

首版只支持两个 stdio 服务、已识别的 Invariant 启动格式、相同的代理选项和环境、绝对命令及工作目录，以及完整匹配的[单邮箱公司域名规则](docs/verification.md)。未知规则、额外入口、不支持的字段和无法确定的工具映射会被拒绝，不会被静默删掉。

候选包括 `client.after.json`、保留两个原下游定义的 `upstreams.json`、聚合启动器 `aggregate.py`、`policy.after.txt` 和记录输入/候选哈希的 `plan.json`。

**生成候选不等于修复完成。** `plan` 保持 `candidate_unverified`：不改原文件，不安装目标规则，不修改运行中的客户端，也无法证明导出文件包含全部线上防护。当前完整行为测试只覆盖随包提供的假数据流程，尚无通用生产部署 `verify` 命令。候选保留原环境变量值，应按原配置的敏感级别保存；摘要报告不打印这些值。

## 如何判断它有用

验收同时看危险发送和正常工作：三个危险发送都应被挡，两次改为内部发送仍应完成，一个没有读过内部资料的新任务仍可发布公开文字。已经读过内部资料的上下文发送公开文字，当前规则仍会保守阻断；这项业务代价会被记录。

接收端没有回执，本身不能说明防住了。还需要对应的成功策略检查、有效调用响应、完整的接收记录和未变化的测试文件。进程方面，“操作系统确认已经退出”与“程序完成了优雅清理”分别记录：没有 finalizer 日志，不能单独证明进程残留，也不能证明清理成功。

实际拦截由已有的 Invariant 网关和规则引擎完成，FastMCP 负责把服务接在一起。这个仓库尝试提供的价值是：从现有配置出发，给出具体修改，并证明危险操作被阻止后正常工作还能继续。相关基础防御和测试产品已有不少，参见[已有工作](README.md#where-this-fits)。

第一版还不判断真实资料读者、群组、访客、抄送或附件权限。它使用官方已有的 `analyze_pending` 接口处理这条绑定工具调用的规则，不会自动改写任意策略。重新连接却保留模型记忆、其他网络或 shell 入口、跨用户共享连接，以及长历史触及规则引擎计算上限，都需要单独处理。

可通过[集成反馈表](https://github.com/yh-l20/agent-defense-check/issues/new?template=integration-result.yml)提交安装失败、不支持的配置、防御缺口或成功接入结果。请说明版本、接收端实际收到什么，以及正常工作是否还能完成；配置只提供移除凭证后的描述，不带真实私密资料。
