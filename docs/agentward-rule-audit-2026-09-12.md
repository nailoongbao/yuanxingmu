# 玄甲三层规则对照 · 2026-09-12

这次逐项读取玄甲的输入、记忆和命令检测代码，再把危险候选作为**文本**交给元星木检查器。最初确认直接放行的 20 条候选，修正后均被阻止或转为人工核对；同组 8 条正常对照继续通过。没有执行候选危险命令，没有调用模型，也没有修改冻结攻击集。

比较对象固定为 [FIND-Lab/AgentWard `46309333bdfdbcf4701000c1dad85b33b4a0e7ef`](https://github.com/FIND-Lab/AgentWard/tree/46309333bdfdbcf4701000c1dad85b33b4a0e7ef)。这里比较实际检测类别，不把声明过但未使用的警告类型当成功能，不要求复制每条宽泛正则。

## 输入检测

对应源码：[input-sanitization.ts](https://github.com/FIND-Lab/AgentWard/blob/46309333bdfdbcf4701000c1dad85b33b4a0e7ef/layers/input-sanitization.ts)。

| 源码中的类别 | 元星木目前的行为 | 本次处理及正常对照 |
| --- | --- | --- |
| 伪造角色、轮次及模型模板 | 阻止明确的系统/用户角色标记，整段内容暂不交给模型 | 补充 `start_of_turn user`、`role HUMAN`、`System Message`、EOT/Instruction、INST 轮次及 Source/Destination 格式。单独列举模板名称仍可通过。 |
| 越狱、覆盖原指令、绕过约束 | 对明确的任务/安全约束覆盖指令给出阻止 | 补充 bypass policy/restriction、do not follow your rules、unfiltered/jailbroken 等指令。普通“充当财务分析师”、虚构角色及“不要绕过规则”的安全要求可通过。 |
| 索取凭证 | 对索取、显示或发送密码、私钥、API key 等给出阻止 | 补充 list/provide 这种明确索取。保留“列出 token 格式”“不要提供私钥”的正常对照；没有照抄对任意 token/secret 词语的判定。 |
| 要求耗尽模型资源 | 对明确要求持续生成到 token 耗尽给出阻止 | 新增直接指令及中文对应；关于配额用尽的错误说明、明确限制次数的任务可通过。 |
| 外部文字要求执行危险命令 | 命令真正进入执行入口时，命令层继续检查 | 没有复制对资料中任意危险命令描述的笼统禁令。输入层仍不识别所有自然语言命令指令；不应把这一项宣称为完整输入识别。 |
| 数组、对象中的字符串 | 现有接入负责展开工具结果，输入检查器自身接收文本 | 本次没有修改接入或声称图片、音频及任意嵌套对象都已覆盖。 |

玄甲定义了 `PROFANITY_DETECTED`，但此文件没有相应检测分支。仅出现结束符、泛指内部状态或“不是 AI”的描述，也不自动等于攻击。规则仍会漏掉改写、转述或多步组合的攻击；本次没有测量识别率。

## 记忆检测

对应源码：[cognition-protection.ts](https://github.com/FIND-Lab/AgentWard/blob/46309333bdfdbcf4701000c1dad85b33b4a0e7ef/layers/cognition-protection.ts)。

| 源码中的类别 | 元星木目前的行为 | 本次处理及正常对照 |
| --- | --- | --- |
| MEMORY、memory/、SOUL、IDENTITY、AGENTS、USER、TOOLS 的直接写入及编辑 | 既有检查覆盖文件工具、补丁及专用记忆操作 | 保留普通记忆偏好；改变长期规则的文件仍可能要求核对。 |
| 忽略旧规则、冒充角色、绕过安全要求、外传凭证 | 复用输入规则；明确投毒内容阻止写入 | 文件工具与命令写入现在使用同一组记忆投毒判断。 |
| 通过条件触发破坏、授予不受限权限 | 原先“用户问摘要时删除所有文件”“执行任意不受限命令”可通过 | 补充明确的批量毁损和自授权限指令；普通 when/if 偏好、“不要删除所有文件”的安全要求仍可通过。 |
| shell 重定向、tee、复制移动、脚本及原位编辑 | 已有规则将可能修改记忆的命令转为核对，明确投毒则阻止 | 没有把所有含文件名的只读命令当写入。任意语言、别名或间接路径仍不能靠文字规则穷尽。 |
| `dd`、下载工具指定写入记忆 | 原先 `dd of=MEMORY.md`、`curl --output`、`wget -O` 漏过记忆层 | 新增对实际输出参数的识别，内容未知时要求核对。HEAD 请求、输出到普通文件、读取记忆后另存备份均作为正常对照。 |

输出路径识别针对明确参数；远端响应决定文件名、运行时拼接路径等仍有边界。规则检查不能替代宿主只读挂载及最终执行入口的限制。

## 命令检测

对应源码：[exec-control.ts](https://github.com/FIND-Lab/AgentWard/blob/46309333bdfdbcf4701000c1dad85b33b4a0e7ef/layers/exec-control.ts)。

| 源码中的类别 | 元星木目前的行为 | 本次处理及正常对照 |
| --- | --- | --- |
| 删除系统范围、覆盖磁盘、格式化、擦除 | 既有硬规则阻止；工作目录内明确删除要求核对 | 策略没有复制“所有绝对路径删除都算系统毁损”的判定。 |
| sudo、提权、危险权限和所有权改动 | 既有硬规则阻止提权；其余权限变更要求核对 | 不把所有权限操作都自动批准。 |
| 下载后执行、eval、source、动态执行 | 已有下载/执行检查与动态内容核对 | 规则解析范围有限；不是任意 shell、脚本和程序的安全证明。 |
| 反向终端及网络连接转执行 | 既有网络重定向、终端转发及 socket 执行特征检查 | 不把所有普通 socket 连接或标准错误重定向都当反向终端。 |
| 密码、云/容器/数据库凭证、历史、环境变量 | 明确凭证路径阻止；完整环境输出要求核对 | 补充 `.gcp/credentials`、`.sh_history`、明确的隐藏凭证文件和 `export -p`、`env -0` 等导出形式。`echo $HOME`、普通历史文档、键盘映射 `.key` 文件可通过。 |
| 进程爆炸、持续填盘、大量占用内存、终止进程 | 既有填盘/进程规则；明确进程爆炸阻止，需判断范围的资源操作核对 | 补充命名函数自复制及 `fillmem`。按 shell token 判断函数定义和调用，打印攻击示例不会因此变成执行。 |
| 无停止条件循环 | 既有 while true、until false、无限 for 等核对 | 补充 `[ 1 ]`、`[[ true ]]` 等恒真条件。有限循环、逐行读取、打印循环示例可通过。 |

“要求核对”不是允许执行。实际宿主还会检查固定任务、保存本次完整候选并消费一次批准。资源规则不等于 CPU、内存或磁盘配额；当前没有这些配额保证。

## 验证范围

代码在 [`guards.py`](../yuanxingmu/guards.py)，新增 [`test_yuanxingmu_agentward_parity.py`](../tests/test_yuanxingmu_agentward_parity.py) 的 **11 项分类回归**，每组都含正常对照。受影响的 Guards、宿主检查、工具审批和 Hermes 组件共 **101 项通过、0 项跳过**，运行于 Linux/WSL 的官方 Hermes Python 环境。

这些数字是组件测试数量，不是 101 次真实模型攻击。语义提示、Broker 和工作台本次没有修改；没有进行新的官方 Agent 原生验收。Hermes 的真实暂停证据、正常误报和未完成审批路径另见[原生验证记录](../yuanxingmu/integrations/hermes/VALIDATION.zh-CN.md)。

此次读取的三个玄甲源码文件 SHA-256：

| 文件 | SHA-256 |
| --- | --- |
| input-sanitization.ts | `d12dd3e4d5e09e37532364245680fefc2581b8f7c917d8da301876540c18cce6` |
| cognition-protection.ts | `eb0829e78137cd6ea43262590510cc834b14148045b9918d74ff3877f9068765` |
| exec-control.ts | `23b817a2fd56a8a1a8a6947c336562648fb32c8c177fd84c648090fcce3e98a7` |

冻结攻击文件 SHA-256 仍为 `f97d836b3fc45b083cd5e75e6829f2cdbaca734a492c4f68b4b27e6c16e01e23`。
