# 在 OpenClaw 中接入自己的模型与私有资料

把几段本地业务资料放心地交给 AI 整理，并在你熟悉的 OpenClaw 原生聊天窗口里查看结果。元星木为这次工作建立一个独立实例，默认没有对外发送资料的接收位置。

**你选择的模型会看到聊天内容和它读取的资料。** 使用云端模型时，这些内容会发送给该模型服务。这里的“默认不能发送”指不能另外发往未配置的接收位置，不包括完成聊天所需的模型请求。已读到的内容与过去完成的发送无法撤回。

本项目目前处于开源安全研究预览阶段，首次初始化需要借助终端命令行。本文以标准的 **Ubuntu 24.04 / WSL Ubuntu 24.04、x86_64 架构** 环境为例，串联系统 Python 3.12+、Node.js 24.16.0、OpenClaw 2026.9.4 以及 bubblewrap 0.9.0 内核沙箱。其他系统架构需自行验证；一旦沙箱隔离或安全自检未通过，系统宁可报错中止，也绝不会妥协退回到宿主机裸跑。

[官网快速上手页](https://yh-l20.github.io/yuanxingmu/start.html) · [底层运行机制与安全边界深度剖析](yuanxingmu.md)

## 1. 在独立目录中极速安装与自检

Windows 用户请先在 PowerShell 中一键安装 WSL2 运行环境：

```powershell
wsl --install -d Ubuntu-24.04
```

跟随屏幕引导完成初始化，打开全新的 **Ubuntu 24.04** 终端窗口。后续的所有命令均在该 Linux 终端中敲入。若你本身就是 Linux 用户或已有就绪的 WSL 环境，直接往下走即可。建议将整个工作目录置于 Linux 用户根目录 `~` 下。

一段一段执行，某段报错时先处理错误。以下目录用于首次安装；已经装好后，直接看[日常打开与关闭](#日常打开与关闭)。

安装核心系统依赖与沙箱工具：

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv git curl xz-utils ca-certificates bubblewrap
/usr/bin/python3 --version
bwrap --version
```

请确认 Python 版本不低于 3.12。bubblewrap 已通过测试的基线版本为 0.9.0，具体能否在你的系统内核中正常创建用户命名空间，后续会有专属的 `doctor` 医生命令为你严密体检。

下载 Node.js 运行时至专用工具目录：

```bash
YXM_DIR="$HOME/yuanxingmu"
mkdir -p "$YXM_DIR/tools" "$YXM_DIR/openclaw" "$YXM_DIR/inputs"
cd "$YXM_DIR/tools"
curl --fail --location --output node-v24.16.0-linux-x64.tar.xz \
  https://nodejs.org/dist/v24.16.0/node-v24.16.0-linux-x64.tar.xz
curl --fail --location --output SHASUMS256.txt \
  https://nodejs.org/dist/v24.16.0/SHASUMS256.txt
sha256sum --check --ignore-missing SHASUMS256.txt
tar -xJf node-v24.16.0-linux-x64.tar.xz
export PATH="$YXM_DIR/tools/node-v24.16.0-linux-x64/bin:$PATH"
node --version
```

终端应明确输出 `OK` 校验通过，且 Node 版本显示为 `v24.16.0`。注意此安装包专为 Linux x86_64 架构打包；ARM / Apple Silicon 架构需下载对应的 ARM 构建包。

拉取元星木源码并安装专属版本的 OpenClaw：

```bash
git clone https://github.com/yh-l20/yuanxingmu.git "$YXM_DIR/yuanxingmu"
/usr/bin/python3 -m venv "$YXM_DIR/.venv"
"$YXM_DIR/.venv/bin/python" -m pip install "$YXM_DIR/yuanxingmu"
npm install --prefix "$YXM_DIR/openclaw" openclaw@2026.9.4
"$YXM_DIR/.venv/bin/python" -I -m yuanxingmu doctor --bwrap /usr/bin/bwrap
```

看到 `"available": true` 后继续。这项自检说明本机基础隔离探测通过；首次启动时，系统还会全面核验配置项、底层运行文件与 OpenClaw 服务的正常响应。注意：这并不代表所有模型与所有电脑都已通过验证。

这套 OpenClaw 严格局限并安装在 `~/yuanxingmu/openclaw/node_modules/openclaw` 路径中。后续所有的运行脚本都会精确绑定该物理路径，你无需手动执行 `openclaw onboard`，更不会污染或串改你本机全局的既有 OpenClaw 配置。

## 2. 准备第一份练习资料

先随手在本地生成一份干净的示范业务文本：

```bash
cat > "$YXM_DIR/inputs/quote.txt" <<'EOF'
项目：春季客户活动（练习资料）
场地：6000 元
物料：2800 元
摄影：1200 元
备注：报价仅供内部讨论，尚未确认供应商。
EOF
```

你也可以换成自己的真实文档。当前版本严格支持 **UTF-8 纯文本（.txt / .md），单文件容量上限为 256 KiB**；暂不支持直接喂入 PDF、Word、Excel 或图片。初次上手，强烈建议先用简短的几行文字建立直观认知。

在创建沙盒实例的瞬间，系统会将文件快照物理拷贝进隔离区。后续你在外部宿主机上修改原文件，绝不会隐式篡改已运行沙盒中的上下文。如果资料内容大改，请创建全新的隔离任务；当前架构不支持在已有沙盒内热插拔追加资料。

## 3. 对接自己的大模型并创建独立任务

请准备好支持 **Function Calling（工具调用）** 的 OpenAI 兼容接口，以及服务商提供的具体模型代号。接口 URL 通常以 `/v1` 结尾（使用的是标准的 Chat Completions 协议），普通网页版的打字账号不能直接当 API 用。

公网商业服务必须走安全 HTTPS 协议。本地自建服务（如 Ollama、vLLM、LM Studio 等）可直接填写 `http://127.0.0.1:1234/v1` 等本地地址，但务必确保该端口在 Linux / WSL 环境下可顺畅连通。

执行以下交互命令，根据提示依次填入接口地址与模型名称；若连接 HTTPS 云端接口，终端会进一步安全提示输入 API 密钥（输入过程自动静默遮蔽，不会在屏幕上泄露）：

```bash
read -r -p "模型接口地址（通常以 /v1 结尾）：" YXM_MODEL_URL
read -r -p "模型名称：" YXM_MODEL_ID
"$YXM_DIR/.venv/bin/python" -I -m yuanxingmu openclaw init \
  --profile "$YXM_DIR/profiles/first-chat" \
  --model-url "$YXM_MODEL_URL" \
  --model-id "$YXM_MODEL_ID" \
  --document "quote=$YXM_DIR/inputs/quote.txt" \
  --node "$YXM_DIR/tools/node-v24.16.0-linux-x64/bin/node" \
  --openclaw-package "$YXM_DIR/openclaw/node_modules/openclaw" \
  --bwrap /usr/bin/bwrap
```

终端回显 `"status": "created"`，即代表沙盒任务实例已成功建档！

参数中的 `--profile` 指定了这个实例自己的目录。首次创建时，该目录必须不存在；不要预先创建 `first-chat`。它会保存资料副本、聊天、配置和权限状态，请保留它以便继续原来的工作。需要另一项工作时，使用另一个新的目录名。

`quote` 是在后续对话中可以直接指代这份资料的标签代号。如需一次性喂入多份参考资料，多次追加 `--document` 参数即可（例如 `--document "notes=/绝对路径/notes.txt"`）。在不显式传入 `--destinations` 的情况下，系统默认不会开放任何对外网络发送端点。

### 想要静默传入密钥？巧用环境变量

如果你在自动化脚本或无交互终端中运行，可使用 `--api-key-env YXM_MODEL_KEY` 参数，告知程序读取指定的系统环境变量名（传入的是**环境变量名称**本身，而不是明文密钥）。

例如，先在当前终端安全导出临时变量，再调起初始化命令：

```bash
read -r -s -p "模型 API 密钥：" YXM_MODEL_KEY
printf '\n'
export YXM_MODEL_KEY
```

创建成功后可运行 `unset YXM_MODEL_KEY` 取消当前 shell 中的变量。实例由宿主侧保存本地使用的配置文件，没有挂载给沙盒中的 OpenClaw，不会要求你每次打开时重新输入。

## 4. 唤起 OpenClaw 原生交互界面

```bash
"$YXM_DIR/.venv/bin/python" -I -m yuanxingmu openclaw start \
  --profile "$YXM_DIR/profiles/first-chat"
```

拉起成功后，控制台会打印出专属于该任务的 **`dashboard_url`**。复制并粘贴到浏览器中打开，默认监听在本地 `127.0.0.1:18911` 回环地址。该链接附带专属的本地访问令牌，仅供你自己管理使用。

进入 OpenClaw 熟悉的对话界面，发出你的第一道指令：

> 请阅读 quote 资料，逐项列出其中的三个费用项目，帮我算出总计费用，并提示我还有什么重要事项尚未确认。请直接在对话中回复。

根据前面的练习数据，三项费用相加应精准等于 **10,000 元**，且需要指出“供应商尚未最终敲定”。在界面中，你能清晰看到工具调用的执行痕迹以及大模型的结构化回答。若模型未调用工具或算错数据，请分别核查模型自身的逻辑能力或提示词；聊天窗口里的自我陈述绝不能替代底层的实际操作记录。

你可以继续吩咐它“提炼为三句话”或“排版为 Markdown 表格”。整个体验完全在原生聊天窗口中完成，无需配置繁琐的外部机器人、Webhook 或复杂的企业应用。

## 日常打开与关闭

在新打开的 Linux 终端中，重新设置安装目录变量，再启动原来的实例：

```bash
YXM_DIR="$HOME/yuanxingmu"
"$YXM_DIR/.venv/bin/python" -I -m yuanxingmu openclaw start \
  --profile "$YXM_DIR/profiles/first-chat"
```

随时巡检当前沙盒的健康状态：

```bash
"$YXM_DIR/.venv/bin/python" -I -m yuanxingmu openclaw status \
  --profile "$YXM_DIR/profiles/first-chat"
```

优雅停止当前服务及其关联的正在运行的子命令：

```bash
"$YXM_DIR/.venv/bin/python" -I -m yuanxingmu openclaw stop \
  --profile "$YXM_DIR/profiles/first-chat"
```

**停止服务后随时可原样唤醒，你的资料、历史会话以及权限状态均稳稳完好如初。** 请切记：仅关闭浏览器网页标签页并不会自动杀掉后台常驻的计算服务。

## 在聊天气泡中快速查看安全水位

在已登录且具备管理特权的 OpenClaw 对话框中，敲入斜杠命令 `/yuanxingmu`（无需任何多余参数）。系统会立刻向你呈现全景安全摘要：直观展示五层防御处于“关闭”、“仅监控记录”还是“硬性拦截”模式，并汇报当前任务是否处于挂起状态、数据权限是否曾被永久销权。

若界面显示“未确认”，代表系统暂时未能抓取到可信的核验快照，切勿主观视作防御正常。若环境审计提示配置发生更迭，需在下次启动时重新触发核验；仅仅在页面上拨动开关并不等于底层已完成重验。

如需调整防御深度或处置挂起异常，回到可视化工作台在对应任务卡片中点开“防护记录”处理即可。出于安全防范考量，聊天快捷命令仅告知操作路径，绝不在聊天框中裸露带敏感 Token 的管理链接。

## 永久吊销该沙盒实例的全部权限

当某项特定涉密业务已彻底办结、你不希望 AI 实例未来以任何形式再触碰或外发这批资料时，可在终端中执行：

```bash
"$YXM_DIR/.venv/bin/python" -I -m yuanxingmu openclaw revoke \
  --profile "$YXM_DIR/profiles/first-chat"
```

或者直接在 OpenClaw 聊天框中输入 `/yuanxingmu-revoke`。

**这是一项不可逆的铁律操作，当前版本没有提供撤销后的“后悔药”命令！** 一旦吊销，该实例后续所有试图通过元星木调阅或外发资料的请求将被底层永久封杀，哪怕重新打开会话也绝无可能解封。它不会删除 AI 在过去会话中已阅读过的知识记忆，无法撤回过去早已发出的外部数据，也不会强行打断本地无关的纯计算流。如需彻底关停服务，请配套执行 `stop` 命令。

| 你的当前意向 | 对应的规范命令 | 之后能否继续唤醒原任务？ |
| --- | --- | --- |
| **今天先告一段落** | `stop` | **完全可以**，之后随时 `start` 原样继续 |
| **看一眼沙盒是否健康、权限是否完好** | `status` | 仅作只读巡检，绝不改动任何既有状态 |
| **彻底封死该任务，严防长尾泄密** | `revoke` | **不可恢复**；资料读取与外发通道将被永久熔断 |

## 常见疑难排障速查指南

| 常见报错或现象 | 背后原因与处置建议 |
| --- | --- |
| **`doctor` 自检返回 `"available": false`** | 先看输出的 `reason` 说明。请确认是在 Linux / WSL2 环境下使用系统原生的 Python 与 bubblewrap；若机器内核严格限制了非特权用户命名空间，需联系宿主管理员放行或更换标准 Linux 环境。切勿跳过这项检查。 |
| **提示仅支持 OpenClaw 2026.9.4** | 请核对 `--openclaw-package` 参数是否精准指向了本次安装在专用目录下的独立依赖包，避免串用到全局安装的其他不兼容版本。 |
| **提示任务目录已包含内容（目录冲突）** | 已经创建好的老任务请直接执行 `start`；若是创建全新工作，请换一个全新的目录名。如果先前曾发生初始化意外中断，残留的损坏目录切勿直接复用，换个新路径重新建档即可。 |
| **大模型报错 401、404 或死活不调工具** | 请逐项核查 API Key、以 `/v1` 结尾的请求地址、模型精确代号，以及该模型本身是否原生支持 Chat Completions 规范下的 Function Calling 工具调用。 |
| **提示本地端口被占用** | 在创建另一个新实例时可加 `--port 18912` 等自定义端口；使用启动输出中的新链接。 |
| **模型报错提示内容太长** | 大模型的上下文窗口容量有限。请换用更短的文本重新创建实例；文件大小限制不代表模型一定能一次处理全部内容。 |
| **启动异常超时或闪退** | 请直接翻阅实例目录下的 `supervisor.log` 与 `gateway.stderr.log`。切不可把闪退状态盲目当作“已处于安全防护中”。 |
| **状态显示 `interrupted` 或 `unconfirmed`** | 说明上次服务遭遇了外部断电或强制杀进程，底层清理流程尚未确认收尾。请妥善保留运行日志与 `lifecycle.json` 现场，排查真实的孤儿进程；切勿暴力删除 SQLite 权限数据库来蒙混过关。 |
| **提示配置、文件校验或运行版本发生变动** | 任务实例在创建时严格固化了所有的运行副本与哈希指纹。切勿手动编辑内部的受保护配置文件或偷换底层执行文件；当前版本不支持原地篡改代码的热升级。 |

需要说明的是，当前向外扩展的通信机制专为开发者预留的**受控结构化 JSON Webhook** 打造，现阶段并未封装针对飞书、企业微信、Slack 等第三方商业 SaaS 的复杂应用连接器。日常在聊天窗口中从容完成受控的资料提炼与分析即可。如需深入定制底层策略与网络规则，欢迎查阅完整的 [架构运行说明手册](yuanxingmu.md)。
