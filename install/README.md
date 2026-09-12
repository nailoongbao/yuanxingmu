# 元星木安装器预览版

把首次安装收成一个入口。装好以后，运行 `~/yuanxingmu-mail/open-yuanxingmu`，在网页中选择资料、连接自己的模型，再进入 OpenClaw 聊天。

[面向使用者的图文步骤](https://yh-l20.github.io/yuanxingmu/start.html) · [117 秒真实模型演示](https://yh-l20.github.io/yuanxingmu/workbench-demo.html)

安装器 `0.2.0a1` 固定安装已发布的元星木 `0.5.0a1`、Node.js `24.16.0` 和 OpenClaw `2026.9.4`。新版支持 AI 起草、本人核对并确认邮件。请安装到新的目录；它不会升级、接管或替换旧安装及旧工作的权限记录。旧版继续使用原来的启动入口。

当前源码还提供 Hermes 的开发安装与验证入口。**默认发行下载仍是上述 OpenClaw 版本**；已发布的 `0.5.0a1` wheel 没有 Hermes 接入，不能用它验证当前源码的新功能。Hermes 的正式发行 wheel 与下载记录尚未切换。

## 适用电脑

Ubuntu 24.04 或 WSL Ubuntu 24.04，x86_64，系统 `/usr/bin/python3` 3.12+，至少 2 GB 可用空间。安装器不负责安装 WSL。首次安装需要联网下载运行组件；模型地址、模型名称和密钥由使用者在工作台填写。

将发行页下载的 `yuanxingmu-installer-0.2.0a1.pyz` 放入 Ubuntu 家目录后，在 Ubuntu 终端运行：

```bash
/usr/bin/python3 -I ~/yuanxingmu-installer-0.2.0a1.pyz --install-root ~/yuanxingmu-mail --system-deps
```

`--system-deps` 会在需要时通过系统 `sudo` 安装 bubblewrap、CA 证书与 AppArmor，并为 `/opt/yuanxingmu/bin/bwrap` 设置专用 AppArmor 配置。可能询问 Ubuntu 密码；不会关闭系统的全局用户命名空间限制。已有完整隔离环境可以省略这个参数。

上面的命令安装到新的 `~/yuanxingmu-mail`。如果这个位置已经有旧安装或工作，请使用 `--install-root ~/另一个新目录`。不指定参数时仍默认使用 `~/yuanxingmu`，但不会接管已有旧版本。不支持 `/mnt/c`、符号链接位置或其他用户的目录。无需自行运行 pip、git 或 npm。

## 日常打开

```bash
~/yuanxingmu-mail/open-yuanxingmu
```

工作台会尝试打开浏览器，也会在终端显示完整的本机管理链接。自动打开失败时，复制链接到自己的浏览器。终端需保持运行。先在页面点击“暂时关闭”，再退出终端；关掉网页或管理终端不会停止已经运行的 AI。

Linux 应用菜单入口只在没有同名入口时创建，可用 `--no-shortcut` 省略。WSL 是否显示该菜单取决于桌面环境，终端启动始终可用。原先手工安装的环境继续使用原来的入口。

## 中断与检查

安装中断后重新运行同一安装器。它仅恢复自己创建、没有工作资料的未完成安装；重试前核对已完成组件。已有完整安装只做检查，不覆盖运行版本、聊天、资料或权限记录。文件改变或原目录被复制后会停止，不会自动接管。

`INSTALLATION.json`、下载文件和 `install-logs/` 留在私有安装目录。请保留报错的目录以便排查。不要公开工作台管理链接、模型密钥或整份工作目录。

## 构建和验证

```bash
# 发布构建只读取已提交的固定源文件，并写入 source_commit。
/usr/bin/python3 install/build_zipapp.py --output /tmp/yuanxingmu-installer.pyz

# 验证用构建可读取未提交改动；其 manifest 明确标记不可发布。
/usr/bin/python3 install/build_zipapp.py --dev --output /tmp/yuanxingmu-installer-dev.pyz

python3 -m unittest discover -s tests -p 'test_yuanxingmu_installer.py' -v
```

`pins.json` 保存官方 wheel、Node archive 的大小与 SHA256，以及 OpenClaw 包和 npm lock 的绑定。下载或本地缓存均须校验后使用；解压拒绝越界路径。执行 npm 前会将完整 Node 文件树与原 archive 比对，包括文件内容和链接。

OpenClaw 使用内置的精确 npm lock 执行 `npm ci`；生命周期脚本正常启用，运行在安装用户权限下。npm 的 HOME、缓存和配置单独设置，但这不是安装脚本沙箱。启动器每次核对安装记录、全部 Python 程序文件、Node 二进制、OpenClaw 的两个入口文件和隔离组件；它不声称逐一验证所有已安装 npm 依赖文件。

`smoke_install.py` 只接受还没有工作台的新安装。它启动实际安装的工作台，创建一项合成工作，检查原生 OpenClaw 网页、重复启动拒绝、关闭后重开、资料权限撤回和停止；同时核对邮件功能已经安装、新工作的草稿列表为空、尚未设置发件邮箱。最后保留记录并关闭自己创建的服务。它不做模型推理或发送消息。`.github/workflows/installer.yml` 在原生 Ubuntu 24.04 上运行这套安装与验收，另在 WSL 实机验证。单元测试明确区分真实文件/进程检查与替代的网络/npm操作。

## Hermes 开发安装

只用于当前源码的本机验收，需要 Ubuntu / WSL Ubuntu 24.04、系统 Python 3.12 或 3.13，建议留出至少 4 GB 空间。它使用单独的 `hermes/env`，不使用或修改电脑上已有的 Hermes、Python 虚拟环境或 OpenClaw 安装。

| 组件 | 固定输入 |
| --- | --- |
| Hermes | 官方 `v2026.9.11`，包版本 `0.21.2`，提交 `939e45c91d751fadd94dcd1b873ac3cb44846213` |
| Python 依赖 | 官方 `uv.lock`，只启用 `web`，使用 `uv sync --frozen`；另运行依赖一致性检查 |
| Python 安装工具 | `uv 0.12.13` 的官方 wheel，固定大小与 SHA256 |
| 构建环境 | `setuptools 83.0.0`、`wheel 0.48.0`、`packaging 26.0` |
| 网页和终端 | 官方根 `package-lock.json`，只安装 `web`、`ui-tui` workspace，构建原生页面和终端入口 |
| Hermes 专用 npm | `11.17.0`，固定官方归档大小与 SHA256；Hermes 上游不接受 Node 24.16.0 自带的 npm 11.13.0 |

先从当前源码构建本地 wheel。下面的构建环境属于开发者，`python -m build` 需要提前安装 Python 的 `build` 工具；安装器本身仍不要求用户手动运行 pip 或 npm。

```bash
python -m build --wheel --outdir /tmp/yuanxingmu-dev-wheels
sha256sum /tmp/yuanxingmu-dev-wheels/agent_defense_check-0.5.0a1-py3-none-any.whl
/usr/bin/python3 install/build_zipapp.py --dev --output /tmp/yuanxingmu-hermes-dev.pyz

/usr/bin/python3 -I /tmp/yuanxingmu-hermes-dev.pyz \
  --install-root ~/yuanxingmu-hermes-dev \
  --development-wheel /tmp/yuanxingmu-dev-wheels/agent_defense_check-0.5.0a1-py3-none-any.whl \
  --development-wheel-sha256 <上一步输出的完整小写SHA256> \
  --no-shortcut
```

两个开发参数必须成对提供。安装前核对传入 SHA256、wheel 元数据中的发行名称/版本、Python 包版本和 Hermes 模块。wheel 版本必须等于本安装器的 `RUNTIME`；开发输入的文件名、大小、SHA256 和版本写入私有安装记录。相同版本号的开发 wheel 与已发布 wheel 是不同的文件，不能相互替换。

开发输入只允许用于新目录，或恢复使用同一输入、还没有工作资料的未完成开发安装。**已有完整目录不能用开发参数覆盖**，即使传入同一个 wheel 也会拒绝。检查已完成安装时省略开发参数；中途失败不会重装已完成的 OpenClaw。没有标记的目录、其他版本目录和用户原有环境都不会被接管。

Hermes、uv 和专用 npm 下载均核对固定大小与 SHA256。Hermes 源码和 npm 归档在解压前检查全部成员，拒绝链接、路径越界、重复路径和特殊文件。uv 和 npm 使用本次目录里的 HOME、配置、缓存和临时文件，不继承模型密钥；构建脚本仍以当前用户身份运行，这不是安装脚本沙箱。

完成后，工作台启动入口会传入已记录的 `hermes/env/bin/python` 与 `hermes/source`，同时检查两个框架的实际隔离环境。安装记录覆盖 Hermes 源码、编译产物和独立 Python 环境的普通文件；只允许虚拟环境标准的 `lib64 -> lib` 链接。Hermes 的 `node_modules` 构建依赖不在日常启动校验范围内，终端入口由官方构建脚本打包为独立文件。`hermes/SOURCE.json` 保存上游身份、锁文件哈希、构建工具版本与 Python 版本。

在尚未打开过工作台的新安装上验证两个原生页面：

```bash
/usr/bin/python3 -I install/smoke_install.py \
  --install-root ~/yuanxingmu-hermes-dev --framework both \
  --report /tmp/yuanxingmu-hermes-acceptance.json

/usr/bin/python3 -I install/check_reuse.py \
  --install-root ~/yuanxingmu-hermes-dev \
  --installer /tmp/yuanxingmu-hermes-dev.pyz
```

验收分别创建两个合成工作，检查实际原生网页 HTTP 响应、停止、管理入口重开、原生网页重开、撤权和最终停止。临时模型入口只记录意外请求并拒绝执行；通过标准要求它收到零次请求。不启动真实模型，不发送邮件或其他外部消息。这是安装与网页启停验证，不是模型防御效果或浏览器交互的完整验证。

[2026-09-12 本机验证记录](evidence/hermes-installer-2026-09-12.json)：安装器定向回归 48/48，两个原生页面及启停验收 28/28，模型入口收到 0 次请求。新开发安装和已有公开发行安装的重复检查均保留原来的资料、权限及运行文件。此次从新任务目录开始，在修正 uv 参数、npm 版本和 uv 锁文件权限后续装完成；没有再次用最终安装器从另一个空目录重跑全量构建。

正式发行切换时，维护者需要将程序版本、安装器/启动器版本常量、`pins.json` 的 wheel 名称/大小/SHA256/URL/源码提交一起更新，再将 `runtime_features` 改为 `["hermes"]`。CI 的实际安装验收也需要启用 `--framework both`。在这些步骤完成前，默认发布配置保留 `runtime_features: []`，不把旧发行 wheel 当作 Hermes 新版。

[新版邮件实机演示](https://yh-l20.github.io/yuanxingmu/email-demo.html) 展示模型起草、工作台核对与确认发送。原有 117 秒视频和旧安装器发行继续保留；它们展示旧版的资料读取与权限撤回。上述演示均不是本安装器的安装过程录像。
