# 元星木安装器预览版

把首次安装收成一个入口。装好以后，运行 `~/yuanxingmu-mail/open-yuanxingmu`，在网页中选择资料、连接自己的模型，再进入 OpenClaw 聊天。

[面向使用者的图文步骤](https://yh-l20.github.io/agent-defense-check/start.html) · [117 秒真实模型演示](https://yh-l20.github.io/agent-defense-check/workbench-demo.html)

安装器 `0.2.0a1` 固定安装已发布的元星木 `0.5.0a1`、Node.js `24.16.0` 和 OpenClaw `2026.9.4`。新版支持 AI 起草、本人核对并确认邮件。请安装到新的目录；它不会升级、接管或替换旧安装及旧工作的权限记录。旧版继续使用原来的启动入口。

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

[新版邮件实机演示](https://yh-l20.github.io/agent-defense-check/email-demo.html) 展示模型起草、工作台核对与确认发送。原有 117 秒视频和旧安装器发行继续保留；它们展示旧版的资料读取与权限撤回。上述演示均不是本安装器的安装过程录像。
