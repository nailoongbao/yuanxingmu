# 包管理器显式改源复核

命令检查现在会对识别到的包管理器来源覆盖返回 `review / package_source_override`。例如，`pip install -i https://packages.example.invalid/simple demo` 以前仅得到 `command_rule_clear`，现在需要核对来源与制品。HTTPS 或私有镜像本身不代表恶意，也不证明依赖可信。

规则用于实际候选命令的 `check_command`，不把外部文档中的普通安装说明自动判为提示词注入。在命令层启用且采用干预模式时，`review` 进入现有复核流程；若宿主选择观察模式或关闭该层，则不会强制暂停。

## 第一版范围

- 直接调用 `pip`、带数字版本的 `pip3` / `pip3.12` 及对应 `.exe` 时，识别 `-i`、`--index-url`、`--extra-index-url`、`--trusted-host`，以及指向 HTTP(S) 的 `-f` / `--find-links`。
- `npm`、`npm.cmd`、`npm.exe` 的 `--registry`。
- 支持上述参数的分离形式、长参数等号形式、`-iURL` / `-fURL`；沿用现有的有限包装命令和 shell 解析。不解析所有包管理器选项或混合短参数簇。
- 打印出来的命令示例、`--` 后的参数数据不触发此规则。已有更严重的阻断仍优先；`python -m pip` 保留现有的程序执行复核。

本地 `--no-index --find-links=/workspace/wheels` 不因这项规则进入改源复核，但仍须通过其他适用的授权和检查。它不是已审核依赖的证明。

## 与依赖安装强制策略的区别

本规则不解析环境变量、`pip.conf`、`.npmrc`、requirements 文件、配置修改命令、默认源、间接脚本或完整依赖图，也不下载、哈希校验或批准任何包。`command_rule_clear` 仅表示没有匹配到现有命令风险规则。

更完整的离线安装能力需要专门的可信宿主接口：宿主选择经过审核的制品清单与固定安装目标，验证实际使用的字节和哈希，控制配置来源、依赖解析及安装脚本，并在受限环境中执行。Worker 可以改写自身环境变量，因此 `PIP_NO_INDEX` / `PIP_FIND_LINKS` 不能单独作为不可覆盖的权限边界。网络命名空间限制直接联网；可连接的宿主 Unix socket 仍依赖各自的授权，不能据此宣称所有外部作用都已消失。

此变更只提供命令复核信号。现有 runtime `0.7.0a2` / installer `0.4.0a2` 固定下载文件尚未包含该规则。
