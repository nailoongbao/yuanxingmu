# 宿主审定 Wheel 制品清单与快照机制

`yuanxingmu.wheel_store` 提供宿主专有的二进制 Python wheel 制品校验与原子发布能力。它用于解决自主 Agent 在任务执行中因动态安装依赖而面临的包投毒、版本漂移及校验到使用期间的替换风险（TOCTOU）。

## 核心设计与安全边界

1. **可信清单先于扫描存在**：
   - 宿主通过 `ExpectedWheelManifest` 预先固定所有允许安装的 wheel 文件名、确切字节大小与 SHA-256 哈希；
   - 严禁根据源目录自动生成哈希。源目录多出任何文件或缺少任何文件，均直接拒绝发布（`manifest_mismatch`）。
2. **描述符级校验与原子复制绑定**：
   - 使用带 `O_NOFOLLOW | O_DIRECTORY` 的目录描述符与 `O_NOFOLLOW` 打开普通文件，坚决拒绝符号链接（`ELOOP`）；
   - 在将数据完整复制到私有临时 staging 目录的过程中同步计算 SHA-256，并在读取完成后再次核对文件身份（inode/mtime/大小），防范读取竞态（Time-of-Check to Time-of-Use）；
   - 仅在全部制品校验成功后，通过 `os.rename` 原子发布到以清单摘要命名的目标只读目录中（`0o500` 目录，`0o400` 文件）。
3. **安全边界声明**：
   - 本机制验证“发布的字节就是宿主审定的字节”，并不证明 wheel 内部代码无恶意或依赖闭包天然完整；
   - 依赖解析、真实任务挂载（`bwrap --ro-bind <store> /wheels`）与 `--no-index` 配置由后续安装流程承载。
