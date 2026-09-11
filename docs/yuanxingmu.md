# 元星木运行说明

元星木让程序在 Linux 隔离环境里执行，把资料读取、发送和任务授权留在可信宿主。当前是单机研究原型，使用 SQLite 和现成 bubblewrap；没有自研沙箱或内核。

## 运行合成演示

```bash
python -m yuanxingmu doctor
python -m yuanxingmu demo --output output/first-yuanxingmu-run
```

需要 Linux、Python 3.12+、支持 `--disable-userns` 与 `--as-pid-1` 的 bubblewrap。已测 Ubuntu 24.04 / WSL2 / Python 3.12.3 / bubblewrap 0.9.0。自选安装位置时附加 `--bwrap /absolute/path/to/bwrap`。`doctor` 真正尝试隔离；失败时排查宿主支持条件，不会无隔离执行。

演示只用临时合成资料和本机独立接收进程。输出包括 `results.json`、接收端 `receiver.jsonl`、授权库和 broker 事件。`results.json` 记录实际工作进程、返回值、正常业务代价、收件内容和执行源码哈希；失败保留 `incomplete` 或 `failed`。

当前[公开运行摘要](../examples/yuanxingmu/verified-core-report.json)提供限定环境的结果，不能换算成真实攻击模型防御率。

## 配置自己的任务

由可信操作人员创建 `policy.json`。资源是固定文件，目的地是固定服务；工作程序只能使用名字：

```json
{
  "resources": {
    "private": {"path": "/srv/task-input/private.txt", "labels": ["company"]},
    "public": {"path": "/srv/task-input/public.txt", "labels": []}
  },
  "destinations": {
    "internal": {"url": "https://internal.example/receive", "labels": ["company"]},
    "public": {"url": "https://public.example/receive", "labels": []}
  }
}
```

示例域名须替换为自己的获准接收服务。HTTPS 为正常服务配置；只有字面量回环 IP 允许 HTTP，供合成测试使用。请求为 `POST`，JSON 正文包含 `request_id` 和 `body`。不跟随重定向，不读取宿主代理环境变量，不允许工作程序改 URL。

如服务确实需要认证，可由可信宿主在目的地加入 `headers` 字典。它只在 broker 中使用，不返回给 worker。当前没有连接真实企业凭证系统；生产使用需要自己的密钥管理、权限来源和轮换方案。配置文件及授权目录必须处于工作区之外。

启动时，工作区应只包含经过可信宿主确认可向任务提供的资料。私密资料应经资源接口读取，不能提前复制到工作区却把它标成公开：

```bash
python -m yuanxingmu run --policy policy.json --state /srv/yuanxingmu/state \
  --task review-001 --new-task --workspace /srv/yuanxingmu/public-work \
  -- /usr/bin/python3 -m yuanxingmu.client read private
```

后续继续此任务，去掉 `--new-task`：

```bash
python -m yuanxingmu run --policy policy.json --state /srv/yuanxingmu/state \
  --task review-001 --workspace /srv/yuanxingmu/public-work \
  -- /usr/bin/python3 -m yuanxingmu.client send internal --body 'internal summary'
```

工作程序也能用 Python 客户端：

```python
from yuanxingmu.client import request

document = request("read", resource="private")
if document["allowed"]:
    result = request("send", destination="internal", body=document["content"])
```

所有连接都由单个、预先绑定身份的 Unix socket 代表同一任务。请求不得包含 task ID、任意 URL 或自行声明的标签。`allowed` 表示授权判断；只有 `outcome: acknowledged` 表示服务返回成功状态。`unknown` / `unconfirmed` 表示发送可能已被对方接收，不能据此断言没有副作用，也不能盲目重试。

## 持久状态与子任务

每次读取先提交标签，再返回字节。标签在整个根任务家族内累积：父任务、已有兄弟任务以及随后创建的子任务都受相同限制。子任务可用资源和目的地只能是父任务子集。

可信宿主可通过 `Broker.delegate` 创建子任务，通过 `Broker.revoke` 显式撤销某任务及其后代；不提供让模型创建全新根任务或清空标签的 RPC。当前没有自动期限到期、审批放行或自动脱敏。普通命令退出不等于任务撤销，便于同任务恢复。

状态目录绑定资源内容哈希和目的地配置。恢复时发现配置或资料改变会停止，不会新建一个“干净”身份。当前还没有安全策略迁移/资源版本更新工具，应保留旧状态并由可信操作方明确安排新任务。

`run` 持久记录工作目录归属。不能把同一目录或其父子目录改绑到其他任务。自行复制含私密数据的工作区、对话历史或结果给新根任务，必须由可信宿主保留对应限制；当前不提供跨机器的数据来源追踪。

## 已建立的执行边界

- 独立网络、进程、用户、挂载等 namespace；丢弃 capabilities，关闭额外 user namespace 创建。
- 只读 Linux 运行时目录、新 `/proc` 与 `/dev`、临时目录、一个可写工作目录及一个指定 socket；不挂宿主 home、整个 root 或授权库。
- 清空父环境，只注入明确允许的设置。工作进程可改自己的环境，但不能由此重新获得宿主网络或凭证。
- 任务主进程退出或被取消后，PID namespace 内后台进程被回收；相关测试使用 Linux pidfd 确认进程实例退出。
- 同一状态目录只有一个 broker 持有进程锁，读取提交和发送全过程串行协调。已获准发送尚未结束时，另一请求不能先取得私密字节。

目录选择、只读挂载、配置和宿主启动入口仍是可信操作。`yuanxingmu.worker` 是供受信任框架适配器启动沙箱的入口，不能当成可以自由指定宿主路径的 Agent 工具。

## 当前覆盖之外

| 边界 | 当前限制 |
| --- | --- |
| 模型 API、浏览器、宿主工具、Slack/邮箱等渠道 | 只有真正进入此执行环境或受控 broker 的动作受保护。宿主直接执行的其他工具仍须接入；框架运行结果单独报告。 |
| 任务 stdout 和本地工作成果 | 返回给启动它的可信宿主/操作人员；宿主继续把这些内容发送到模型或外部服务，需要相同信息权限约束。 |
| 初始工作区和只读运行时 | 由宿主确认可提供给该任务。不能含绕过读取标签机制的私密文件、敏感硬链接或宿主子挂载。 |
| 内核、资源耗尽、侧信道 | 与宿主共享内核；未设置 CPU、内存、磁盘配额，没有内核漏洞/微架构侧信道保证。 |
| 业务权限来源 | 标签和允许目的地由操作人员配置；未连接企业目录、文档 ACL 或跨用户授权。 |
| 脱敏与公共摘要 | 私密读取后保守限制整个任务，正常公共摘要也会被拦。未实现自动解密级或可信摘要器。 |
| 多机与高可用 | 单机、单 broker；没有分布式事务、可靠重试、恰好一次发送或在线迁移。 |

## 验证

```bash
python -m unittest discover -s tests -p 'test_yuanxingmu*.py' -v
```

可用 `YUANXINGMU_TEST_BWRAP` 指定测试用 bubblewrap。Windows 的权限库测试仍可运行，真实 broker/沙箱测试明确跳过。发布工作流先执行 `doctor`，防止把“不支持所以跳过”当作 Linux 隔离成功。
