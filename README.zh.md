# dsh-provenance

[English](README.md) | [中文](README.zh.md)

[![npm version](https://img.shields.io/npm/v/dsh-provenance)](https://www.npmjs.com/package/dsh-provenance)
[![npm downloads](https://img.shields.io/npm/dm/dsh-provenance)](https://www.npmjs.com/package/dsh-provenance)
[![license](https://img.shields.io/npm/l/dsh-provenance)](https://github.com/Darren-Tang/dsh-provenance/blob/main/LICENSE)
[![dsh-plugin](https://img.shields.io/badge/dsh-plugin-DeepSeek%20Harness-4f46e5)](https://github.com/deepseek-ai/deepseek-harness)

**你在 GitHub 上看到的源码，不一定是你安装的那个包。**

面向 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) 插件的供应链装前预检工具。
它回答了一个当前生态里所有扫描器都没问过的问题。

![dsh-provenance 演示](assets/demo.gif)

现有的插件扫描器读的是已经落在你磁盘上的文件，问的是"这段代码有没有干坏事"。这个问题有用，但它不是第一个该问的问题。第一个问题是：

> **这段代码，是作者给我看的那段代码吗？**

npm 的 tarball 是发布者上传的任何东西。registry 不会替你从仓库构建它，也没有任何机制强制两者一致。一个发布者完全可以往 GitHub 推干净的源码，攒够 star 和好评，然后往 tarball 里多塞一个文件再发布。所有在 `dsh plugin add` **之后**才运行的扫描器，都会把这个被注入的文件当成正常代码扫一遍——而那时候，包的安装钩子早就跑完了。

`dsh-provenance` 在安装**之前**运行，交叉比对三个独立的真相来源：npm registry、上游仓库、以及真实传输的字节内容。

---

## 它检查什么

| 检查项 | 回答的问题 |
| --- | --- |
| **来源锚定** | 这个安装源指向的是不可变内容，还是可能在同名下发生变化？ |
| **Registry 完整性** | 我们收到的字节，和 registry 公布的摘要一致吗？ |
| **安装钩子** | 代码会不会在 `dsh plugin add` 执行期间就跑起来，早于任何装后扫描？ |
| **构建溯源** | 有没有 SLSA attestation 把这个构建产物绑定到具体的 commit 和 CI 工作流？ |
| **产物与源码比对** | 发布的文件真的对应那个 commit 吗？有没有东西是发布时才加进去的？ |

### 为什么"是否锚定"比看起来更重要

```
some-plugin@1.2.3          锚定      已发布的 npm 版本不可变
some-plugin@^1.2.3         未锚定    下次安装可能解析到别的版本
github:owner/repo          未锚定    默认分支可以在同名下被改写
github:owner/repo#v1.0.0   未锚定    tag 可以被仓库所有者移动
github:owner/repo#<sha>    锚定      commit sha 无法伪造
```

浮动的 git 引用比浮动的 npm 版本范围更危险。npm 的情况下，你审过的版本永远保持字节不变；git 分支的情况下，**你审查过的代码和你安装的代码可能悄无声息地不是同一份**，而插件目录里到处都是 `github:owner/repo` 这种安装指令。

---

## 安装

作为 dsh 插件：

```sh
dsh plugin --profile web add dsh-provenance
```

作为独立 CLI（不需要装 dsh，适合放进 CI）：

```sh
npm install -g dsh-provenance
```

需要 Node.js 22.19+。**零运行时依赖**——一个用来审查不可信包的工具，不该自己再拖一条供应链。

---

## 使用

### 装之前先跑

```sh
dsh-provenance preflight some-plugin@1.2.3
dsh-provenance preflight github:owner/repo
dsh-provenance preflight some-plugin --json      # 供 CI 使用
```

### 在 dsh 里用

注册了两个工具，agent 自己就能调用：

- `provenance_preflight` —— 装之前审查安装源
- `provenance_verify` —— 检查某个 profile 里已经装了什么

### 审查已经装了的东西

```sh
dsh-provenance verify --profile web
```

完全本地运行：不联网、不执行任何插件代码。报告哪些已装插件是锚定的、哪些还能追溯到上游、哪些携带了已经执行过的安装钩子。

### CI

```sh
dsh-provenance preflight some-plugin@1.2.3 --strict
```

退出码：`0` ok/notice，`1` review（需要 `--strict`），`2` block。

---

## 安装拦截

dsh 的 agent 能执行 shell 命令，这意味着**agent 本身也可能被诱导去安装插件**——通过一份被投毒的 README、agent 抓取到的网页，或者一条精心构造的 issue 评论。只审查人类手动输入的内容，会漏掉这条路径。

所以安装尝试会被拦截，除非该来源在本次会话里已经通过预检：

```
dsh-provenance: refusing to install evil-plugin without a supply-chain preflight.
Installing runs the package's install hooks immediately, so this cannot be checked
afterwards. Call provenance_preflight with source="evil-plugin" first, then retry.
```

如果这个拦截影响到你，可以用 `{ guardInstalls: false }` 关闭。

实现说明：这里用的是 `ctx.tools.guard()` 而不是 `tools/pre-execute` 事件，因为 `guard` 的签名是明确文档化的（`(execution) => string | undefined`，同步），而且它的拒绝是**单调的**——后面任何插件都无法把这次拒绝翻回许可。guard 读取的是 `execution.arguments`，这是流水线视图真实暴露的字段名；生态里一个类似的工具读了 `exec.args`，结果哨兵连续两个版本都没生效过。

---

## 这个工具不做什么

明确写出来，因为夸大安全工具的能力范围本身就是一种伤害：

- **不验证 sigstore 签名链。** attestation 载荷只做了解析，没做密码学验证。要做这个请跑 `npm audit signatures`。每份报告都会诚实说明这一点。
- **无法验证构建产物。** `lib/`、`dist/` 和被压缩过的文件永远被标记为 `unverifiable`，绝不会标成 `match`。要验证它们需要复现构建过程。
- **一份"干净"的报告不代表安全。** 它只代表这些规则没有发现问题。
- **这不是代码扫描器。** 它检查的是*代码从哪来*，不是代码*做了什么*。请搭配行为扫描器一起用，两者回答的是不同问题。
- **这不是运行时账本。** 它不去观察或记录插件安装之后做了什么——那是"审计日志"意义上的 provenance，不是"供应链"意义上的 provenance。本工具在安装*之前*运行并拒绝，而不是在事后运行并记录。

### 它拒绝出现的那种失败模式

如果一个文件都没能跟仓库对上，报告**不会**显示一个看起来让人安心的 `0 mismatch`。它会触发 `diff.nothing-verified`，明确说这次比对什么都没验证到。一个把"我没法检查这个"悄悄算成"这个没问题"的工具，比没有工具还糟——因为它把证据缺失包装成了虚假的安全感。

---

## 安全属性

审查不可信的包，这件事本身就有风险。每份报告都携带一个 `guarantees` 区块，断言以下几点：

- **被审查的包永远不会被执行。** 不会调用任何包管理器，所以审查过程本身不会触发任何安装钩子。
- **不会往磁盘写任何东西。** 归档文件完全在内存里解析，这从结构上就消除了 zip-slip、符号链接逃逸和磁盘耗尽，而不是靠防御规则去堵。
- **网络出口有白名单**，只允许 `registry.npmjs.org`、`codeload.github.com`、`api.github.com`。这一点很关键：恶意包能完全控制自己 `repository.url` 字段的内容，如果没有固定的 host 白名单，扫描器本身就会变成打进运营者内网的 SSRF 跳板。字面 IP、内嵌凭据、非默认端口、跳出白名单的重定向，全部会被拒绝。
- **处处设限。** 响应体大小、gzip 解压输出、归档条目数、单条目大小都有硬上限，一个归档文件不可能撑爆内存。
- **凭据只从环境变量读取。** `GITHUB_TOKEN` 是可选的，只用来提高匿名请求的速率上限，永远不会被记录或持久化。

---

## 架构

```
src/core/     零框架依赖 —— 核心引擎，全量单测覆盖
src/index.ts  薄的 dsh 适配层
src/cli.ts    独立 CLI
```

dsh v0.1 是开发者预览版，官方明确说明未来会有破坏性变更。所以供应链核心逻辑被特意与 harness 接口隔离开：dsh 接口变了，理论上只需要重写这一薄层适配代码，CLI 完全不受影响。

## 开发

```sh
npm install
npm test              # 先编译核心，再跑全部测试
npm run typecheck     # 只检查核心，不需要 dsh 的 peer 依赖
npm run build         # 完整构建，需要 dsh 的 peer 包
```

测试用的是真实的 gzip 字节、真实的 tar 头部结构、以及官方文档给出的真实字段名，而不是可能和实现共享同一个错误假设的 mock。

在 dsh 源码 checkout 里做本地开发：

```sh
npm run build
# 先把 cordis.yml 里的路径改成绝对路径
pnpm dsh web --patch /absolute/path/to/dsh-provenance/cordis.yml
```

## 许可证

MIT
