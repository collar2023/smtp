# SMTP — 端到端加密邮驿 (smtp.aillm.net)

> 基于经典 **RFC 5321 SMTP** 协议状态机并叠加自定义 **X-CIPHER** 扩展的零知识、端到端加密（E2EE）密件投递与中转系统。
> 采用 **X25519 ECDH** 密钥协商与 **AES-GCM-256** 认证加密算法，部署于轻量级无服务器架构 **Cloudflare Workers** + **D1** SQL 数据库 + **KV** 名录，并配备了复古“纸墨报版”风格的单页面 Web 界面（SPA）。

---

## 目录

1. [这是什么](#这是什么)
2. [架构总览](#架构总览)
3. [E2EE 加密模型](#e2ee-加密模型)
4. [RFC 5321 SMTP 状态机](#rfc-5321-smtp-状态机)
5. [安全与威胁模型](#安全与威胁模型)
6. [使用方式](#使用方式)
7. [HTTP API 参考](#http-api-参考)
8. [部署指南](#部署指南)
9. [CLI 客户端](#cli-客户端)
10. [限制与已知折衷](#限制与已知折衷)
11. [开发与测试](#开发与测试)
12. [许可证](#许可证)

---

## 这是什么

**应用场景**：你和朋友都是开发者，希望能够互发端到端加密的便签或短信，但不想依赖那些将私钥托管在服务器上的中心化邮件或即时通讯服务（如 ProtonMail、Gmail 等）。

**技术方案**：自行托管的 Cloudflare Worker，收件箱中仅存储密文。每封邮件通过 **X25519 ECDH** 派生出共享密钥，并在本地通过 **AES-GCM-256** 完成加密。私钥永远保留在用户的浏览器本地或 CLI 中，服务器只接触到密文、公开的元数据和公钥。

**核心特点**：
* ✅ **真正的端到端加密 (E2EE)**：服务器从未接触明文，也无权访问用户私钥。从数学原理上杜绝了服务端解密邮件的可能。
* ✅ **解耦的协议状态机**：在 Worker 内部实现了一个完全独立、经过充分单元测试的经典 RFC 5321 SMTP 状态机，致敬 1982 年的网络协议设计美学。
* ✅ **轻量架构**：单一 Worker 文件，一个用于存储密文的 D1 SQLite 数据库，一个用于存储公钥名录的 KV 空间，并预留了 R2 存储桶用于未来的文件附件。
* ✅ **用户自管密钥**：私钥一旦丢失，数据将永久无法恢复。本系统不提供任何“重置密码”或备份找回机制（这是安全特性，而非缺陷）。

---

## 架构总览

```
┌─────────────────────────────────────────────────────────┐
│ 浏览器 SPA (smtp.aillm.net)                            │
│  ┌────────────┬────────────┬────────────┐               │
│  │ 收件箱     │ 撰写       │ 我的密钥   │               │
│  │ (本地解密) │ (本地加密) │ (X25519)   │               │
│  └─────┬──────┴─────┬──────┴─────┬──────┘               │
│        │ HTTPS API  │            │                      │
└────────┼────────────┼────────────┼──────────────────────┘
         │            │            │
         ▼            ▼            ▼
┌─────────────────────────────────────────────────────────┐
│ Cloudflare Worker (smtp.aillm.net)                      │
│ ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│ │ /api/inbox   │  │ /api/send    │  │ /api/key/*   │  │
│ │ GET 收件箱   │  │ POST 存密文  │  │ 公钥目录     │  │
│ └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
│        │                 │                 │           │
│        │   ┌─────────────┴─────────────┐   │           │
│        │   │  src/smtp-state-machine.js │   │           │
│        │   │  RFC 5321 纯逻辑状态机     │   │           │
│        │   │  14/14 单测通过            │   │           │
│        │   └────────────────────────────┘   │           │
└────────┼──────────────────┼─────────────────┼──────────┘
         │                  │                 │
         ▼                  ▼                 ▼
    ┌─────────┐       ┌──────────┐       ┌──────────┐
    │ D1      │       │ KV       │       │ R2       │
    │ SQLite  │       │ 公钥名录 │       │ (预留)   │
    │ 密文    │       │ 缓存     │       │ 附件     │
    └─────────┘       └──────────┘       └──────────┘


CLI 客户端 (smtp-cli.js, Node 18+)
  - 命令：keygen / send / list / read
  - 调用相同的 HTTPS API 端点
  - 私钥保存在本地 ~/.smtp-aillm/x25519.json (权限 600)
```

### 加密与递送数据流 (Alice 发信给 Bob)

1. **公钥发现**：Alice 通过 `/api/key/:fp` 接口拉取 Bob 的 X25519 公钥（44位 base64 字符），或由 Bob 线下直接提供。
2. **本地撰写**：Alice 输入明文（如 `主题="秘密会议"`, `正文="明天下午2点复盘"`）。
3. **本地加密**：
   - Alice 从浏览器本地存储加载自己的 X25519 私钥 `alice_sk`。
   - 派生共享密钥：`shared_secret = X25519_ECDH(alice_sk, bob_pk)`。
   - 随机生成两个安全防重放的 12 字节初始向量 (IV)：`iv_subject` 和 `iv_body`。
   - 分别加密：
     * `subject_ct = AES-GCM-256(shared_secret, iv_subject, subject)`
     * `body_ct = AES-GCM-256(shared_secret, iv_body, body)`
   - 立即清空内存中的共享密钥缓冲区 (`shared_secret.fill(0)`)。
4. **提交密文**：Alice 发送 `POST /api/send`，上传 Bob 的公钥指纹、自己的公钥 `from_pk`、密文及 IV。
5. **Worker 存储**：Cloudflare Worker 将数据持久化到 D1 数据库：
   `INSERT INTO mail (..., from_pk, subject_ct, body_ct, subject_iv, body_iv)`
6. **收信与解密**：Bob 发起 `GET /api/inbox` 并附带 `X-Auth: bob_fp` 验证。Worker 返回信件列表，其中包含 Alice 的公钥 `from_pk`。Bob 在本地使用其私钥 `bob_sk` 与 `alice_pk` 计算共享密钥并解密主题和正文。

---

## E2EE 加密模型

端到端加密算法完全基于浏览器和 Node.js 原生的 Web Crypto API 运行。

### 数学原理 (ECDH + AES-GCM)

$$\text{共享密钥} = \text{ECDH}(\text{自身私钥}, \text{对方公钥})$$

$$\text{密文} = \text{AES-GCM-256}(\text{共享密钥}, \text{随机 IV}, \text{明文})$$

得益于 Diffie-Hellman 密钥交换协议的数学对称性：
$$\text{ECDH}(\text{alice\_sk}, \text{bob\_pk}) \equiv \text{ECDH}(\text{bob\_sk}, \text{alice\_pk})$$

Alice 和 Bob 无需直接传递密钥，即可安全生成相同的 32 字节对称密钥。而中间人或服务器即使截获了 `alice_pk`、`bob_pk` 以及密文，在没有私钥的情况下也无法攻破离散对数难题以获取共享密钥。

### 密钥格式
* **公钥**：32 字节 raw 格式，经过 base64 编码（44 个字符）。
* **私钥**：48 字节 PKCS#8 格式，经过 base64 编码（64 个字符）。Web Crypto 导入私钥必须使用 PKCS#8 格式。
* **指纹 (FP)**：公钥 Base64 的前 16 位字符（包含 12 字节的原始熵），用作简易的端点通信地址（如 `abcdEFGHijklMNOP@smtp.aillm.net`）。

---

## RFC 5321 SMTP 状态机

内核 [src/smtp-state-machine.js](file:///home/ubuntu/workers/smtp/src/smtp-state-machine.js) 实现了 **RFC 5321 SMTP 状态机** 的纯逻辑版本。该模块完全解耦，不执行任何 I/O 操作。

### 8 个核心状态

| 状态 | 说明 | 允许的命令 |
|---|---|---|
| `CONNECT` | 初始建立连接状态 | `EHLO` / `HELO` / `QUIT` / `NOOP` |
| `GREETED` | 客户端已自报家门 | `AUTH` / `MAIL FROM` / `RSET` / `QUIT` |
| `AUTH_CHAL` | 服务端已发出 Challenge 挑战，等待签名 | base64 签名 / `*` (取消) / `AUTH` |
| `AUTH_OK` | 客户端身份认证通过 | `MAIL FROM` / `AUTH` (报错 503) / `QUIT` / `RSET` |
| `MAIL` | 发件人已配置 | `RCPT TO` / `QUIT` / `RSET` |
| `RCPT` | 收件人已配置（可配多个） | `RCPT TO` / `DATA` / `QUIT` / `RSET` |
| `DATA_HDR` | 处理邮件头部字段 | 头字段 / 空行（转移至 Body） |
| `DATA_BODY` | 处理邮件正文主体 | `.` (单点结束，触发 onMessage) / 任意文本行 |
| `QUIT` | 退出连接状态 | 无 |

### 单元测试
您可以在本地运行测试以验证状态机对协议的合规度：
```bash
node --test test/smtp-state-machine.test.js
```
测试用例覆盖：
- 多行响应（如 `250-SIZE`, `250 AUTH`）。
- 完整命令流程事务测试。
- 非法状态转移处理与异常响应。
- 邮件重置 (`RSET`) 与退出 (`QUIT`)。
- dot-stuffing（单行句点转义）机制。
- 信件大小超出限制拦截 (`552`)。

---

## 安全与威胁模型

### 服务器无法获取的信息
* **邮件主题与正文明文**：在发信人浏览器端已加密。
* **X25519 双方私钥**：仅存留在客户端的本地环境中。
* **派生出的对称密钥**：用完即销毁，不对外共享。

### 服务器可见的信息
* **元数据**：发信指纹、收信指纹、传输时间和密文数据包体积。
* **公钥**：为解密信箱列表和阅读特定信件，发信人的公钥是随信件以明文形式上传并展示的。

### 已知安全缺陷与折衷
1. **无前向安全性 (No Forward Secrecy)**：本系统未配置双棘轮协议（Signal Ratchet）。若您的私钥不慎泄露，使用该密钥协商过的所有历史通信密件均可被破译。
2. **元数据公开性**：任何人只要知道您的 16 位公钥指纹，均可通过 API 列出针对该指纹的来信列表（但读不到密文内容）。
3. **发信人伪造可能性**：我们没有对密文附加额外的 Ed25519 签名。在纯网络中继环境下，服务器理论上可以伪造发信人字段（不过由于是个人私有化部署，风险可控）。

---

## 使用方式

### 方法 1：网页浏览器 SPA
访问并使用 **`https://smtp.aillm.net`**：

1. **生成密钥**：前往 **我的密钥** 面板 $\rightarrow$ 点击 **生成新密钥对**。
2. **密钥备份**：点击 **导出备份** 下载您的 JSON 私钥并保存在密码管理器中。
3. **发送加密邮件**：进入 **发件箱**，填入收件人地址，粘贴对方的 44 位 Base64 公钥，书写信件后点击 **加密并发送**。
4. **收信解密**：切换到 **收件箱**，点击邮件即可在本地通过 JS 解密并展示明文。

### 方法 2：CLI 客户端
```bash
# 1. 生成并保存本地密钥对 (保存在 ~/.smtp-aillm/x25519.json)
$ node smtp-cli.js keygen
✓ X25519 密钥对已生成
  FP: abcdEFGHijklMNOP
  文件: /home/user/.smtp-aillm/x25519.json

# 2. 发送端到端加密邮件
$ node smtp-cli.js send bob@smtp.aillm.net <bob_pubkey_base64> "测试" "明天2点开会"
✓ 已端到端加密发送, id: 80e8940836c42bea

# 3. 查看信箱列表
$ node smtp-cli.js list
──────────────────────────────────────────────────────────
  id:     80e8940836c42bea
  from:   abcdEFGHijklMNOP@smtp.aillm.net
  to:     bob@smtp.aillm.net
  at:     2026-06-16T08:24:19.155Z
  status: 新件

# 4. 本地解密并阅读信件
$ node smtp-cli.js read 80e8940836c42bea
──────────────────────────────────────────────────────────
From:     abcdEFGHijklMNOP@smtp.aillm.net
To:       bob@smtp.aillm.net
Date:     2026-06-16T08:24:19.155Z
Subject:  测试
──────────────────────────────────────────────────────────
明天2点开会
──────────────────────────────────────────────────────────
```

---

## HTTP API 参考

| 请求方式 | 路径 | 鉴权请求头 | 说明 |
|---|---|---|---|
| `GET` | `/` | 无 | 网页前端主页 |
| `GET` | `/api/key/:fp` | 无 | 获取指定指纹对应的公钥 |
| `PUT` | `/api/key` | 无 | 注册公钥 `{fp, pub}` |
| `POST` | `/api/send` | 无 | 发送密文信件 `{to, to_fp, from, from_pk, subject_ct, subject_iv, body_ct, body_iv}` |
| `GET` | `/api/inbox` | `X-Auth: <fp>` | 列出该指纹接收的信件 |
| `GET` | `/api/mail/:id` | `X-Auth: <fp>` | 读取特定加密信件详情 |
| `POST` | `/api/smtp/feed` | 无 | SMTP 模拟对话投递接口 |

---

## 部署指南

### Cloudflare Workers 部署步骤
确保本地已安装并登录 Wrangler 客户端。

1. **创建必要的云端资源**：
   ```bash
   npx wrangler d1 create smtp-mail-db
   npx wrangler kv namespace create keyring
   ```
2. **填充配置文件**：
   将返回的 D1 数据库 ID 和 KV ID 粘贴进您的 `wrangler.toml`：
   ```toml
   [[d1_databases]]
   binding = "MAIL_DB"
   database_name = "smtp-mail-db"
   database_id = "你的D1数据库UUID"

   [[kv_namespaces]]
   binding = "KEYRING_KV"
   id = "你的KV命名空间ID"
   ```
3. **部署至 Cloudflare**：
   ```bash
   npx wrangler deploy
   ```
   *注意：数据库的初始化建表会在 Worker 接收到首次访问时自动完成。*

---

## 限制与已知折衷

| 项目 | 支持状态 | 备注 |
|---|---|---|
| 端到端加密 (E2EE) | ✅ | 服务器不见明文 |
| X25519 ECDH 派生共享密钥 | ✅ | 工业级密码学设计 |
| AES-GCM 256 位对称加密 | ✅ | 包含完整性校验 |
| 主题与正文独立加密 | ✅ | |
| 多设备密钥同步 | ❌ | 私钥仅存本地，新设备需手动导入私钥 |
| 邮件撤回/阅后即焚 | ❌ | |
| 文件附件 | ❌ | 协议层有 SIZE 限制，但前端未开发上传组件 |
| 密文检索 | ❌ | 服务端不可见明文，无法进行服务端文本搜索 |
| 发信箱 (Outbox) 记录 | ❌ | 收件箱只显示收到的信件，发信记录目前仅存客户端本地 |
| 多人抄送群发 | ❌ | 每一个收件人均需独立推导密钥，暂不支持多收件人加密 |
| 前向安全性 | ❌ | 若私钥泄露，该私钥对应的所有历史邮件均可被还原 |
| 自动公钥名录发现 | ❌ | 数据库接口预留，目前主要依赖线下手动交换公钥以保安全 |

---

## 开发与测试

### 运行单元测试
```bash
node --test test/smtp-state-machine.test.js
```

### 本地开发服务器启动
```bash
npx wrangler dev --config wrangler.dev.toml --port 8799 --local
```

---

## 许可证 (License)

本项目采用自定义许可证授权：
* **个人使用**：允许免费用于个人、非商业目的的学习、修改及自行托管部署。
* **商业使用**：未经版权所有者（collar2023）明确书面许可，严禁将本项目用于任何商业性开发、分发或整合至收费的商业服务中。

版权所有 (c) 2026 collar2023。保留所有权利。
