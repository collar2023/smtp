# SMTP — 端到端加密邮驿 (smtp.aillm.net)

> 在 RFC 5321 SMTP 协议外壳上叠加自创的 **X-CIPHER** 扩展
> 用 **X25519 ECDH** 派生共享密钥 + **AES-GCM** 加密的密件投递系统
> 部署在 Cloudflare Worker + D1,纸墨报版 UI

---

## ⚠️ 旧版本用户必读

**2026-06-16 加密模型完全重写**。如果你之前用过本服务:

- 浏览器:访问 `https://smtp.aillm.net/` → 「我的密钥」→ **重新生成密钥对**(点一下就行)
- CLI:删除 `~/.smtp-aillm/ed25519.json`,然后 `node smtp-cli.js keygen`
- 旧邮件**不可读**(旧版用 Ed25519 + 公开 FP 派生密钥,新版用 X25519 ECDH)
- 旧密钥**作废**,需要重新跟朋友交换公钥

**为什么改**:旧版加密模型有致命缺陷——AES 密钥从公开 FP 派生,任何拿到你 FP 的人(理论上所有人)都能解密你的历史邮件。**这不是"端到端加密",是"端到任何人都能读的编码"**。新版用 X25519 ECDH,服务器和任何旁观者都拿不到私钥,真正端到端。

---

## 目录

1. [这是什么](#这是什么)
2. [架构总览](#架构总览)
3. [加密模型 (X25519 ECDH)](#加密模型-x25519-ecdh)
4. [协议内核 (RFC 5321)](#协议内核-rfc-5321)
5. [安全模型](#安全模型)
6. [使用方式](#使用方式)
7. [HTTP API](#http-api)
8. [部署](#部署)
9. [CLI 客户端](#cli-客户端)
10. [限制与未做](#限制与未做)
11. [开发与测试](#开发与测试)

---

## 这是什么

**场景**:你和朋友都是开发者,想互发端到端加密便签,但不想用 Gmail/ProtonMail 这种中心化服务(它们虽然有 E2E 加密,但密钥托管在他们的服务器)。

**方案**:自己跑一个 Cloudflare Worker,收件箱存密文,每封邮件用 **X25519 ECDH** 派生共享密钥 → **AES-GCM** 加密。私钥永远在用户本地,服务器只见到密文。

**特点**:
- ✅ **真端到端**:服务器从未接触明文,也没有私钥,理论上无法解密
- ✅ **零中心化**:代码自己跑,数据存自己的 D1 配额里
- ✅ **协议经典外壳**:HTTP API + 一个 RFC 5321 状态机库,致敬 1982 年的协议美
- ✅ **轻量**:单 worker,单 D1,单 KV,单 R2(预留)
- ✅ **密钥自管**:丢失私钥 = 永远读不到旧密文(这是特性,不是 bug)

**局限**:
- ❌ **不能发到真 Gmail/QQ/163**:这是密件系统,不是邮件投递系统
- ❌ **不能从真邮箱收进来**:CF Email Routing 未启用
- ✅ **你 + 朋友都用本系统(SPA 或 CLI)**:真互通

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
    │ 密文    │       │ 公钥目录 │       │ (预留)   │
    │ 元数据  │       │ 1 年 TTL │       │ 附件     │
    └─────────┘       └──────────┘       └──────────┘


CLI 客户端 (smtp-cli.js, Node 18+)
  - keygen / send / list / read
  - 用 fetch 调同样 API
  - 私钥存 ~/.smtp-aillm/x25519.json (chmod 600)
```

### 数据流:Alice 发密件给 Bob

```
Alice (浏览器)
  1. 选 Bob 的 X25519 公钥 (base64, 44 字符)
     (从 KV 公钥目录 /api/key/:fp 拉,或当面拷贝)
  2. 输入明文 subject="会议纪要", body="明天 14:00 复盘"
  3. 浏览器:
     a. 加载自己的 X25519 私钥 (from localStorage)
     b. shared = deriveBits(my_sk, bob_pk)         ← X25519 ECDH
     c. iv1, iv2 = random 12 bytes each
     d. sub_ct = AES-GCM-encrypt(shared, iv1, subject)
     e. body_ct = AES-GCM-encrypt(shared, iv2, body)
     f. shared.fill(0)                              ← 内存清零
  4. POST /api/send {to, to_fp, from, from_pk, subject_ct, ...}
     ↑ 携带 Alice 的 X25519 公钥, Bob 收到后才能 ECDH 派生

Worker
  5. INSERT INTO mail (..., from_pk, subject_ct, body_ct, ...)
  6. 200 OK {id: "abc123"}

Bob (几分钟后)
  7. GET /api/inbox  Header X-Auth: <bob_fp>
  8. Worker: SELECT id, from_addr, from_pk, ... WHERE to_fp = <bob_fp>
  9. 返回邮件列表(每个都带 from_pk)
  10. Bob 点击邮件 → GET /api/mail/<id>
  11. Worker 返回完整密文行(含 from_pk)
  12. Bob 浏览器:
      a. 加载自己的 X25519 私钥
      b. shared = deriveBits(my_sk, alice_pk)       ← 同一个 shared
      c. 派生 AES key
      d. plaintext = AES-GCM-decrypt(aes_key, iv, ct)
  13. 显示明文 "会议纪要" / "明天 14:00 复盘"
```

**关键点**:
- Alice 派生 shared 时**只需要 Bob 的公钥**(公开)
- Bob 派生 shared 时**只需要 Alice 的公钥**(从邮件的 from_pk 拿到)
- 双方各持**自己的私钥**,**没有第三方能派生同样的 shared**
- 服务器拿到 (alice_pk, bob_pk, ct) 也**无法派生 shared**(缺任意一方的私钥)
- `sharedKey.fill(0)` 在用完后清零内存,减少侧信道泄露

---

## 加密模型 (X25519 ECDH)

### 加密流程

```
1. 双方各持一对 X25519 密钥:
   - Alice: (alice_sk, alice_pk)
   - Bob:   (bob_sk,   bob_pk)

2. Alice 发邮件:
   shared_a = X25519(alice_sk, bob_pk)    ← 32 bytes
   key      = AES-GCM.importKey(shared_a)
   iv       = random 12 bytes
   ct       = AES-GCM.encrypt(key, iv, plaintext)

3. 邮件载荷: {from_pk: alice_pk, ct, iv}

4. Bob 收邮件:
   shared_b = X25519(bob_sk, alice_pk)   ← 同一个 32 bytes
   key      = AES-GCM.importKey(shared_b)
   plaintext = AES-GCM.decrypt(key, iv, ct)
```

**为什么 X25519**:
- WebCrypto 原生支持(2024 GA)
- 32 字节私钥 = 32 字节公钥,简洁
- 已知数学安全,工业级(Signal/TLS 1.3/WireGuard 都在用)
- ECDH 性质: `X25519(alice_sk, bob_pk) === X25519(bob_sk, alice_pk)`,双方得到同一个 shared

### 密钥存储格式

```json
{
  "pub":  "<base64 44 chars>",   // 32 字节 raw 公钥
  "priv": "<base64 64 chars>"    // 48 字节 pkcs8 私钥
}
```

- 私钥必须 pkcs8 格式(48 字节 DER),WebCrypto 不接受 raw X25519 私钥
- 公钥 32 字节 raw,直接 base64

### FP (Fingerprint, 16 字符)

为方便人脑交换,**只用公钥前 16 字符 base64 作为"地址"**:

```
FP = pubKeyB64.slice(0, 16)   // 12 字节原始熵
```

- 够用(96 bit 空间)
- 人可以口头/微信发(`我的 FP 是 abc123XYZabc12==`)
- 但**不是真正的 128 bit 哈希**,只是前缀

**修法**(如要统一): SHA-256(pubKey) 前 16 字节作为 FP, 替换 `slice(0, 16)`。当前保持 `pubKeyB64.slice(0, 16)`。

---

## 协议内核 (RFC 5321)

`src/smtp-state-machine.js` 是**纯逻辑** RFC 5321 SMTP 状态机,**无 IO,无网络**,可以直接在 Node 跑测试,也可以在 Worker 喂命令。

### 8 个核心状态

| 状态 | 含义 | 接受的命令 |
|---|---|---|
| CONNECT | 初始 | EHLO / HELO / QUIT / NOOP |
| GREETED | 已自报家门 | AUTH / MAIL FROM / RSET / QUIT |
| AUTH_CHAL | 已发出 challenge, 等签名 | 签名的 base64 / * (中止) / AUTH (重挑战) |
| AUTH_OK | 鉴权通过 | MAIL FROM / AUTH (返回 503) / QUIT / RSET |
| MAIL | 已收到 MAIL FROM | RCPT TO / QUIT / RSET |
| RCPT | 已收到 ≥1 RCPT TO | RCPT TO / DATA / QUIT / RSET |
| DATA_HDR | DATA 模式, 收 headers | 任何 header / 空行 (转 body) |
| DATA_BODY | DATA 模式, 收 body | `.` (终止, 触发 onMessage) / 任何行 |
| QUIT | 已收 QUIT, 准备关闭 | (无) |

### 单元测试

```bash
$ node --test test/smtp-state-machine.test.js
# tests 14
# pass  14
```

覆盖:
- SmtpReply 序列化(单行 / 多行)
- 完整 EHLO → MAIL → RCPT → DATA → QUIT 流程
- 错误命令(503/501)
- AUTH 中途 `*` 中止
- AUTH_OK 状态再 AUTH → 503
- RSET 回 GREETED 后再 AUTH → 334
- dot-stuffing(`.` 转义)
- 超过 maxSize 邮件 → 552
- onMessage 回调触发

### 关键 bug 修复(本版)

| 之前 | 现在 |
|---|---|
| `verb.toUpperCase()` 破坏 base64 签名 | AUTH_CHAL 状态提前分支,不 toUpperCase |
| `onAuthVerify()` 未 await,Promise 恒真 | `await this.onAuthVerify(...)` |
| Challenge 确定性 [1,2,...,32] | `makeChallenge()` 真随机 32 字节 |

### `/api/smtp/feed` 端点(协议层 HTTP 包装)

为了在 Web 端也能"走一遍"协议层(调试、教育),`POST /api/smtp/feed` 端点接受一行 SMTP 命令,返回对应 reply。

**为什么需要 sid**:每次 HTTP 请求是无状态的,协议状态机需要跨请求保持。所以**首次请求会生成 `sid`**,客户端**带 `sid` 续接**。状态存 KV(TTL 5 分钟)。

```bash
# 首次
$ curl -X POST https://smtp.aillm.net/api/smtp/feed \
    -H "Content-Type: application/json" \
    -d '{"line":"EHLO client.example.com"}'
{"sid":"d39d62d0","reply":"250-mx.smtp.aillm.net Hello\r\n250-SIZE 52428800\r\n250-8BITMIME\r\n250-X-CIPHER v1\r\n250 AUTH X-CIPHER\r\n"}

# 续接
$ curl -X POST https://smtp.aillm.net/api/smtp/feed \
    -H "Content-Type: application/json" \
    -d '{"line":"MAIL FROM:<alice@x.com>","sid":"d39d62d0"}'
{"sid":"d39d62d0","reply":"250 2.1.0 Sender ok\r\n"}

# DATA 模式下空行/正文行返回 code=0 (CONTINUE)
$ curl -X POST ... -d '{"line":"","sid":"d39d62d0"}'
{"sid":"d39d62d0","reply":"0 CONTINUE\r\n"}
```

---

## 安全模型

### ✅ 服务器**永远见不到**

- 任何邮件的**明文主题/正文**
- 任何用户的**X25519 私钥**(私钥在浏览器 localStorage 或本地文件 `~/.smtp-aillm/x25519.json`, chmod 600)
- 任何邮件的**加密共享密钥**(共享密钥在浏览器内存中,用完即清零)

### ⚠️ 服务器**能见到**

- **元数据**:谁发给谁,什么时间,多大(密文 base64 长度)
- **公钥**(alice_pk + bob_pk 都是公开传输的)
- **D1 SQL 内容**:邮件密文行,除了 to_fp / from_fp / from_addr / to_addr,没别的
- **MITM 风险**(理论):服务器可替换 from_pk,让接收方派生错误 shared,但**你自己跑 worker**,风险为 0

### 🔒 加密保证

- **算法**:X25519 ECDH(32 字节共享密钥) + AES-GCM 256-bit
- **认证加密**:GCM 模式同时提供**完整性**和**机密性** — 篡改密文会被 AES-GCM 拒绝
- **每段独立 IV**:12 字节随机,GCM 推荐大小
- **共享密钥**: `X25519(my_sk, their_pk)`,**理论 128 bit 安全**(Curve25519)
- **前向保密**:❌ **没有**。每对通信方共用同一密钥,若任一私钥泄露,所有历史可解。**MVP 简化**,要 ratchet 协议得用 Signal Protocol 风格的双棘轮(MVP 不做)

### 🛡 建议(你该做的)

1. **私钥备份**:导出 JSON 文件(浏览器 SPA 的"导出备份"按钮),**加密存储在密码管理器 / 加密 U 盘**
2. **不要在聊天里发私钥**:一旦发出去,对话日志/截图/AI 训练数据都可能留底
3. **公钥可以公开**:你把 16 字符 FP 发给朋友,或者把 44 字符完整公钥发给他们,都没关系
4. **HTTP 严格**:用 HTTPS 访问 `smtp.aillm.net` (默认就 HTTPS)
5. **退出登录即清空**:浏览器 localStorage 在隐身模式不会持久
6. **丢失私钥 = 数据永久丢失**:没救

### ⚠️ 已知 trade-off

1. **小圈子的"信任"**:任何知道你 16 字符 FP 的人都能拉你的收件箱元数据(发件人/时间/数量),但**读不到密文**
2. **邮件伪造**:发件人无签名(我们没加 Ed25519 双签名),所以**理论上**服务器或中间人能伪造发件人。但你自己跑 worker,风险为 0
3. **KV 公钥目录目前**:`PUT /api/key` 可被任何人调用,任何人能注册**任意 fp 对应的任意公钥**。但**没人用**(`/api/send` 不查公钥目录,只信请求里的 from_pk/to_fp)。**未来要做自动公钥发现时再考虑加鉴权**

---

## 使用方式

### 方式 1:浏览器 SPA(推荐,UI 美)

访问 **https://smtp.aillm.net/**

#### 第一次: 生成密钥

1. 打开「我的密钥」标签
2. 点 "生成新密钥对"
3. 看到 **FP**(公钥前 16 字符)和**完整公钥**(44 字符 base64)
4. **把完整公钥发给朋友**(44 字符,或带 FP 前缀,无所谓)
5. **点 "导出备份"** → 下载 `smtp.aillm.net-key-xxxx.json`
6. **妥善保管这个文件**

#### 发密件

1. 「撰写」标签
2. 收件人:`xxx@smtp.aillm.net`(任意用户名,纯展示用)
3. 收件人公钥:粘贴朋友的 44 字符 base64 公钥
4. 输入主题 + 正文(明文)
5. 点 "加密并发送" → 浏览器本地 X25519 ECDH + AES-GCM 加密 → 上传密文

#### 收密件

1. 「收件箱」标签
2. 自动列出你的所有密件(按 to_fp 过滤)
3. 点击邮件 → 浏览器本地 ECDH 派生 shared + AES-GCM 解密 → 显示明文

#### 导入已有密钥(团队协作 / 换设备)

如果你已经有密钥对(从其他设备/CLI 来的):
1. 「我的密钥」标签
2. 在导入文本框粘:
   - 整个 JSON: `{"pub":"...","priv":"..."}`
   - 或两行 base64: 第 1 行 pub,第 2 行 priv
3. 或点 "从文件选择…" 选之前导出的 JSON
4. 点 "从文本导入" / 自动验证 ECDH round-trip

### 方式 2:CLI 客户端(终端党)

```bash
# 安装: 无, 直接跑
cd ~/workers/smtp

# 1. 生成密钥
$ node smtp-cli.js keygen
✓ X25519 密钥对已生成
  FP: abcdEFGHijklMNOP
  文件: /home/ubuntu/.smtp-aillm/x25519.json

# 2. 发送密件
$ node smtp-cli.js send bob@smtp.aillm.net <bob-pub-base64-44-chars> "你好" "明天 14:00 复盘"
✓ 已端到端加密发送, id: 80e8940836c42bea

# 3. 列出收件箱
$ node smtp-cli.js list
──────────────────────────────────────────────────────────
  id:    80e8940836c42bea
  from:  abcdEFGHijklMNOP@smtp.aillm.net
  to:    bob@smtp.aillm.net
  at:    2026-06-16T08:24:19.155Z
  status: 新件

# 4. 读取邮件
$ node smtp-cli.js read 80e8940836c42bea
──────────────────────────────────────────────────────────
From:     abcdEFGHijklMNOP@smtp.aillm.net
To:       bob@smtp.aillm.net
Date:     2026-06-16T08:24:19.155Z
Subject:  你好
──────────────────────────────────────────────────────────
明天 14:00 复盘
──────────────────────────────────────────────────────────
```

#### 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `SMTP_ENDPOINT` | `https://smtp.aillm.net` | API 地址 |
| `SMTP_KEYDIR` | `~/.smtp-aillm` | 密钥目录 |

#### 端到端互发流程(团队)

```bash
# Alice 这边
$ node smtp-cli.js keygen
FP: alice_fp_xxxxxxxxxxxx
完整公钥: alice_pub_base64_44_chars_xxxxxxxxxxxx=

# Bob 这边
$ node smtp-cli.js keygen
FP: bob_fp_yyyyyyyyyyyy
完整公钥: bob_pub_base64_44_chars_yyyyyyyyyyyy=

# 互相交换完整公钥 (微信/口头/手抄)
# Alice → Bob:  alice_pub_base64_44_chars_xxx...
# Bob   → Alice: bob_pub_base64_44_chars_yyy...

# Alice 发给 Bob
$ node smtp-cli.js send bob@smtp.aillm.net bob_pub_base64... "hi bob" "encrypted body"
# 成功, id: xxx

# Bob 拉收件箱
$ node smtp-cli.js list
# 看到 Alice 的邮件
$ node smtp-cli.js read xxx
# 看到 "hi bob" / "encrypted body"
```

---

## HTTP API

| Method | Path | 鉴权 | 说明 |
|---|---|---|---|
| GET | `/` | 无 | SPA 主页 |
| GET | `/api/key/:fp` | 无 | 查询公钥(MVP 未用) |
| PUT | `/api/key` | 无 | 注册公钥 `{fp, pub}` (TTL 1 年) |
| POST | `/api/send` | 无 | 发送加密邮件 `{to, to_fp, from, from_pk, subject_ct, subject_iv, body_ct, body_iv}` |
| GET | `/api/inbox` | Header `X-Auth: <fp>` | 收件箱列表(按 to_fp 过滤),**包含 from_pk** |
| GET | `/api/mail/:id` | Header `X-Auth: <fp>` | 读取单封(含完整密文 + from_pk) |
| POST | `/api/smtp/feed` | 无 | SMTP 协议层端点(见上节) |

### 鉴权说明

- **`/api/send`** 无鉴权:小圈子场景,任何人都能 POST 任意 to_fp。但发出去的是**密文**,没私钥解不开。**限流**: 单封 ≤ 200KB
- **`/api/inbox` / `/api/mail/:id`** 用 `X-Auth: <fp>` header。理论上任何知道对方 fp 的人能拉元数据(发件人/时间/数量),**读不到密文**。**已知 trade-off**,跟"小圈子信任"模型一致
- **`/api/key`** 无鉴权:但**目前没人用**

### 请求/响应示例

#### 发邮件

```bash
$ curl -X POST https://smtp.aillm.net/api/send \
    -H "Content-Type: application/json" \
    -d '{
      "to": "bob@smtp.aillm.net",
      "to_fp": "abcdEFGHijklMNOP",
      "from": "alice_fp_xx@smtp.aillm.net",
      "from_pk": "alice_full_pub_base64_44chars",
      "from_fp": "alice_fp_xx",
      "subject_ct": "ENC_SUBJECT_BASE64",
      "subject_iv": "IV_SUBJECT_BASE64",
      "body_ct": "ENC_BODY_BASE64",
      "body_iv": "IV_BODY_BASE64"
    }'

{"id":"80e8940836c42bea"}
```

#### 读收件箱

```bash
$ curl https://smtp.aillm.net/api/inbox \
    -H "X-Auth: abcdEFGHijklMNOP"

[
  {
    "id": "80e8940836c42bea",
    "from_addr": "alice_fp_xx@smtp.aillm.net",
    "from_fp": "alice_fp_xx",
    "from_pk": "alice_full_pub_base64_44chars",
    "to_addr": "bob@smtp.aillm.net",
    "subject_preview": "(encrypted)",
    "created_at": 1781598259155,
    "read_at": null
  }
]
```

**注意 `from_pk` 字段**:接收方需要它来 ECDH 派生 shared key,务必保留。

#### 读单封

```bash
$ curl https://smtp.aillm.net/api/mail/80e8940836c42bea \
    -H "X-Auth: abcdEFGHijklMNOP"

{
  "id": "80e8940836c42bea",
  "to_addr": "bob@smtp.aillm.net",
  "to_fp": "abcdEFGHijklMNOP",
  "from_addr": "alice_fp_xx@smtp.aillm.net",
  "from_fp": "alice_fp_xx",
  "from_pk": "alice_full_pub_base64_44chars",
  "subject_ct": "...",
  "subject_iv": "...",
  "body_ct": "...",
  "body_iv": "...",
  "size": 168,
  "created_at": 1781598259155,
  "read_at": null
}
```

---

## 部署

### 一次性部署

```bash
# 1. 拉代码 (假设在 ~/workers/)
cd ~/workers/smtp

# 2. 创建资源 (CF API token 需 Workers/D1/KV 写权限)
npx wrangler d1 create smtp-mail-db          # 把 id 填入 wrangler.toml
npx wrangler kv namespace create smtp        # 把 id 填入 wrangler.toml
npx wrangler r2 bucket create smtp-mail      # (预留, 暂未使用)

# 3. 部署
npx wrangler deploy
# 输出:
#   Uploaded smtp (3.03 sec)
#   Deployed smtp triggers (1.85 sec)
#     smtp.aillm.net (custom domain)
#   Current Version ID: ...

# 4. (可选) 手动应用 D1 schema
npx wrangler d1 execute smtp-mail-db --remote --file=./schema.sql
# 实际: worker 首次启动时会自动 lazy 创建 (含 from_pk 列)
```

### wrangler.toml 关键字段

```toml
name = "smtp"
main = "index.js"
compatibility_date = "2026-06-12"
compatibility_flags = ["nodejs_compat"]

[[r2_buckets]]
binding = "MAIL_BUCKET"
bucket_name = "smtp-mail"

[[d1_databases]]
binding = "MAIL_DB"
database_name = "smtp-mail-db"
database_id = "YOUR_D1_ID"

[[kv_namespaces]]
binding = "KEYRING_KV"
id = "YOUR_KV_ID"

[[routes]]
pattern = "smtp.aillm.net"
custom_domain = true
```

### D1 Schema 升级注意事项

`ensureSchema(env)` 在 worker 启动时:
1. 尝试 `ALTER TABLE mail ADD COLUMN from_pk` (兼容旧版)
2. 失败则 `DROP TABLE + CREATE TABLE`(破坏性升级,清空所有邮件)

**升级前确保你接受数据丢失**。或者手动在 dashboard 跑:
```sql
ALTER TABLE mail ADD COLUMN from_pk TEXT NOT NULL DEFAULT '';
```

---

## CLI 客户端

### 文件

- `smtp-cli.js` — 单文件 Node 18+ 客户端
- 私钥存 `~/.smtp-aillm/x25519.json` (chmod 600)
- 共享 SPA 的所有 API

### 子命令

| 命令 | 说明 |
|---|---|
| `keygen` | 生成 X25519 密钥对 |
| `send <to> <to-pub> <subject> <body>` | 发送加密邮件(接收方公钥 44 字符 base64) |
| `list` | 列出收件箱(只显示发给当前 FP 的) |
| `read <id>` | 解密并打印单封邮件 |

### 配合脚本(用环境变量切环境)

```bash
# 生产
SMTP_ENDPOINT=https://smtp.aillm.net node smtp-cli.js list

# 本地 (wrangler dev 起来后)
SMTP_ENDPOINT=http://127.0.0.1:8799 SMTP_KEYDIR=~/.smtp-aillm-dev node smtp-cli.js list
```

---

## 限制与未做

诚实清单:

| 项 | 状态 | 备注 |
|---|---|---|
| 端到端加密 | ✅ | 真 E2E, 服务器不见明文 |
| X25519 ECDH 派生共享密钥 | ✅ | 工业级 |
| AES-GCM 256 加密 | ✅ | |
| 主题/正文加密 | ✅ | |
| 多设备同步 | ❌ | 私钥只存在本地,新设备需要导入 |
| 邮件撤回/删除 | ❌ | 服务端不删 |
| 阅后即焚 | ❌ | MVP 未做 |
| 附件 | ❌ | 协议层有 SIZE 52428800 限制,但前端未实现上传 |
| 搜索 | ❌ | 服务器不见明文,无法服务端搜索 |
| 已发送文件夹 | ❌ | 收件箱只有收到的,没有"我发出去的" |
| 群发 | ❌ | 每个收件人单独加密,需手动多次 send |
| **前向保密** | ❌ | receiver_pk 泄露 → 所有历史可解。要 ratchet 协议才行 |
| 发件人签名 | ❌ | 没加 Ed25519 双签名,服务器理论上能伪造 from(MVP 信任自己跑 worker) |
| SMTP 出站到 Gmail | ❌ | 不在范围内 |
| SMTP 入站从 Gmail | ❌ | 同上 |
| DKIM/SPF/DMARC | ❌ | 同上 |
| 私钥找回 | ❌ | 丢失 = 数据永久丢失 |
| CSP / 安全头 | ❌ | 暂未加(防 XSS / 劫持) |
| 自动公钥发现 | ❌ | KV 端点存在但未启用,需要手互传公钥 |

---

## 开发与测试

### 跑测试

```bash
node --test test/smtp-state-machine.test.js
# tests 14 / pass 14
```

### 本地开发

```bash
# 简化的 wrangler.dev.toml (不含 D1 真实 id)
npx wrangler dev --config wrangler.dev.toml --port 8799 --local

# 另开终端
node smtp-cli.js list
```

### 项目结构

```
smtp/
├── wrangler.toml                  # Cloudflare Worker 配置
├── wrangler.dev.toml              # 本地开发配置 (不含 D1 真实 id)
├── index.js                       # Worker 入口 + 内嵌 SPA HTML
├── smtp-cli.js                    # CLI 客户端
├── schema.sql                     # D1 schema
├── README.md                      # 本文件
├── STATUS.md                      # 状态简述
├── src/
│   ├── smtp-state-machine.js      # RFC 5321 状态机 (核心, 14 单测)
│   ├── smtp-codec.js              # base64/hex 编解码
│   ├── smtp-auth.js               # Ed25519 挑战签名 (/api/smtp/feed 协议层 demo)
│   ├── smtp-codec.js              # base64/hex 编码
│   ├── smtp-crypto.js             # makeMessageId
│   └── smtp-state-machine.js      # RFC 5321 状态机 (经典协议美)
└── test/
    └── smtp-state-machine.test.js # 14 个状态机单元测试
```

### 协议内核单独使用

`src/smtp-state-machine.js` 是纯逻辑,可独立 require:

```js
import { SmtpSession, SmtpReply, STATES } from './src/smtp-state-machine.js';

const s = new SmtpSession({ hostname: 'mx.example.com' });
const reply = await s.feed('EHLO client.example.com');
console.log(reply.serialize());
// "250-mx.example.com Hello\r\n250-SIZE 52428800\r\n..."
```

适合用来:
- 写自己的 SMTP 客户端
- 做 SMTP 协议的 fuzzing 测试
- 给其他邮件项目嵌入状态机

---

## 协议层示例 (RFC 5321 + X-CIPHER 完整流程)

```
S: 220 mx.smtp.aillm.net ESMTP ready
C: EHLO client.example.com
S: 250-mx.smtp.aillm.net Hello
S: 250-SIZE 52428800
S: 250-8BITMIME
S: 250-X-CIPHER v1
S: 250 AUTH X-CIPHER
C: AUTH X-CIPHER
S: 334 <base64-challenge-32-bytes>      ← 真随机
C: <base64-ed25519-signature>           ← Ed25519 签 challenge (未来用)
S: 235 2.7.0 Authentication successful
C: MAIL FROM:<alice@x.com>
S: 250 2.1.0 Sender ok
C: RCPT TO:<bob@smtp.aillm.net>
S: 250 2.1.5 Recipient ok
C: DATA
S: 354 End data with <CR><LF>.<CR><LF>
C: Subject: hello
C: From: alice@x.com
C: To: bob@smtp.aillm.net
C:
C: hi bob
C: this is body
C: .
S: 250 2.0.0 Ok: queued as cipher message
C: QUIT
S: 221 2.0.0 Bye
```

**注**:当前 `/api/send` 端点不强制走 SMTP 协议(直接 POST JSON 更快),但 `/api/smtp/feed` 端点完整实现了这个协议对话,可在 SPA "协议演示"功能里用。

---

## License

个人项目,无 license。你和朋友互发密件免费使用。
