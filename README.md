# SMTP — End-to-End Encrypted Mail Post (smtp.aillm.net)

> A zero-knowledge, end-to-end encrypted (E2EE) messaging system built on top of the classic **RFC 5321 SMTP** state machine with a custom **X-CIPHER** extension.
> Powered by **X25519 ECDH** key exchange, **AES-GCM-256** authenticated encryption, and deployed as a lightweight serverless app on **Cloudflare Workers** + **D1** SQL Database + **KV**, featuring a retro "paper-and-ink" web UI.

---

## Table of Contents

1. [Introduction](#introduction)
2. [Architecture Overview](#architecture-overview)
3. [E2EE Cryptographic Model](#e2ee-cryptographic-model)
4. [RFC 5321 SMTP State Machine](#rfc-5321-smtp-state-machine)
5. [Security & Threat Model](#security--threat-model)
6. [Usage Guide](#usage-guide)
7. [HTTP API Reference](#http-api-reference)
8. [Deployment Guide](#deployment-guide)
9. [CLI Client](#cli-client)
10. [Limitations & Trade-offs](#limitations--trade-offs)
11. [Development & Testing](#development--testing)

---

## Introduction

**The Problem**: Developers want to send encrypted notes or small messages to colleagues without relying on centralized communication platforms or email giants (e.g., ProtonMail, Gmail) where private keys are hosted on third-party servers.

**The Solution**: A self-hosted Cloudflare Worker serving an encrypted message inbox. The private key remains exclusively in the user's browser or local CLI. Using **X25519 ECDH** and **AES-GCM-256**, messages are encrypted *before* they are sent to the server. The server only sees ciphertext, metadata, and public keys.

**Features**:
* ✅ **True End-to-End Encryption (E2EE)**: The server never touches plain text, nor does it hold private keys. It is mathematically incapable of decrypting the messages.
* ✅ **Decoupled State Machine**: A pure-logic, fully-tested implementation of RFC 5321 SMTP state machine inside the worker, honoring the classic beauty of 1982 protocol design.
* ✅ **Ultra Lightweight**: Single Worker file, single D1 SQL database for ciphertext, single KV namespace for public keys, and optional R2 bucket for large attachments.
* ✅ **Self-Managed Keys**: Loose your private key, lose your data. No backup codes, no "forgot password" links. This is a security feature, not a bug.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│ Browser SPA (smtp.aillm.net)                            │
│  ┌────────────┬────────────┬────────────┐               │
│  │ Inbox      │ Compose    │ My Keys    │               │
│  │ (Local     │ (Local     │ (X25519    │               │
│  │ Decrypt)   │ Encrypt)   │ Storage)   │               │
│  └─────┬──────┴─────┬──────┴─────┬──────┘               │
│        │ HTTPS API  │            │                      │
└────────┼────────────┼────────────┼──────────────────────┘
         │            │            │
         ▼            ▼            ▼
┌─────────────────────────────────────────────────────────┐
│ Cloudflare Worker (smtp.aillm.net)                      │
│ ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│ │ /api/inbox   │  │ /api/send    │  │ /api/key/*   │  │
│ │ GET Inbox    │  │ POST Cipher  │  │ PubKey Dir   │  │
│ └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
│        │                 │                 │           │
│        │   ┌─────────────┴─────────────┐   │           │
│        │   │  src/smtp-state-machine.js │   │           │
│        │   │  RFC 5321 Pure Logic      │   │           │
│        │   │  14/14 Unit Tests Passed  │   │           │
│        │   └────────────────────────────┘   │           │
└────────┼──────────────────┼─────────────────┼──────────┘
         │                  │                 │
         ▼                  ▼                 ▼
    ┌─────────┐       ┌──────────┐       ┌──────────┐
    │ D1      │       │ KV       │       │ R2       │
    │ SQLite  │       │ Public   │       │ Reserved │
    │ Cipher  │       │ Key      │       │ for      │
    │ Storage │       │ Registry │       │ Files    │
    └─────────┘       └──────────┘       └──────────┘


CLI Client (smtp-cli.js, Node 18+)
  - Commands: keygen / send / list / read
  - Invokes the same HTTPS API endpoints
  - Private key stored locally in ~/.smtp-aillm/x25519.json (chmod 600)
```

### Encryption & Delivery Data Flow (Alice sending a mail to Bob)

1. **PublicKey Discovery**: Alice fetches Bob's X25519 public key (44 characters base64) either directly from `/api/key/:fp` (public registry) or exchanges it manually.
2. **Local Composition**: Alice drafts the email (`subject="Secret project"`, `body="Meet at 2 PM"`).
3. **Local Encryption**:
   - Alice loads her private key `alice_sk` from browser local storage.
   - Alice computes the shared secret: `shared_secret = X25519_ECDH(alice_sk, bob_pk)`.
   - Generates two cryptographically secure random 12-byte initialization vectors: `iv_subject`, `iv_body`.
   - Encrypts:
     * `subject_ct = AES-GCM-256(shared_secret, iv_subject, subject)`
     * `body_ct = AES-GCM-256(shared_secret, iv_body, body)`
   - Wipes the `shared_secret` buffer from memory (`shared_secret.fill(0)`).
4. **Post Ciphertext**: Alice sends a `POST /api/send` request containing Bob's fingerprint, her public key (`from_pk`), the ciphertexts, and the IVs.
5. **Worker Storage**: The Cloudflare Worker inserts the record into D1 SQLite:
   `INSERT INTO mail (..., from_pk, subject_ct, body_ct, subject_iv, body_iv)`
6. **Bob Retrieves Mail**: Bob calls `GET /api/inbox` using header `X-Auth: bob_fp`. The server returns the envelope containing Alice's public key `from_pk`.
7. **Local Decryption**: Bob fetches the full ciphertext from `/api/mail/:id`, imports `bob_sk` and `alice_pk`, derives the identical `shared_secret = X25519_ECDH(bob_sk, alice_pk)`, and decrypts both headers locally.

---

## E2EE Cryptographic Model

The end-to-end encryption relies entirely on the Web Crypto API implemented natively in browsers and Node.js.

### The Math (ECDH + AES-GCM)

$$\text{Shared Secret} = \text{ECDH}(\text{PrivateKey}_{\text{Self}}, \text{PublicKey}_{\text{Peer}})$$

$$\text{Ciphertext} = \text{AES-GCM-256}(\text{Shared Secret}, \text{IV}_{\text{Random}}, \text{Plaintext})$$

Because of the Diffie-Hellman property:
$$\text{ECDH}(\text{alice\_sk}, \text{bob\_pk}) \equiv \text{ECDH}(\text{bob\_sk}, \text{alice\_pk})$$

Both parties derive the exact same 32-byte shared key, but an eavesdropper (or the hosting server) seeing only `alice_pk`, `bob_pk`, and the ciphertexts cannot solve the Discrete Logarithm problem to obtain the shared secret.

### Key Formats
* **Public Key**: 32-byte raw public key, base64-encoded (44 characters).
* **Private Key**: 48-byte PKCS#8 private key, base64-encoded (64 characters). Web Crypto requires PKCS#8 format for importing private keys.
* **Fingerprint (FP)**: The first 16 characters of the base64 public key (representing 12 bytes of raw entropy), used as the short identity address (e.g., `abcdEFGHijklMNOP@smtp.aillm.net`).

---

## RFC 5321 SMTP State Machine

The core protocol layer is designed as a **pure-logic state machine** in [src/smtp-state-machine.js](file:///home/ubuntu/workers/smtp/src/smtp-state-machine.js). It performs no network or disk I/O, allowing it to run identically in browsers, CLI environments, or Cloudflare Worker threads.

### 8 Protocol States

| State | Purpose | Allowed Commands |
|---|---|---|
| `CONNECT` | Initial greeting state | `EHLO` / `HELO` / `QUIT` / `NOOP` |
| `GREETED` | Client identity known | `AUTH` / `MAIL FROM` / `RSET` / `QUIT` |
| `AUTH_CHAL` | Challenge sent, awaiting signature | base64 signature / `*` (abort) / `AUTH` |
| `AUTH_OK` | Authentication completed | `MAIL FROM` / `AUTH` (503 error) / `QUIT` / `RSET` |
| `MAIL` | Sender address set | `RCPT TO` / `QUIT` / `RSET` |
| `RCPT` | Recipient(s) configured | `RCPT TO` / `DATA` / `QUIT` / `RSET` |
| `DATA_HDR` | Processing message headers | Header fields / empty line (enters body) |
| `DATA_BODY` | Processing mail body | `.` (EOF, triggers onMessage) / body lines |
| `QUIT` | Graceful exit requested | None |

### State Machine Unit Testing
You can run the unit test suite locally to verify the RFC compliance:
```bash
node --test test/smtp-state-machine.test.js
```
The 14 tests cover:
- Multi-line SMTP EHLO replies (`250-`, `250 `).
- Complete standard transaction flow (`EHLO` $\rightarrow$ `MAIL` $\rightarrow$ `RCPT` $\rightarrow$ `DATA` $\rightarrow$ `.` $\rightarrow$ `QUIT`).
- Command sequence validations (e.g. sending `AUTH` after `AUTH_OK` returns 503).
- Session reset (`RSET`).
- Standard dot-stuffing escape validation (e.g., `..` $\rightarrow$ `.`).
- Size limitation enforcement (`552 Message size exceeds limit`).

---

## Security & Threat Model

### What the Server CANNOT See
* **Subject and Body plaintext**: They are encrypted in-browser before upload.
* **X25519 Private Keys**: Never leaves local storage.
* **Derived AES Key**: Never shared or stored. Cleared from memory after encryption/decryption completes.

### What the Server CAN See
* **Metadata**: Sender fingerprint, recipient fingerprint, delivery timestamp.
* **Public Keys**: Exchanged during mail listing and registration.
* **Storage Footprint**: Total size of the base64-encoded encrypted messages.

### Known Limitations & Security Trade-offs
1. **No Forward Secrecy**: The system does not implement a Double Ratchet (Signal-style). If your private key is compromised, all historical emails encrypted with that key can be decrypted.
2. **Metadata Exposure**: Anyone knowing your 16-character fingerprint can query `/api/inbox` with that fingerprint and list the timestamps, sizes, and sender addresses of your emails (though they cannot decrypt them).
3. **Sender Spoofing**: We did not implement Ed25519 double-signatures on the ciphertext. While the message contents are tamper-proof due to AES-GCM's authentication tag, a malicious server could theoretically spoof the `from` field of a ciphertext. This is mitigated by hosting your own private Worker.

---

## Usage Guide

### Option 1: Retro Web UI (SPA)
Visit **`https://smtp.aillm.net`** on your browser.

1. **Generate Keys**: Navigate to **My Keys** $\rightarrow$ Click **Generate New Key Pair**.
2. **Backup Keys**: Click **Export Backup** to download your key JSON. Store it in a password manager.
3. **Compose E2EE Mail**: Under **Compose**, enter the recipient address, paste their 44-character X25519 public key, fill in the subject/body, and click **Encrypt and Send**.
4. **Read Mail**: Go to **Inbox**, click any incoming message, and it will be decrypted dynamically in your browser.

### Option 2: CLI Client
```bash
# 1. Generate local keys (saved to ~/.smtp-aillm/x25519.json)
$ node smtp-cli.js keygen
✓ X25519 Keypair generated
  FP: abcdEFGHijklMNOP
  File: /home/user/.smtp-aillm/x25519.json

# 2. Send an E2EE mail
$ node smtp-cli.js send bob@smtp.aillm.net <bob-pubkey-base64> "Hello Bob" "This is my private message"
✓ Encrypted and sent successfully, ID: 80e8940836c42bea

# 3. List Inbox
$ node smtp-cli.js list
──────────────────────────────────────────────────────────
  id:     80e8940836c42bea
  from:   abcdEFGHijklMNOP@smtp.aillm.net
  to:     bob@smtp.aillm.net
  at:     2026-06-16T08:24:19.155Z
  status: Unread

# 4. Decrypt and Read
$ node smtp-cli.js read 80e8940836c42bea
──────────────────────────────────────────────────────────
From:     abcdEFGHijklMNOP@smtp.aillm.net
To:       bob@smtp.aillm.net
Date:     2026-06-16T08:24:19.155Z
Subject:  Hello Bob
──────────────────────────────────────────────────────────
This is my private message
──────────────────────────────────────────────────────────
```

---

## HTTP API Reference

| Method | Path | Auth Header | Description |
|---|---|---|---|
| `GET` | `/` | None | Web App Frontend SPA |
| `GET` | `/api/key/:fp` | None | Get public key by fingerprint |
| `PUT` | `/api/key` | None | Register public key `{fp, pub}` |
| `POST` | `/api/send` | None | Send E2EE mail `{to, to_fp, from, from_pk, subject_ct, subject_iv, body_ct, body_iv}` |
| `GET` | `/api/inbox` | `X-Auth: <fp>` | List inbox messages for a fingerprint |
| `GET` | `/api/mail/:id` | `X-Auth: <fp>` | Read single mail details (returns ciphertext) |
| `POST` | `/api/smtp/feed` | None | Stateless SMTP simulation endpoint |

---

## Deployment Guide

### Cloudflare Workers Prerequisites
Ensure you have the Wrangler CLI installed and authenticated.

1. **Create Resources**:
   ```bash
   npx wrangler d1 create smtp-mail-db
   npx wrangler kv namespace create keyring
   ```
2. **Update Configuration**:
   Paste the generated database ID and KV ID into your `wrangler.toml`:
   ```toml
   [[d1_databases]]
   binding = "MAIL_DB"
   database_name = "smtp-mail-db"
   database_id = "YOUR-D1-DATABASE-UUID"

   [[kv_namespaces]]
   binding = "KEYRING_KV"
   id = "YOUR-KV-NAMESPACE-ID"
   ```
3. **Deploy**:
   ```bash
   npx wrangler deploy
   ```
   *Note: D1 database tables will be initialized lazily on the first request.*

---

## License

Personal project. Provided "as-is" without warranty. Feel free to clone, host, and use for private communications with your peers.
