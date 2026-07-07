#!/usr/bin/env node
// smtp-cli.js — 端到端加密命令行客户端 (X25519 ECDH + AES-GCM)
const fs = require('fs');
const path = require('path');

const ENDPOINT = process.env.SMTP_ENDPOINT || 'https://smtp.aillm.net';
const KEY_DIR = process.env.SMTP_KEYDIR || path.join(process.env.HOME, '.smtp-aillm');
const KEY_FILE = path.join(KEY_DIR, 'x25519.json');

function ensureKeyDir() {
  if (!fs.existsSync(KEY_DIR)) fs.mkdirSync(KEY_DIR, { recursive: true });
}
function loadKey() {
  if (!fs.existsSync(KEY_FILE)) return null;
  return JSON.parse(fs.readFileSync(KEY_FILE, 'utf8'));
}
function saveKey(k) {
  ensureKeyDir();
  fs.writeFileSync(KEY_FILE, JSON.stringify(k, null, 2));
  fs.chmodSync(KEY_FILE, 0o600);
}

function b64enc(b) { return Buffer.from(b).toString('base64'); }
function b64dec(s) { return Buffer.from(s, 'base64'); }
function b64valid(s, len) {
  if (typeof s !== 'string') return false;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(s)) return false;
  try { const b = b64dec(s); return len === undefined || b.length === len; } catch (e) { return false; }
}

// X25519
async function genKey() {
  const kp = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  return {
    pub: b64enc(new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey))),
    priv: b64enc(new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey))),
  };
}
async function loadMyKey() {
  const k = loadKey();
  if (!k) return null;
  return {
    sk: await crypto.subtle.importKey('pkcs8', b64dec(k.priv), { name: 'X25519' }, false, ['deriveBits']),
    pubB64: k.pub,
  };
}
async function deriveShared(mySk, theirPubB64) {
  const theirPk = await crypto.subtle.importKey('raw', b64dec(theirPubB64), { name: 'X25519' }, true, []);
  const bits = await crypto.subtle.deriveBits({ name: 'X25519', public: theirPk }, mySk, 256);
  return new Uint8Array(bits);
}
async function aesEncrypt(plain, key) {
  const aesKey = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(plain));
  return { iv: b64enc(iv), ct: b64enc(new Uint8Array(ct)) };
}
async function aesDecrypt(ctB64, ivB64, key) {
  const aesKey = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64dec(ivB64) }, aesKey, b64dec(ctB64));
  return new TextDecoder().decode(pt);
}

// ── 子命令 ──
async function cmdKeygen() {
  if (loadKey()) {
    const k = loadKey();
    console.log('⚠  密钥已存在:', KEY_FILE);
    console.log('  FP:', k.pub.slice(0, 16));
    return;
  }
  const k = await genKey();
  saveKey(k);
  console.log('✓ X25519 密钥对已生成');
  console.log('  FP:', k.pub.slice(0, 16));
  console.log('  文件:', KEY_FILE);
}

async function cmdSend(to, toPubB64, subject, body) {
  const me = await loadMyKey();
  if (!me) throw new Error('请先运行: node smtp-cli.js keygen');
  if (!b64valid(toPubB64, 32)) {
    throw new Error('收件人公钥必须是 32 字节 X25519 (base64 44 字符)');
  }
  const shared = await deriveShared(me.sk, toPubB64);
  const subEnc = await aesEncrypt(subject || '(无主题)', shared);
  const bodyEnc = await aesEncrypt(body, shared);

  const res = await fetch(ENDPOINT + '/api/send', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      to,
      to_fp: toPubB64.slice(0, 16),
      from: me.pubB64.slice(0, 16) + '@smtp.aillm.net',
      from_pk: me.pubB64,
      from_fp: me.pubB64.slice(0, 16),
      subject_ct: subEnc.ct, subject_iv: subEnc.iv,
      body_ct: bodyEnc.ct, body_iv: bodyEnc.iv,
    })
  });
  if (!res.ok) throw new Error('send failed: ' + res.status + ' ' + await res.text());
  const j = await res.json();
  console.log('✓ 已端到端加密发送, id:', j.id);
}

async function cmdList() {
  const me = await loadMyKey();
  if (!me) throw new Error('请先 keygen');
  const res = await fetch(ENDPOINT + '/api/inbox', {
    headers: { 'X-Auth': me.pubB64.slice(0, 16) }
  });
  if (!res.ok) throw new Error('list failed: ' + res.status);
  const mails = await res.json();
  if (!mails.length) { console.log('(收件箱空)'); return; }
  for (const m of mails) {
    console.log('─'.repeat(60));
    console.log('  id:    ', m.id);
    console.log('  from:  ', m.from_addr);
    console.log('  to:    ', m.to_addr);
    console.log('  at:    ', new Date(m.created_at).toISOString());
    console.log('  status:', m.read_at ? '已读' : '新件');
  }
}

async function cmdRead(id) {
  const me = await loadMyKey();
  if (!me) throw new Error('请先 keygen');
  const res = await fetch(ENDPOINT + '/api/inbox', {
    headers: { 'X-Auth': me.pubB64.slice(0, 16) }
  });
  const inbox = await res.json();
  const mail = inbox.find(m => m.id === id);
  if (!mail) throw new Error('mail id not in inbox: ' + id);

  // 拉单封密文
  const detailRes = await fetch(ENDPOINT + '/api/mail/' + id, {
    headers: { 'X-Auth': me.pubB64.slice(0, 16) }
  });
  if (!detailRes.ok) throw new Error('read failed: ' + detailRes.status);
  const m = await detailRes.json();
  // ECDH 解密
  const shared = await deriveShared(me.sk, m.from_pk);
  const sub = await aesDecrypt(m.subject_ct, m.subject_iv, shared);
  const body = await aesDecrypt(m.body_ct, m.body_iv, shared);
  console.log('─'.repeat(60));
  console.log('From:    ', m.from_addr);
  console.log('To:      ', m.to_addr);
  console.log('Date:    ', new Date(m.created_at).toISOString());
  console.log('Subject: ', sub);
  console.log('─'.repeat(60));
  console.log(body);
  console.log('─'.repeat(60));
}

async function main() {
  const [cmd, ...args] = process.argv.slice(2);
  if (!cmd || cmd === '-h' || cmd === '--help') {
    console.log(`用法:
  node smtp-cli.js keygen
  node smtp-cli.js send <to> <to-pub-b64> <subject> <body>
  node smtp-cli.js list
  node smtp-cli.js read <id>

ENV:
  SMTP_ENDPOINT  (default: ${ENDPOINT})
  SMTP_KEYDIR    (default: ${KEY_DIR})
`);
    return;
  }
  try {
    if (cmd === 'keygen') return cmdKeygen();
    if (cmd === 'send')   return cmdSend(args[0], args[1], args[2] || '', args.slice(3).join(' '));
    if (cmd === 'list')   return cmdList();
    if (cmd === 'read')   return cmdRead(args[0]);
    throw new Error('未知子命令: ' + cmd);
  } catch (e) {
    console.error('✗', e.message);
    process.exit(1);
  }
}
main();
