// smtp — 端到端加密 SMTP 服务 (HTTP API + 报版 SPA)
// 协议内核: src/smtp-state-machine.js (RFC 5321 状态机, 经典协议美, 已单测)
// 鉴权:    src/smtp-auth.js   (Ed25519, 仅 /api/smtp/feed 协议层 demo 使用)
// 工具:    src/smtp-codec.js, src/smtp-crypto.js (makeMessageId)

import { SmtpSession } from './src/smtp-state-machine.js';
import { makeChallenge, verifyChallenge } from './src/smtp-auth.js';
import { makeMessageId } from './src/smtp-crypto.js';
import { bytesToB64, b64ToBytes } from './src/smtp-codec.js';

const HTML_TEMPLATE = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SMTP — 端到端加密邮驿</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Noto+Serif+SC:wght@400;600;700&family=Playfair+Display:ital,wght@0,700;0,900&family=Courier+Prime:wght@400;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --paper:        #faf7f0;
      --paper-mid:    #f0ece0;
      --ink:          #121212;
      --ink-light:    #3a3a3a;
      --ink-muted:    #7a7a7a;
      --blue:         #003366;
      --blue-hover:   #00224d;
      --blue-light:   rgba(0, 51, 102, 0.06);
      --red:          #a82e2e;
      --red-light:    rgba(168, 46, 46, 0.05);
      --border:       #c8bfa8;
      --border-light: #e0d9cc;
      --mono:         'Courier Prime', 'Courier New', monospace;
    }
    * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; margin: 0; padding: 0; }
    body {
      background: var(--paper);
      color: var(--ink);
      font-family: 'Noto Serif SC', 'STSong', serif;
      min-height: 100vh;
      display: flex; flex-direction: column; align-items: center;
      background-image: repeating-linear-gradient(0deg, transparent, transparent 27px, rgba(0,0,0,0.018) 27px, rgba(0,0,0,0.018) 28px);
    }
    #app { width: 100%; max-width: 720px; min-height: 100vh; display: flex; flex-direction: column; }
    @media (min-width: 760px) {
      body { justify-content: flex-start; padding: 40px 24px; background-color: #e8e2d4; }
      #app { min-height: auto; border: 1px solid var(--border); box-shadow: 0 2px 12px rgba(0,0,0,.09); background: var(--paper); background-image: none; }
    }
    .masthead { text-align: center; padding: 24px 32px 0; }
    .rule-double { border: none; border-top: 4px double var(--ink); margin-bottom: 14px; }
    .rule-single { border: none; border-top: 1px solid var(--ink); margin-top: 12px; }
    .masthead h1 { font-family: 'Playfair Display', serif; font-size: 40px; font-weight: 900; letter-spacing: 6px; text-transform: uppercase; line-height: 1; }
    .masthead-sub { display: flex; align-items: center; justify-content: center; margin-top: 7px; font-size: 10px; color: var(--ink-muted); letter-spacing: 2px; text-transform: uppercase; flex-wrap: wrap; gap: 0; }
    .bull { margin: 0 9px; color: var(--red); font-size: 7px; }
    .edition-bar { display: flex; justify-content: space-between; align-items: center; padding: 5px 32px 14px; font-size: 10px; color: var(--ink-muted); border-bottom: 1px solid var(--border-light); font-style: italic; }
    .pill { font-style: normal; font-weight: 700; font-size: 9px; letter-spacing: 1.5px; text-transform: uppercase; border: 1px solid currentColor; padding: 1px 6px; }
    .pill-red { color: var(--red); }
    .pill-blue { color: var(--blue); }
    .view-body { padding: 22px 32px 28px; }
    .note-box { padding: 12px 14px; border-left: 3px solid var(--blue); background: var(--blue-light); font-size: 12px; color: var(--ink-light); line-height: 1.9; margin-bottom: 20px; }
    .note-box.red { border-left-color: var(--red); background: var(--red-light); }
    .note-title { font-size: 9.5px; letter-spacing: 1.5px; text-transform: uppercase; font-weight: 700; color: var(--blue); display: block; margin-bottom: 5px; }
    .note-box.red .note-title { color: var(--red); }
    .field-wrap { margin-bottom: 16px; }
    .field-wrap label { display: block; font-size: 9.5px; letter-spacing: 1.8px; text-transform: uppercase; color: var(--ink-muted); margin-bottom: 6px; }
    .field-wrap input, .field-wrap textarea { width: 100%; padding: 7px 0 5px; font-size: 14px; font-family: 'Noto Serif SC', serif; border: none; border-bottom: 1.5px solid var(--border); background: transparent; color: var(--ink); outline: none; transition: border-color 0.15s; }
    .field-wrap input::placeholder, .field-wrap textarea::placeholder { color: #c0b89e; font-style: italic; }
    .field-wrap input:focus, .field-wrap textarea:focus { border-bottom-color: var(--blue); }
    .field-wrap textarea { height: 160px; resize: vertical; padding: 8px; border: 1px solid var(--border); background: #fff; }
    .field-wrap:focus-within label { color: var(--blue); }
    .btn { width: 100%; padding: 12px 24px; font-size: 12px; font-weight: 700; font-family: 'Noto Serif SC', serif; letter-spacing: 2px; text-transform: uppercase; cursor: pointer; border: none; transition: background 0.15s; display: block; }
    .btn:active { opacity: 0.88; }
    .btn:disabled { cursor: not-allowed; opacity: 0.55; }
    .btn-blue { background: var(--blue); color: #f5f0e8; }
    .btn-blue:hover { background: var(--blue-hover); }
    .btn-red { background: var(--red); color: #f5f0e8; }
    .btn-outline { background: transparent; color: var(--blue); border: 1px solid var(--blue); margin-top: 10px; }
    .btn-outline:hover { background: var(--blue-light); }
    .mail-list { list-style: none; }
    .mail-item { border-bottom: 1px solid var(--border-light); padding: 14px 0; cursor: pointer; }
    .mail-item:hover { background: var(--blue-light); }
    .mail-meta { display: flex; justify-content: space-between; font-size: 10px; color: var(--ink-muted); letter-spacing: 1px; text-transform: uppercase; margin-bottom: 4px; }
    .mail-from { font-size: 14px; color: var(--ink); font-weight: 600; }
    .mail-subject { font-size: 13px; color: var(--ink-light); margin-top: 2px; }
    .mail-empty { text-align: center; padding: 60px 20px; color: var(--ink-muted); font-style: italic; }
    .mail-detail { background: #fff; border: 1px solid var(--border); padding: 20px; }
    .mail-detail-h { border-bottom: 1px solid var(--border-light); padding-bottom: 12px; margin-bottom: 12px; }
    .mail-detail-from { font-size: 13px; color: var(--ink); }
    .mail-detail-from span { color: var(--ink-muted); margin-right: 6px; font-size: 10px; letter-spacing: 1.5px; text-transform: uppercase; }
    .mail-detail-to { font-size: 13px; color: var(--ink-light); margin-top: 4px; }
    .mail-detail-to span { color: var(--ink-muted); margin-right: 6px; font-size: 10px; letter-spacing: 1.5px; text-transform: uppercase; }
    .mail-detail-date { font-size: 11px; color: var(--ink-muted); margin-top: 6px; font-style: italic; }
    .mail-detail-sub { font-size: 18px; font-weight: 700; color: var(--ink); margin: 16px 0 12px; font-family: 'Playfair Display', serif; }
    .mail-detail-body { font-size: 14px; line-height: 1.9; color: var(--ink); white-space: pre-wrap; word-break: break-word; }
    .key-card { background: #fff; border: 1px solid var(--border); padding: 16px; font-family: var(--mono); font-size: 11px; line-height: 1.6; word-break: break-all; margin-top: 10px; }
    .key-fp { color: var(--blue); font-weight: 700; font-size: 12px; letter-spacing: 1.5px; margin-bottom: 6px; }
    #toast { position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%) translateY(80px); background: var(--ink); color: var(--paper); padding: 9px 22px; font-size: 13px; letter-spacing: 0.5px; transition: transform 0.28s ease; z-index: 9999; white-space: nowrap; pointer-events: none; }
    #toast.show { transform: translateX(-50%) translateY(0); }
    .tabs { display: flex; border-bottom: 1px solid var(--border); margin-bottom: 16px; }
    .tab { flex: 1; padding: 10px; text-align: center; font-size: 11px; letter-spacing: 2px; text-transform: uppercase; color: var(--ink-muted); cursor: pointer; border-bottom: 2px solid transparent; }
    .tab.active { color: var(--blue); border-bottom-color: var(--blue); font-weight: 700; }
  </style>
</head>
<body>
<div id="app">

  <div id="home-view">
    <div class="masthead">
      <hr class="rule-double">
      <h1>SMTP</h1>
      <div class="masthead-sub">
        <span>端到端加密</span><span class="bull">◆</span>
        <span>X25519 ECDH · AES-GCM</span><span class="bull">◆</span>
        <span>X-CIPHER 扩展</span>
      </div>
      <hr class="rule-single">
    </div>
    <div class="edition-bar">
      <span>Cipher Post · 加密邮驿</span>
      <span class="pill pill-blue">v1</span>
    </div>
    <div class="view-body">
      <div class="note-box">
        <span class="note-title">🔐 协议说明</span>
        本服务基于 <strong>X-CIPHER</strong> 自定义扩展:用 X25519 ECDH 派生共享密钥,AES-GCM 加密邮件。密钥在浏览器本地,服务器不见明文。
      </div>
      <div class="tabs">
        <div class="tab active" data-tab="inbox" onclick="switchTab('inbox')">收件箱</div>
        <div class="tab" data-tab="compose" onclick="switchTab('compose')">发件箱</div>
        <div class="tab" data-tab="key" onclick="switchTab('key')">我的密钥</div>
      </div>

      <!-- Inbox -->
      <div id="inbox-panel">
        <div id="key-missing" style="display:none">
          <div class="note-box red">
            <span class="note-title">⚠️ 未检测到密钥</span>
            请先到「我的密钥」标签生成 X25519 密钥对。
          </div>
        </div>
        <ul class="mail-list" id="mail-list"></ul>
        <div class="mail-empty" id="mail-empty">收件箱空空如也</div>
      </div>

      <!-- Compose -->
      <div id="compose-panel" style="display:none">
        <div class="field-wrap">
          <label>收件人 (To)</label>
          <input type="text" id="to-addr" placeholder="bob@smtp.aillm.net">
        </div>
        <div class="field-wrap">
          <label>收件人 X25519 公钥 (Recipient Public Key)</label>
          <input type="text" id="to-fp" placeholder="44 chars base64" maxlength="44">
        </div>
        <div class="field-wrap">
          <label>主题 (Subject)</label>
          <input type="text" id="subject" placeholder="明文 (本地加密后上传)">
        </div>
        <div class="field-wrap">
          <label>正文 (Body)</label>
          <textarea id="body" placeholder="明文内容..."></textarea>
        </div>
        <button class="btn btn-blue" id="send-btn" onclick="sendMail()">加密并发送</button>
      </div>

      <!-- Key -->
      <div id="key-panel" style="display:none">
        <div class="note-box">
          <span class="note-title">🔑 密钥管理</span>
          密钥对存储在浏览器 localStorage。<strong>请妥善备份</strong>:私钥一旦丢失,加密邮件将永久无法解密。
        </div>
        <div class="key-card" id="key-display" style="display:none">
          <div class="key-fp">FP: <span id="key-fp"></span></div>
          <div style="color:var(--ink-muted);font-size:10px;margin-bottom:4px;letter-spacing:1.5px;">PUBLIC KEY (X25519, 32 BYTES · BASE64 · 分享此公钥给发件人)</div>
          <div id="key-pub"></div>
          <div style="color:var(--ink-muted);font-size:10px;margin:10px 0 4px;letter-spacing:1.5px;">PRIVATE KEY (X25519 PKCS8 · BASE64) — 保密</div>
          <div id="key-priv" style="color:var(--red)"></div>
        </div>
        <button class="btn btn-blue" id="gen-btn" onclick="generateKey()">生成新密钥对</button>
        <button class="btn btn-outline" onclick="exportKey()">导出备份</button>

        <div id="import-section" style="margin-top:24px">
          <div class="note-box" style="margin-bottom:14px">
            <span class="note-title">📥 导入已有密钥</span>
            已有密钥对?可粘贴 JSON 或 base64,或选择备份文件 (.json)。导入会<strong>覆盖</strong>当前密钥。
          </div>
          <div class="field-wrap">
            <label>粘贴 JSON 备份 或 base64 格式 (pub + 换行 + priv)</label>
            <textarea id="import-text" style="height:110px;font-family:var(--mono);font-size:12px;padding:10px;border:1px solid var(--border);background:#fff;resize:vertical" placeholder='{"pub":"base64...","priv":"base64..."}&#10;或两行 base64&#10;第一行 pub (44 chars)&#10;第二行 priv (64 chars pkcs8)'></textarea>
          </div>
          <button class="btn btn-outline" onclick="importKeyFromText()">从文本导入</button>
          <button class="btn btn-outline" onclick="document.getElementById('import-file').click()">从文件选择…</button>
          <input type="file" id="import-file" accept=".json,application/json" style="display:none" onchange="importKeyFromFile(event)">
        </div>
      </div>
    </div>
  </div>

  <!-- Mail detail (overlays home) -->
  <div id="detail-view" style="display:none">
    <div class="masthead">
      <hr class="rule-double">
      <h1>SMTP</h1>
      <div class="masthead-sub">
        <span>密件详情</span><span class="bull">◆</span><span>Cipher Detail</span>
      </div>
      <hr class="rule-single">
    </div>
    <div class="view-body">
      <div class="mail-detail" id="detail-card"></div>
      <button class="btn btn-outline" style="margin-top:16px" onclick="backToInbox()">← 返回收件箱</button>
    </div>
  </div>

</div>
<div id="toast"></div>

<script>
var KEY_STORAGE = 'smtp.aillm.net:x25519';
var currentTab = 'inbox';

function showToast(msg) {
  var t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(function() { t.classList.remove('show'); }, 2800);
}

function switchTab(name) {
  currentTab = name;
  document.querySelectorAll('.tab').forEach(function(el) {
    el.classList.toggle('active', el.dataset.tab === name);
  });
  document.getElementById('inbox-panel').style.display = name === 'inbox' ? 'block' : 'none';
  document.getElementById('compose-panel').style.display = name === 'compose' ? 'block' : 'none';
  document.getElementById('key-panel').style.display = name === 'key' ? 'block' : 'none';
  if (name === 'inbox') loadInbox();
  if (name === 'key') renderKey();
}

function showView(name) {
  document.getElementById('home-view').style.display = name === 'home' ? 'block' : 'none';
  document.getElementById('detail-view').style.display = name === 'detail' ? 'block' : 'none';
}

// ── 密钥管理 ──
async function generateKey() {
  // 单 X25519 密钥对: 用于 ECDH 派生共享密钥
  var kp = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  var pkRaw = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
  var skPkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
  // 存 base64 格式 (public 32 bytes, private 48 bytes pkcs8)
  var data = {
    pub: bytesToB64(pkRaw),
    priv: bytesToB64(skPkcs8)
  };
  localStorage.setItem(KEY_STORAGE, JSON.stringify(data));
  renderKey();
  showToast('✓ X25519 密钥对已生成');
}

function loadKey() {
  var s = localStorage.getItem(KEY_STORAGE);
  if (!s) return null;
  try { return JSON.parse(s); } catch (e) { return null; }
}

function renderKey() {
  var k = loadKey();
  var display = document.getElementById('key-display');
  if (!k) {
    display.style.display = 'none';
    document.getElementById('key-missing').style.display = 'block';
    return;
  }
  document.getElementById('key-missing').style.display = 'none';
  display.style.display = 'block';
  document.getElementById('key-fp').textContent = k.pub.slice(0, 16);
  document.getElementById('key-pub').textContent = k.pub;
  document.getElementById('key-priv').textContent = k.priv;
}

function exportKey() {
  var k = loadKey();
  if (!k) return showToast('请先生成密钥');
  var blob = new Blob([JSON.stringify(k, null, 2)], { type: 'application/json' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = 'smtp.aillm.net-key-' + k.pub.slice(0, 8) + '.json';
  a.click();
  URL.revokeObjectURL(url);
}

// 解析任意格式: JSON / pub+priv 两行 base64 或 hex / 整个一行 JSON
function parseKeyInput(text) {
  text = (text || '').trim();
  if (!text) return null;
  // 尝试 JSON
  if (text.startsWith('{')) {
    try {
      var j = JSON.parse(text);
      if (j && j.pub && j.priv) return { pub: j.pub.trim(), priv: j.priv.trim() };
    } catch (e) {}
  }
  // 尝试 pub+priv 两行 base64 或 hex
  var lines = text.split(String.fromCharCode(10)).map(function(l) { return l.trim(); }).filter(Boolean);
  var cleaned = []; lines.forEach(function(l) { while (l.length && l.charCodeAt(l.length - 1) === 13) l = l.slice(0, -1); if (l) cleaned.push(l); }); lines = cleaned;
  // base64 格式 (X25519: pub 44 chars / priv 64 chars pkcs8)
  if (lines.length === 2 && isValidBase64(lines[0]) && isValidBase64(lines[1])) {
    return { pub: lines[0], priv: lines[1] };
  }
  // 尝试 JSON 单行 (没换行)
  try {
    var j2 = JSON.parse(text);
    if (j2 && j2.pub && j2.priv) return { pub: j2.pub.trim(), priv: j2.priv.trim() };
  } catch (e) {}
  return null;
}

async function importKey(pubB64, privB64) {
  // 严格校验: X25519 公钥 32 bytes (base64 44 chars), 私钥 48 bytes pkcs8 (base64 64 chars)
  if (!isValidBase64(pubB64) || b64ToBytes(pubB64).length !== 32) {
    return showToast('❌ 公钥必须是 32 字节 X25519 (base64 44 字符)');
  }
  if (!isValidBase64(privB64) || b64ToBytes(privB64).length !== 48) {
    return showToast('❌ 私钥必须是 48 字节 X25519 pkcs8 (base64 64 字符)');
  }
  // 实际 import 一遍, 验证能跑
  try {
    var sk = await crypto.subtle.importKey('pkcs8', b64ToBytes(privB64),
      { name: 'X25519' }, false, ['deriveBits']);
    var pk = await importX25519PubKey(b64ToBytes(pubB64));
    // 派生共享密钥验证 round-trip (pk 在 derive 中只是数据, 不需 deriveBits usage)
    var shared = await crypto.subtle.deriveBits({ name: 'X25519', public: pk }, sk, 256);
    if (shared.byteLength !== 32) throw new Error('shared key length wrong');
  } catch (e) {
    return showToast('❌ 导入失败: ' + (e.message || e));
  }
  localStorage.setItem(KEY_STORAGE, JSON.stringify({ pub: pubB64, priv: privB64 }));
  renderKey();
  showToast('✓ 密钥已导入');
  if (currentTab === 'inbox') loadInbox();
}

function isValidBase64(s) {
  if (typeof s !== 'string') return false;
  // base64: A-Z a-z 0-9 + / = (padding)
  return /^[A-Za-z0-9+/]+={0,2}$/.test(s);
}

function importKeyFromText() {
  var text = document.getElementById('import-text').value;
  var k = parseKeyInput(text);
  if (!k) return showToast('❌ 无法解析: 请粘贴 JSON 或 pub+priv 两行 base64');
  importKey(k.pub, k.priv);
}

function importKeyFromFile(ev) {
  var f = ev.target.files && ev.target.files[0];
  if (!f) return;
  var reader = new FileReader();
  reader.onload = function() {
    var k = parseKeyInput(reader.result);
    if (!k) return showToast('❌ 文件格式无法解析');
    importKey(k.pub, k.priv);
  };
  reader.onerror = function() { showToast('❌ 读取文件失败'); };
  reader.readAsText(f);
  ev.target.value = ''; // 允许重选同一文件
}

// ── Inbox ──
async function loadInbox() {
  if (!loadKey()) { document.getElementById('key-missing').style.display = 'block'; return; }
  document.getElementById('key-missing').style.display = 'none';
  var res = await fetch('/api/inbox', {
    headers: { 'X-Auth': loadKey().pub.slice(0, 16) }
  });
  if (!res.ok) { showToast('加载失败'); return; }
  var mails = await res.json();
  var list = document.getElementById('mail-list');
  var empty = document.getElementById('mail-empty');
  list.innerHTML = '';
  if (!mails.length) { empty.style.display = 'block'; return; }
  empty.style.display = 'none';
  mails.forEach(function(m) {
    var li = document.createElement('li');
    li.className = 'mail-item';
    li.onclick = function() { openMail(m.id); };
    var date = new Date(m.created_at);
    li.innerHTML =
      '<div class="mail-meta"><span>' + date.toISOString().slice(0, 19).replace('T', ' ') + '</span><span>' +
        (m.read_at ? '已读' : '新件') + '</span></div>' +
      '<div class="mail-from">' + escapeHtml(m.from_addr) + '</div>' +
      '<div class="mail-subject">🔒 ' + escapeHtml(m.subject_preview) + '</div>';
    list.appendChild(li);
  });
}

async function openMail(id) {
  try {
  var k = loadKey();
  if (!k) { showToast('请先生成/导入密钥'); return; }
  var res = await fetch('/api/mail/' + id, {
    headers: { 'X-Auth': k.pub.slice(0, 16) }
  });
  if (!res.ok) { showToast('邮件不存在'); return; }
  var mail = await res.json();
  // 端到端解密: X25519 ECDH + AES-GCM
  // 需要 (自己的 X25519 sk, 发送方的 X25519 pk) 派生共享密钥
  if (!mail.from_pk) {
    throw new Error('邮件缺少发送方公钥 (旧版邮件不可读)');
  }
  var mySk = await crypto.subtle.importKey('pkcs8', b64ToBytes(k.priv),
    { name: 'X25519' }, false, ['deriveBits']);
  var theirPk = await importX25519PubKey(b64ToBytes(mail.from_pk));
  var sharedBits = await crypto.subtle.deriveBits(
    { name: 'X25519', public: theirPk }, mySk, 256
  );
  var sharedKey = new Uint8Array(sharedBits);
  var aesKey = await crypto.subtle.importKey('raw', sharedKey, 'AES-GCM', false, ['decrypt']);
  var subject = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64ToBytes(mail.subject_iv) }, aesKey, b64ToBytes(mail.subject_ct)
  );
  var body = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64ToBytes(mail.body_iv) }, aesKey, b64ToBytes(mail.body_ct)
  );
  sharedKey.fill(0);
  var date = new Date(mail.created_at);
  document.getElementById('detail-card').innerHTML =
    '<div class="mail-detail-h">' +
      '<div class="mail-detail-from"><span>From</span>' + escapeHtml(mail.from_addr) + '</div>' +
      '<div class="mail-detail-to"><span>To</span>' + escapeHtml(mail.to_addr) + '</div>' +
      '<div class="mail-detail-date">' + date.toISOString() + '</div>' +
    '</div>' +
    '<div class="mail-detail-sub">' + escapeHtml(new TextDecoder().decode(subject)) + '</div>' +
    '<div class="mail-detail-body">' + escapeHtml(new TextDecoder().decode(body)) + '</div>';
  showView('detail');
  loadInbox();
  } catch (e) {
    showToast('❌ 解密失败: ' + (e.message || e));
    console.error('openMail error:', e);
  }
}

function backToInbox() {
  showView('home');
  switchTab('inbox');
}

// ── Send ──
async function sendMail() {
  var k = loadKey();
  if (!k) return showToast('请先生成密钥');
  var to = document.getElementById('to-addr').value.trim();
  var toPkB64 = document.getElementById('to-fp').value.trim();
  var subject = document.getElementById('subject').value.trim();
  var body = document.getElementById('body').value.trim();
  if (!to || !toPkB64) return showToast('收件人地址 + X25519 公钥必填');
  if (!isValidBase64(toPkB64) || b64ToBytes(toPkB64).length !== 32) {
    return showToast('❌ 收件人公钥格式不对: 需 32 字节 X25519 公钥 (base64, 44 字符)');
  }

  var btn = document.getElementById('send-btn');
  btn.disabled = true; btn.textContent = '加密中…';
  try {
    // === 端到端加密: X25519 ECDH + AES-GCM ===
    // 1. 加载自己的私钥 + 接收方公钥
    var mySk = await crypto.subtle.importKey('pkcs8', b64ToBytes(k.priv),
      { name: 'X25519' }, false, ['deriveBits']);
    var theirPk = await importX25519PubKey(b64ToBytes(toPkB64));
    // 2. 派生共享密钥 (32 bytes)
    var sharedBits = await crypto.subtle.deriveBits(
      { name: 'X25519', public: theirPk }, mySk, 256
    );
    var sharedKey = new Uint8Array(sharedBits);
    // 3. 用共享密钥 + AES-GCM 加密主题和正文
    var aesKey = await crypto.subtle.importKey('raw', sharedKey, 'AES-GCM', false, ['encrypt']);
    var subIv = crypto.getRandomValues(new Uint8Array(12));
    var bodyIv = crypto.getRandomValues(new Uint8Array(12));
    var subCt = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: subIv }, aesKey, new TextEncoder().encode(subject || '(无主题)')
    );
    var bodyCt = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: bodyIv }, aesKey, new TextEncoder().encode(body)
    );
    // 4. 清理: 共享密钥在内存中也清掉
    sharedKey.fill(0);

    // 5. POST 到 server (携带发送方公钥, 接收方用来 ECDH 派生)
    var res = await fetch('/api/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        to: to,
        to_fp: toPkB64.slice(0, 16),       // 接收方 FP (公钥前 16 字符, 与 X-Auth 一致)
        from: k.pub.slice(0, 16) + '@smtp.aillm.net',  // 发送方 FP 作为地址
        from_pk: k.pub,                   // 发送方 X25519 公钥 (base64)
        from_fp: k.pub.slice(0, 16),      // 16 字符标识 (公钥前 16 字符)
        subject_ct: bytesToB64(new Uint8Array(subCt)),
        subject_iv: bytesToB64(subIv),
        body_ct: bytesToB64(new Uint8Array(bodyCt)),
        body_iv: bytesToB64(bodyIv),
      })
    });
    if (!res.ok) { showToast('发送失败: ' + res.status); return; }
    showToast('✓ 已端到端加密发送');
    document.getElementById('subject').value = '';
    document.getElementById('body').value = '';
    switchTab('inbox');
  } catch (e) {
    showToast('❌ 加密失败: ' + e.message);
    console.error('sendMail:', e);
  } finally {
    btn.disabled = false; btn.textContent = '加密并发送';
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, function(c) {
    return ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' })[c];
  });
}

// ── Crypto helpers ──
// X25519 公钥导入 (兼容不同浏览器对 usages 的处理)
async function importX25519PubKey(rawBytes) {
  try {
    return await crypto.subtle.importKey('raw', rawBytes, { name: 'X25519' }, true, []);
  } catch (e) {
    return await crypto.subtle.importKey('raw', rawBytes, { name: 'X25519' }, true, ['deriveBits']);
  }
}

function bytesToB64(bytes) {
  var bin = ''; for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function b64ToBytes(b64) {
  var bin = atob(b64);
  var out = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ── Init ──
loadInbox();
</script>
</body>
</html>`;

// ─── Worker 入口 ───
let dbInitPromise = null;
async function ensureSchema(env) {
  if (!dbInitPromise) {
    dbInitPromise = (async () => {
      // 步骤 1: 兜底建表 (idempotent, 表存在则跳过)
      await env.MAIL_DB.batch([
        env.MAIL_DB.prepare(`CREATE TABLE IF NOT EXISTS mail (
          id          TEXT PRIMARY KEY,
          to_addr     TEXT NOT NULL,
          to_fp       TEXT NOT NULL,
          from_addr   TEXT NOT NULL,
          from_fp     TEXT NOT NULL,
          from_pk     TEXT NOT NULL DEFAULT '',
          subject_ct  TEXT NOT NULL,
          subject_iv  TEXT NOT NULL,
          body_ct     TEXT NOT NULL,
          body_iv     TEXT NOT NULL,
          size        INTEGER NOT NULL,
          created_at  INTEGER NOT NULL,
          read_at     INTEGER
        )`),
        env.MAIL_DB.prepare(`CREATE INDEX IF NOT EXISTS idx_to_addr_created ON mail (to_addr, created_at DESC)`),
        env.MAIL_DB.prepare(`CREATE INDEX IF NOT EXISTS idx_to_fp_created  ON mail (to_fp, created_at DESC)`),
      ]);
      // 步骤 2: 升级 - 旧版 mail 表没有 from_pk 列, 加上
      // duplicate column = 已迁移过, 静默忽略
      // 任何其他错误都抛出, 不再 DROP TABLE
      try {
        await env.MAIL_DB.prepare(
          `ALTER TABLE mail ADD COLUMN from_pk TEXT NOT NULL DEFAULT ''`
        ).run();
      } catch (e) {
        if (!(e.message && /duplicate column/i.test(e.message))) {
          throw e;
        }
      }
    })();
  }
  // 修 I7: 失败时重置 dbInitPromise, 让后续请求可重试
  // 否则 isolate 终身 500, 直到 Cloudflare 回收
  try {
    await dbInitPromise;
  } catch (e) {
    dbInitPromise = null;
    throw e;
  }
  return dbInitPromise;
}

var worker_default = {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (env.MAIL_DB) await ensureSchema(env);

    // SPA
    if (url.pathname === '/' || url.pathname === '/index.html') {
      return new Response(HTML_TEMPLATE, {
        headers: { 'Content-Type': 'text/html;charset=UTF-8' }
      });
    }

    // GET /api/key/:fp — 查公钥
    if (url.pathname.startsWith('/api/key/') && request.method === 'GET') {
      const fp = url.pathname.slice(9);
      const pub = await env.KEYRING_KV.get('pub:' + fp);
      if (!pub) return new Response('Not Found', { status: 404 });
      return new Response(pub, { headers: { 'Content-Type': 'text/plain' } });
    }

    // PUT /api/key — 注册公钥
    if (url.pathname === '/api/key' && request.method === 'PUT') {
      const { fp, pub } = await request.json();
      if (!fp || !pub) return new Response('Bad Request', { status: 400 });
      await env.KEYRING_KV.put('pub:' + fp, pub, { expirationTtl: 86400 * 365 });
      return new Response('ok');
    }

    // POST /api/send — 接收加密邮件
    if (url.pathname === '/api/send' && request.method === 'POST') {
      const m = await request.json();
      // 必须字段: to, to_fp, from, from_pk, subject_ct, body_ct
      if (!m.to || !m.to_fp || !m.from || !m.from_pk || !m.subject_ct || !m.body_ct) {
        return new Response('Bad Request (need: to, to_fp, from, from_pk, subject_ct, body_ct)', { status: 400 });
      }
      // 简单长度校验, 防滥用 (base64 字符数, 原始密文约 150KB)
      const MAX_CT_LEN = 200000;
      if (m.subject_ct.length > MAX_CT_LEN || m.body_ct.length > MAX_CT_LEN) {
        return new Response('Payload too large', { status: 413 });
      }
      const id = makeMessageId();
      const created = Date.now();
      // size 字段: 密文总字节数 (base64 字符串长度)
      const size = (m.subject_ct || '').length + (m.body_ct || '').length;
      await env.MAIL_DB.prepare(
        `INSERT INTO mail (id, to_addr, to_fp, from_addr, from_fp, from_pk, subject_ct, subject_iv, body_ct, body_iv, size, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        id, m.to, m.to_fp, m.from, m.from_fp, m.from_pk,
        m.subject_ct, m.subject_iv, m.body_ct, m.body_iv,
        size, created
      ).run();
      return new Response(JSON.stringify({ id }), { headers: { 'Content-Type': 'application/json' } });
    }

    // GET /api/inbox — 拉取收件箱 (按 to_fp 过滤)
    if (url.pathname === '/api/inbox' && request.method === 'GET') {
      const fp = request.headers.get('X-Auth');
      if (!fp) return new Response('Auth required', { status: 401 });
      // 接收方需要拿到发送方的公钥 (from_pk) 才能 ECDH 派生共享密钥解密
      const { results } = await env.MAIL_DB.prepare(
        `SELECT id, from_addr, from_fp, from_pk, to_addr, subject_ct, created_at, read_at FROM mail WHERE to_fp = ? ORDER BY created_at DESC LIMIT 50`
      ).bind(fp).all();
      const mails = (results || []).map(r => ({
        id: r.id,
        from_addr: r.from_addr,
        from_fp: r.from_fp,
        from_pk: r.from_pk,         // 关键: 接收方 ECDH 用的发送方公钥
        to_addr: r.to_addr,
        subject_preview: '(encrypted)',
        created_at: r.created_at,
        read_at: r.read_at,
      }));
      return new Response(JSON.stringify(mails), { headers: { 'Content-Type': 'application/json' } });
    }

    // GET /api/mail/:id — 读取单封 (含密文)
    if (url.pathname.startsWith('/api/mail/') && request.method === 'GET') {
      const id = url.pathname.slice(10);
      const fp = request.headers.get('X-Auth');
      if (!fp) return new Response('Auth required', { status: 401 });
      const row = await env.MAIL_DB.prepare(
        `SELECT * FROM mail WHERE id = ? AND to_fp = ?`
      ).bind(id, fp).first();
      if (!row) return new Response('Not Found', { status: 404 });
      // 标记已读
      if (!row.read_at) {
        await env.MAIL_DB.prepare(`UPDATE mail SET read_at = ? WHERE id = ?`)
          .bind(Date.now(), id).run();
      }
      return new Response(JSON.stringify(row), { headers: { 'Content-Type': 'application/json' } });
    }

    // ── SMTP 协议层 demo ──
    // POST /api/smtp/feed — 喂一行 SMTP 协议, 返回 reply
    //   - 首次请求:  body { line, fp?, pubkey? }  无 sid
    //   - 后续请求:  body { line, sid }  客户端用 sid 续接 session
    //   - 状态:     存在 KV (sid → 序列化 session), TTL 5 分钟
    //   - 现状:     协议层 demo, 状态机完整性留此出口, 前端未使用
    if (url.pathname === '/api/smtp/feed' && request.method === 'POST') {
      const body = await request.json();
      const line = body.line || '';
      let session, sid = body.sid;

      if (sid) {
        const saved = await env.KEYRING_KV.get('smtp:session:' + sid, 'json');
        if (saved) {
          session = Object.assign(new SmtpSession(), saved);
          // 重新注入 challenge (Uint8Array 无法 JSON 序列化)
          session.challenge = makeChallenge();
          session.onAuthVerify = async (challenge, sigB64) => {
            if (!saved.pubkey) return false;
            return await verifyChallenge(challenge, sigB64, b64ToBytes(saved.pubkey));
          };
        }
      }
      if (!session) {
        session = new SmtpSession();
        session.challenge = makeChallenge();
        sid = crypto.randomUUID().split('-')[0];
        session.onAuthVerify = async (challenge, sigB64) => {
          if (!body.pubkey) return false;
          return await verifyChallenge(challenge, sigB64, b64ToBytes(body.pubkey));
        };
      }

      const reply = await session.feed(line);

      // 持久化 (去掉 onAuthVerify 引用, 重新注入)
      const persistable = {
        state: session.state,
        hostname: session.hostname,
        maxSize: session.maxSize,
        cipherVersion: session.cipherVersion,
        extensions: session.extensions,
        supportedAuth: session.supportedAuth,
        authed: session.authed,
        mailFrom: session.mailFrom,
        rcptTo: session.rcptTo,
        data: session.data,
        dataSize: session.dataSize,
        peerFingerprint: session.peerFingerprint || null,
        pubkey: body.pubkey || null,
      };
      await env.KEYRING_KV.put('smtp:session:' + sid, JSON.stringify(persistable), { expirationTtl: 300 });

      return new Response(JSON.stringify({ sid, reply: reply.serialize() }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response('Not Found', { status: 404 });
  }
};

export { worker_default as default };

