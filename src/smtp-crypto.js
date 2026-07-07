// smtp-crypto.js
// 邮件 id 生成 (16 hex chars, 64 bit entropy)
// 加密逻辑 (X25519 ECDH + AES-GCM) 在 SPA / CLI 中内联实现,
// 保留此模块仅为 makeMessageId 一个工具函数

export function makeMessageId() {
  const r = crypto.getRandomValues(new Uint8Array(8));
  return Array.from(r).map(b => b.toString(16).padStart(2, '0')).join('');
}
