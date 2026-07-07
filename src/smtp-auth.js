// smtp-auth.js
// X-CIPHER 鉴权层: Ed25519 挑战签名 (用于 /api/smtp/feed 协议层 demo)

import { bytesToB64, b64ToBytes } from './smtp-codec.js';

export function makeChallenge() {
  const c = new Uint8Array(32);
  crypto.getRandomValues(c);
  return c;
}

export async function verifyChallenge(challenge, signatureB64, publicKey) {
  try {
    const key = await crypto.subtle.importKey(
      'raw', publicKey, { name: 'Ed25519' }, false, ['verify']
    );
    const sig = b64ToBytes(signatureB64);
    return await crypto.subtle.verify('Ed25519', key, sig, challenge);
  } catch (e) {
    return false;
  }
}
