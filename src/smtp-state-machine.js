// smtp-state-machine.js
// RFC 5321 SMTP 对话状态机 (纯逻辑,无 IO)
// 经典协议美: 每个状态转换都是纯函数, 可单测

import { bytesToB64 } from './smtp-codec.js';
import { makeChallenge } from './smtp-auth.js';

export const STATES = Object.freeze({
  CONNECT:   'CONNECT',   // 初始, 等待 EHLO/HELO
  GREETED:   'GREETED',   // 收到 EHLO/HELO, 等待 AUTH 或 MAIL FROM
  AUTH_CHAL: 'AUTH_CHAL', // 已发出 challenge, 等待签名的 base64
  AUTH_OK:   'AUTH_OK',   // 鉴权成功, 等待 MAIL FROM
  MAIL:      'MAIL',      // 已收到 MAIL FROM, 等待 RCPT TO
  RCPT:      'RCPT',      // 已收到至少一个 RCPT TO, 等待 DATA 或更多 RCPT
  DATA_HDR:  'DATA_HDR',  // 已收到 DATA, 正在接收 headers
  DATA_BODY: 'DATA_BODY', // headers 结束 (\r\n\r\n), 接收 body 直到 <CR><LF>.<CR><LF>
  QUIT:      'QUIT',      // 收到 QUIT, 准备关闭
});

export class SmtpReply {
  constructor(code, text, multiline = false) {
    this.code = code;
    this.text = Array.isArray(text) ? text : [text];
    this.multiline = multiline;
  }
  // RFC 5321 §4.2: 多行响应, 除最后一行外每行 "code-", 最后一行 "code "
  serialize() {
    if (this.text.length === 1 && !this.multiline) {
      return `${this.code} ${this.text[0]}\r\n`;
    }
    return this.text
      .map((line, i) =>
        i === this.text.length - 1
          ? `${this.code} ${line}\r\n`
          : `${this.code}-${line}\r\n`
      )
      .join('');
  }
}

export class SmtpSession {
  constructor({ hostname = 'mx.smtp.aillm.net', maxSize = 52428800, cipherVersion = 'v1' } = {}) {
    this.hostname = hostname;
    this.maxSize = maxSize;
    this.cipherVersion = cipherVersion;
    this.state = STATES.CONNECT;
    this.extensions = ['SIZE ' + maxSize, '8BITMIME', 'X-CIPHER ' + cipherVersion];
    this.authed = false;
    this.supportedAuth = ['X-CIPHER']; // 自定义 challenge-response 鉴权
    this.mailFrom = null;
    this.rcptTo = [];
    this.data = '';
    this.dataSize = 0;
    this.challenge = null;     // Uint8Array, AUTH 阶段
    this.peerFingerprint = null;
  }

  // 公开入口: 喂一行 client 命令 (不含 \r\n), 返回 SmtpReply
  // 注意: DATA 接收过程中可能返回 null (继续接收), 这里包装为伪 reply (code 0)
  async feed(line) {
    const trimmed = (line || '').replace(/\r$/, '');
    const r = await this.#transition(trimmed);
    return r || new SmtpReply(0, 'CONTINUE');
  }

  #transition(line) {
    // DATA 模式特殊处理 (lines 包含 \r\n)
    if (this.state === STATES.DATA_BODY) {
      return this.#dataBody(line);
    }

    // 修复 #2: AUTH_CHAL 状态下不 toUpperCase, base64 保持原样
    // 整行就是 base64 签名, 不解析 verb
    if (this.state === STATES.AUTH_CHAL) {
      return this.#onAuthChal('', line, line);
    }

    const parts = line.split(' ');
    const verb = parts[0].toUpperCase();
    const args = parts.slice(1).join(' ');

    switch (this.state) {
      case STATES.CONNECT:
        return this.#onConnect(verb, args, line);
      case STATES.GREETED:
        return this.#onGreeted(verb, args, line);
      case STATES.AUTH_CHAL:  // 上面已处理, 这里不会被命中
        return new SmtpReply(451, '4.3.0 Internal state error');
      case STATES.AUTH_OK:
        return this.#onAuthOk(verb, args, line);
      case STATES.MAIL:
        return this.#onMail(verb, args, line);
      case STATES.RCPT:
        return this.#onRcpt(verb, args, line);
      case STATES.DATA_HDR:
        return this.#onDataHdr(verb, args, line);
      case STATES.QUIT:
        return new SmtpReply(221, '2.0.0 Bye');
      default:
        return new SmtpReply(451, '4.3.0 Internal state error');
    }
  }

  #onConnect(verb, args, raw) {
    if (verb === 'EHLO') {
      this.state = STATES.GREETED;
      return this.#ehloReply();
    }
    if (verb === 'HELO') {
      this.state = STATES.GREETED;
      return new SmtpReply(250, this.hostname + ' Hello');
    }
    if (verb === 'QUIT') {
      this.state = STATES.QUIT;
      return new SmtpReply(221, '2.0.0 Bye');
    }
    if (!verb) {
      return new SmtpReply(503, '5.5.1 Send HELO/EHLO first');
    }
    if (verb === 'NOOP') {
      return new SmtpReply(250, '2.0.0 OK');
    }
    return new SmtpReply(503, '5.5.1 Send HELO/EHLO first');
  }

  #ehloReply() {
    const lines = [this.hostname + ' Hello', ...this.extensions];
    if (this.supportedAuth.length) {
      lines.push('AUTH ' + this.supportedAuth.join(' '));
    }
    return new SmtpReply(250, lines, true);
  }

  #onGreeted(verb, args, raw) {
    if (verb === 'AUTH' && args.toUpperCase().startsWith('X-CIPHER')) {
      // 修复 #4: 用真随机 challenge, 防止重放
      this.challenge = makeChallenge();
      this.state = STATES.AUTH_CHAL;
      return new SmtpReply(334, bytesToB64(this.challenge));
    }
    if (verb === 'MAIL' && args.toUpperCase().startsWith('FROM:')) {
      return this.#startMail(args.slice(5));
    }
    if (verb === 'QUIT') {
      this.state = STATES.QUIT;
      return new SmtpReply(221, '2.0.0 Bye');
    }
    if (verb === 'NOOP') return new SmtpReply(250, '2.0.0 OK');
    if (verb === 'RSET') {
      this.#reset();
      return new SmtpReply(250, '2.0.0 OK');
    }
    return new SmtpReply(503, '5.5.1 AUTH or MAIL FROM required');
  }

  async #onAuthChal(verb, args, raw) {
    // client 回复 base64( signature(challenge, privateKey) )
    if (verb === 'AUTH') {
      // 重新挑战 — 用真随机
      const c = makeChallenge();
      this.challenge = c;
      return new SmtpReply(334, bytesToB64(c));
    }
    if (verb === '*' || raw === '*') {
      this.state = STATES.GREETED;
      return new SmtpReply(501, '5.0.0 Auth aborted');
    }
    if (verb !== '') {
      return new SmtpReply(501, '5.5.4 Syntax error');
    }
    if (!raw) {
      this.state = STATES.GREETED;
      return new SmtpReply(501, '5.0.0 Auth aborted');
    }
    // 验证由外部 onAuthVerify 回调完成
    // 修复 #3: 必须 await, 否则 Promise 对象恒为 truthy, 任何签名都"通过"
    if (typeof this.onAuthVerify === 'function') {
      const ok = await this.onAuthVerify(this.challenge, raw);
      if (!ok) {
        this.state = STATES.GREETED;
        return new SmtpReply(535, '5.7.8 Authentication failed');
      }
    }
    this.authed = true;
    this.peerFingerprint = raw.slice(0, 16);
    this.state = STATES.AUTH_OK;
    return new SmtpReply(235, '2.7.0 Authentication successful');
  }

  #onAuthOk(verb, args, raw) {
    if (verb === 'MAIL' && args.toUpperCase().startsWith('FROM:')) {
      return this.#startMail(args.slice(5));
    }
    if (verb === 'AUTH') {
      return new SmtpReply(503, '5.5.1 Already authenticated');
    }
    if (verb === 'QUIT') {
      this.state = STATES.QUIT;
      return new SmtpReply(221, '2.0.0 Bye');
    }
    if (verb === 'RSET') {
      this.#reset();
      return new SmtpReply(250, '2.0.0 OK');
    }
    return new SmtpReply(503, '5.5.1 MAIL FROM required');
  }

  #onMail(verb, args, raw) {
    if (verb === 'RCPT' && args.toUpperCase().startsWith('TO:')) {
      const addr = args.slice(3);
      if (!this.#isValidAddr(addr)) {
        return new SmtpReply(501, '5.1.3 Bad recipient address');
      }
      this.rcptTo.push(addr);
      this.state = STATES.RCPT;
      return new SmtpReply(250, '2.1.5 Recipient ok');
    }
    if (verb === 'QUIT') {
      this.state = STATES.QUIT;
      return new SmtpReply(221, '2.0.0 Bye');
    }
    if (verb === 'RSET') {
      this.#reset();
      return new SmtpReply(250, '2.0.0 OK');
    }
    return new SmtpReply(503, '5.5.1 RCPT TO required');
  }

  #onRcpt(verb, args, raw) {
    if (verb === 'RCPT' && args.toUpperCase().startsWith('TO:')) {
      const addr = args.slice(3);
      if (!this.#isValidAddr(addr)) {
        return new SmtpReply(501, '5.1.3 Bad recipient address');
      }
      this.rcptTo.push(addr);
      return new SmtpReply(250, '2.1.5 Recipient ok');
    }
    if (verb === 'DATA') {
      this.state = STATES.DATA_HDR;
      this.data = '';
      this.dataSize = 0;
      return new SmtpReply(354, 'End data with <CR><LF>.<CR><LF>');
    }
    if (verb === 'QUIT') {
      this.state = STATES.QUIT;
      return new SmtpReply(221, '2.0.0 Bye');
    }
    if (verb === 'RSET') {
      this.#reset();
      return new SmtpReply(250, '2.0.0 OK');
    }
    return new SmtpReply(503, '5.5.1 DATA or RCPT TO required');
  }

  #onDataHdr(verb, args, raw) {
    // DATA_HDR 状态下, 任何非空行都视为 header
    // 空行表示 headers 结束, 进入 body (空行也写入 data 以分隔)
    if (raw === '') {
      this.data += '\r\n';
      this.dataSize += 2;
      this.state = STATES.DATA_BODY;
      return null; // 继续接收
    }
    this.data += raw + '\r\n';
    this.dataSize += raw.length + 2;
    if (this.dataSize > this.maxSize) {
      this.state = STATES.GREETED;
      this.#reset();
      return new SmtpReply(552, '5.3.4 Message size exceeds limit');
    }
    return null;
  }

  #dataBody(raw) {
    // 终止符: 单行 "."
    if (raw === '.') {
      // 邮件接收完毕, 触发回调 (外部可注册 onMessage)
      if (typeof this.onMessage === 'function') {
        try {
          this.onMessage({
            mailFrom: this.mailFrom,
            rcptTo: [...this.rcptTo],
            data: this.data,
          });
        } catch (e) {
          this.state = STATES.GREETED;
          this.#reset();
          return new SmtpReply(451, '4.3.0 Message processing failed');
        }
      }
      this.state = STATES.GREETED;
      this.#reset();
      return new SmtpReply(250, '2.0.0 Ok: queued as cipher message');
    }
    // dot-stuffing: 首字符 "." 表示客户端转义, 去掉第一个 "."
    const line = raw.startsWith('.') ? raw.slice(1) : raw;
    this.data += line + '\r\n';
    this.dataSize += line.length + 2;
    if (this.dataSize > this.maxSize) {
      this.state = STATES.GREETED;
      this.#reset();
      return new SmtpReply(552, '5.3.4 Message size exceeds limit');
    }
    return null;
  }

  #startMail(fromField) {
    // 简化: 只取 <addr>
    const m = fromField.match(/<([^>]+)>/);
    if (!m) {
      return new SmtpReply(501, '5.1.7 Bad sender address syntax');
    }
    this.mailFrom = m[1];
    this.rcptTo = [];
    this.state = STATES.MAIL;
    return new SmtpReply(250, '2.1.0 Sender ok');
  }

  #isValidAddr(addr) {
    return /^<[^<>\s]+@[^<>\s]+>$/.test(addr);
  }

  #reset() {
    this.mailFrom = null;
    this.rcptTo = [];
    this.data = '';
    this.dataSize = 0;
    this.state = STATES.GREETED;
  }
}


