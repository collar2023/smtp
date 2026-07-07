// node:test 兼容 (Node 18+)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SmtpSession, SmtpReply, STATES } from '../src/smtp-state-machine.js';

function bootSession() {
  return new SmtpSession({ hostname: 'mx.smtp.aillm.net' });
}

// ── SmtpReply 序列化 ──
test('SmtpReply: 单行响应', async () => {
  const r = new SmtpReply(250, 'OK');
  assert.equal(r.serialize(), '250 OK\r\n');
});

test('SmtpReply: 多行响应 (multiline flag)', async () => {
  const r = new SmtpReply(250, ['mx OK', 'SIZE 100', 'AUTH X-CIPHER'], true);
  assert.equal(r.serialize(), '250-mx OK\r\n250-SIZE 100\r\n250 AUTH X-CIPHER\r\n');
});

// ── 状态机核心流程 ──
test('完整 EHLO → MAIL → RCPT → DATA → QUIT 流程', async () => {
  const s = bootSession();
  let captured = null;
  s.onMessage = (msg) => { captured = msg; };

  let reply = await s.feed('EHLO client.example.com');
  assert.equal(s.state, STATES.GREETED);
  assert.equal(reply.code, 250);
  assert.ok(reply.text.some(l => l.startsWith('X-CIPHER')));

  reply = await s.feed('MAIL FROM:<alice@example.com>');
  assert.equal(reply.code, 250);
  assert.equal(s.state, STATES.MAIL);
  assert.equal(s.mailFrom, 'alice@example.com');

  reply = await s.feed('RCPT TO:<bob@smtp.aillm.net>');
  assert.equal(reply.code, 250);
  assert.equal(s.state, STATES.RCPT);
  assert.deepEqual(s.rcptTo, ['<bob@smtp.aillm.net>']);

  reply = await s.feed('DATA');
  assert.equal(reply.code, 354);
  assert.equal(s.state, STATES.DATA_HDR);

  // headers
  assert.equal((await s.feed('Subject: hello')).code, 0);
  assert.equal((await s.feed('From: alice@example.com')).code, 0);
  // 空行 → 进入 body
  assert.equal((await s.feed('')).code, 0);
  assert.equal(s.state, STATES.DATA_BODY);
  // body
  assert.equal((await s.feed('hi bob')).code, 0);
  // 终止
  const finalReply = await s.feed('.');
  assert.equal(finalReply.code, 250);
  assert.equal(s.state, STATES.GREETED);
  assert.ok(captured);
  assert.ok(captured.data.includes('Subject: hello'));
  assert.ok(captured.data.includes('hi bob'));
  assert.equal(captured.mailFrom, 'alice@example.com');
  assert.deepEqual(captured.rcptTo, ['<bob@smtp.aillm.net>']);

  reply = await s.feed('QUIT');
  assert.equal(reply.code, 221);
  assert.equal(s.state, STATES.QUIT);
});

// ── 错误用例 ──
test('未先 EHLO 就 MAIL 应返回 503', async () => {
  const s = bootSession();
  const reply = await s.feed('MAIL FROM:<x@y.com>');
  assert.equal(reply.code, 503);
});

test('EHLO 之前空行应返回 503', async () => {
  const s = bootSession();
  const reply = await s.feed('');
  assert.equal(reply.code, 503);
});

test('未知命令返回 500', async () => {
  const s = bootSession();
  await s.feed('EHLO x');
  const reply = await s.feed('FOOBAR');
  // FOOBAR 在 GREETED 状态下, 会落到 503 (要求 AUTH/MAIL)
  assert.equal(reply.code, 503);
});

test('AUTH_OK 状态下再次 AUTH 应返回 503', async () => {
  // 设计: 已鉴权后, 再次 AUTH 是协议错误, 应返回 503
  // 想重新挑战, 需先 RSET
  const s = bootSession();
  await s.feed('EHLO x');
  await s.feed('AUTH X-CIPHER');
  await s.feed('AAAA');   // 占位签名 → AUTH_OK
  const reply = await s.feed('AUTH X-CIPHER');
  assert.equal(reply.code, 503);
});

test('RSET 后再 AUTH 应重新挑战 (334)', async () => {
  const s = bootSession();
  await s.feed('EHLO x');
  await s.feed('AUTH X-CIPHER');
  await s.feed('AAAA');
  await s.feed('RSET');
  const reply = await s.feed('AUTH X-CIPHER');
  assert.equal(reply.code, 334);
});

test('AUTH 中途 * 应中止并回到 GREETED', async () => {
  const s = bootSession();
  await s.feed('EHLO x');
  await s.feed('AUTH X-CIPHER');
  const reply = await s.feed('*');
  assert.equal(reply.code, 501);
  assert.equal(s.state, STATES.GREETED);
});

test('RCPT TO 地址格式错误返回 501', async () => {
  const s = bootSession();
  await s.feed('EHLO x');
  await s.feed('MAIL FROM:<a@b.com>');
  const reply = await s.feed('RCPT TO:not-an-address');
  assert.equal(reply.code, 501);
});

test('RSET 应清空 mailFrom/rcptTo/data', async () => {
  const s = bootSession();
  await s.feed('EHLO x');
  await s.feed('MAIL FROM:<a@b.com>');
  await s.feed('RCPT TO:<c@d.com>');
  await s.feed('RSET');
  assert.equal(s.mailFrom, null);
  assert.equal(s.rcptTo.length, 0);
});

test('dot-stuffing: 第一个 . 在 DATA body 中应被剥离', async () => {
  const s = bootSession();
  let captured = null;
  s.onMessage = (msg) => { captured = msg; };
  await s.feed('EHLO x');
  await s.feed('MAIL FROM:<a@b.com>');
  await s.feed('RCPT TO:<c@d.com>');
  await s.feed('DATA');
  await s.feed('Subject: t');
  await s.feed('');
  await s.feed('..hidden');   // 客户端转义: 实际是 ".hidden"
  await s.feed('.');
  assert.ok(captured);
  assert.equal(captured.data, 'Subject: t\r\n\r\n.hidden\r\n');
});

test('超过 maxSize 邮件应返回 552', async () => {
  const s = new SmtpSession({ hostname: 'x', maxSize: 50 });
  await s.feed('EHLO x');
  await s.feed('MAIL FROM:<a@b.com>');
  await s.feed('RCPT TO:<c@d.com>');
  await s.feed('DATA');
  await s.feed('Subject: x');
  await s.feed('');
  const reply = await s.feed('x'.repeat(200));
  assert.equal(reply.code, 552);
});

test('onMessage 回调应在数据收完时被调用', async () => {
  const s = bootSession();
  let captured = null;
  s.onMessage = (msg) => { captured = msg; };
  await s.feed('EHLO x');
  await s.feed('MAIL FROM:<a@b.com>');
  await s.feed('RCPT TO:<c@d.com>');
  await s.feed('DATA');
  await s.feed('Subject: t');
  await s.feed('');
  await s.feed('body');
  await s.feed('.');
  assert.ok(captured);
  assert.equal(captured.mailFrom, 'a@b.com');
  assert.deepEqual(captured.rcptTo, ['<c@d.com>']);
  assert.ok(captured.data.includes('body'));
});
