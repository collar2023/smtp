-- D1 schema for smtp worker (X25519 ECDH 版本)
CREATE TABLE IF NOT EXISTS mail (
  id          TEXT PRIMARY KEY,    -- 16 hex chars (64 bit)
  to_addr     TEXT NOT NULL,       -- 接收方 SMTP 地址
  to_fp       TEXT NOT NULL,       -- 接收方 fp (16 字符 base64 前缀)
  from_addr   TEXT NOT NULL,
  from_fp     TEXT NOT NULL,       -- 发送方 fp (16 字符 base64 前缀)
  from_pk     TEXT NOT NULL DEFAULT '',  -- 发送方 X25519 公钥 (base64 44 字符), 接收方 ECDH 用
  subject_ct  TEXT NOT NULL,
  subject_iv  TEXT NOT NULL,
  body_ct     TEXT NOT NULL,
  body_iv     TEXT NOT NULL,
  size        INTEGER NOT NULL,    -- 密文总字节数
  created_at  INTEGER NOT NULL,
  read_at     INTEGER
);

CREATE INDEX IF NOT EXISTS idx_to_addr_created ON mail (to_addr, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_to_fp_created  ON mail (to_fp, created_at DESC);
