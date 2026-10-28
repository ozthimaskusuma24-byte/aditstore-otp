PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'customer' CHECK (role IN ('customer','admin')),
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS wallets (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  balance INTEGER NOT NULL DEFAULT 0 CHECK (balance >= 0),
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS wallet_transactions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('topup','purchase','refund','adjustment')),
  amount INTEGER NOT NULL,
  reference TEXT NOT NULL UNIQUE,
  note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS wallet_transaction_apply
AFTER INSERT ON wallet_transactions
BEGIN
  UPDATE wallets
  SET balance = balance + NEW.amount,
      updated_at = NEW.created_at
  WHERE user_id = NEW.user_id;
END;

CREATE TABLE IF NOT EXISTS topups (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  merchant_ref TEXT NOT NULL UNIQUE,
  gateway_reference TEXT,
  amount INTEGER NOT NULL CHECK (amount > 0),
  method TEXT NOT NULL DEFAULT 'QRIS2',
  status TEXT NOT NULL DEFAULT 'CREATING',
  qr_url TEXT,
  pay_url TEXT,
  pay_code TEXT,
  expires_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_topups_user_created ON topups(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS orders (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  idempotency_key TEXT NOT NULL,
  upstream_order_id TEXT UNIQUE,
  service_id TEXT NOT NULL,
  service_name TEXT NOT NULL,
  provider TEXT NOT NULL,
  country_code TEXT NOT NULL,
  provider_id TEXT NOT NULL,
  upstream_price INTEGER NOT NULL,
  sell_price INTEGER NOT NULL,
  number TEXT,
  status TEXT NOT NULL DEFAULT 'processing',
  otp_code TEXT,
  otp_message TEXT,
  expires_at TEXT,
  refunded_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(user_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS idx_orders_user_created ON orders(user_id, created_at DESC);
