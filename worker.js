const NOKOS_BASE = 'https://nokospusat.com';
const TRIPAY_PRODUCTION = 'https://tripay.co.id/api';
const TRIPAY_SANDBOX = 'https://tripay.co.id/api-sandbox';
const encoder = new TextEncoder();

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      ...extraHeaders
    }
  });
}
function fail(message, status = 400, code = 'bad_request') {
  return json({ error: { code, message } }, status);
}
function nowIso() { return new Date().toISOString(); }
function id() { return crypto.randomUUID(); }
function safeInt(value, min, max) {
  const n = Number(value);
  return Number.isSafeInteger(n) && n >= min && n <= max ? n : null;
}
function b64url(bytes) {
  let str = '';
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function fromB64url(text) {
  const padded = text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - text.length % 4) % 4);
  const raw = atob(padded);
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}
function hex(bytes) { return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join(''); }
async function hmacBytes(secret, message) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, typeof message === 'string' ? encoder.encode(message) : message));
}
async function hmacHex(secret, message) { return hex(await hmacBytes(secret, message)); }
function timingSafeTextEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
async function passwordHash(password, saltText) {
  const salt = saltText ? fromB64url(saltText) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 150000, hash: 'SHA-256' }, key, 256);
  return { salt: b64url(salt), hash: b64url(new Uint8Array(bits)) };
}
async function makeSession(userId, env) {
  const payload = b64url(encoder.encode(JSON.stringify({ sub: userId, exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60 })));
  const signature = b64url(await hmacBytes(env.SESSION_SECRET, payload));
  return `${payload}.${signature}`;
}
async function sessionUser(request, env) {
  if (!env.SESSION_SECRET) return null;
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(/(?:^|;\s*)__Host-adit_session=([^;]+)/);
  if (!match) return null;
  const parts = match[1].split('.');
  if (parts.length !== 2) return null;
  const expected = b64url(await hmacBytes(env.SESSION_SECRET, parts[0]));
  if (!timingSafeTextEqual(expected, parts[1])) return null;
  try {
    const payload = JSON.parse(new TextDecoder().decode(fromB64url(parts[0])));
    if (!payload.sub || !Number.isFinite(payload.exp) || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return await env.DB.prepare('SELECT id, name, email, role FROM users WHERE id = ?').bind(payload.sub).first();
  } catch { return null; }
}
function sessionCookie(token) {
  return `__Host-adit_session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=604800`;
}
function clearSessionCookie() {
  return '__Host-adit_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0';
}
async function readJson(request) {
  try { return await request.json(); } catch { return null; }
}
function cleanEmail(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}
function validEmail(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 190; }
function markup(env, wholesale) {
  const percent = Number(env.SELL_MARKUP_PERCENT ?? 15);
  const fixed = Number(env.SELL_MARKUP_FIXED ?? 0);
  return Math.ceil(wholesale * (1 + Math.max(0, Math.min(percent, 200)) / 100) + Math.max(0, Number.isFinite(fixed) ? fixed : 0));
}
function tripayBase(env) { return String(env.TRIPAY_MODE || 'sandbox').toLowerCase() === 'production' ? TRIPAY_PRODUCTION : TRIPAY_SANDBOX; }
function requireConfig(env, keys) {
  const missing = keys.filter(k => !env[k] || String(env[k]).includes('PASTE_'));
  return missing;
}
async function nokosFetch(env, path, init = {}) {
  const missing = requireConfig(env, ['NOKOS_API_KEY']);
  if (missing.length) throw new Error('API Nokos Pusat belum dikonfigurasi di Cloudflare Secrets.');
  const headers = new Headers(init.headers || {});
  headers.set('Authorization', `Bearer ${env.NOKOS_API_KEY}`);
  headers.set('Accept', 'application/json');
  if (init.body) headers.set('Content-Type', 'application/json');
  const response = await fetch(`${NOKOS_BASE}${path}`, { ...init, headers });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(result?.error?.message || `API Nokos Pusat merespons HTTP ${response.status}.`);
    error.status = response.status;
    error.data = result;
    throw error;
  }
  return result;
}
async function walletBalance(env, userId) {
  const row = await env.DB.prepare('SELECT balance FROM wallets WHERE user_id = ?').bind(userId).first();
  return Number(row?.balance || 0);
}
async function createLedger(env, { userId, kind, amount, reference, note }) {
  const result = await env.DB.prepare(
    `INSERT INTO wallet_transactions (id, user_id, kind, amount, reference, note, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(reference) DO NOTHING`
  ).bind(id(), userId, kind, amount, reference, note || '', nowIso()).run();
  return Number(result.meta?.changes || 0) > 0;
}
async function updateOrderFromUpstream(env, user, localOrder, data) {
  const remote = data?.data;
  if (!remote) return localOrder;
  const remoteStatus = String(remote.status || localOrder.status).toLowerCase();
  const status = remoteStatus.slice(0, 48);
  const otpCode = remote.otp && typeof remote.otp === 'object' ? (remote.otp.code || null) : null;
  const otpMessage = remote.otp && typeof remote.otp === 'object' ? (remote.otp.message || null) : null;
  await env.DB.prepare(
    `UPDATE orders SET status = ?, number = COALESCE(?, number), otp_code = ?, otp_message = ?,
      expires_at = COALESCE(?, expires_at), updated_at = ? WHERE id = ? AND user_id = ?`
  ).bind(status, remote.number || null, otpCode, otpMessage, remote.expires_at || null, nowIso(), localOrder.id, user.id).run();
  if ((status === 'cancelled' || status === 'expired') && !localOrder.refunded_at) {
    const applied = await createLedger(env, {
      userId: user.id, kind: 'refund', amount: Number(localOrder.sell_price),
      reference: `order:${localOrder.id}:refund`, note: `Pengembalian saldo pesanan ${localOrder.service_name}`
    });
    if (applied) {
      await env.DB.prepare('UPDATE orders SET refunded_at = ?, updated_at = ? WHERE id = ? AND user_id = ?')
        .bind(nowIso(), nowIso(), localOrder.id, user.id).run();
    }
  }
  return await env.DB.prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?').bind(localOrder.id, user.id).first();
}

async function handleCallback(request, env) {
  const missing = requireConfig(env, ['TRIPAY_PRIVATE_KEY']);
  if (missing.length) return json({ success: false, message: 'Payment gateway belum dikonfigurasi.' }, 503);
  const raw = await request.text();
  const signature = request.headers.get('X-Callback-Signature') || '';
  const expected = await hmacHex(env.TRIPAY_PRIVATE_KEY, raw);
  if (!timingSafeTextEqual(signature.toLowerCase(), expected.toLowerCase())) {
    return json({ success: false, message: 'Invalid signature' }, 403);
  }
  if (request.headers.get('X-Callback-Event') !== 'payment_status') {
    return json({ success: false, message: 'Unrecognized callback event' }, 400);
  }
  let payload;
  try { payload = JSON.parse(raw); } catch { return json({ success: false, message: 'Invalid JSON' }, 400); }
  const merchantRef = String(payload.merchant_ref || '');
  const gatewayRef = String(payload.reference || '');
  const status = String(payload.status || '').toUpperCase();
  if (!merchantRef || !gatewayRef || !status) return json({ success: false, message: 'Missing callback fields' }, 400);
  const topup = await env.DB.prepare('SELECT * FROM topups WHERE merchant_ref = ?').bind(merchantRef).first();
  if (!topup) return json({ success: false, message: 'Top-up not found' }, 404);
  if (topup.gateway_reference && topup.gateway_reference !== gatewayRef) {
    return json({ success: false, message: 'Gateway reference mismatch' }, 400);
  }
  if (status === 'PAID') {
    const paidAmount = Number(payload.total_amount);
    if (!Number.isSafeInteger(paidAmount) || paidAmount !== Number(topup.amount)) {
      return json({ success: false, message: 'Payment amount mismatch' }, 400);
    }
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO wallet_transactions (id, user_id, kind, amount, reference, note, created_at)
         SELECT ?, user_id, 'topup', ?, ?, ?, ? FROM topups
         WHERE merchant_ref = ? AND amount = ? AND status != 'PAID'
         ON CONFLICT(reference) DO NOTHING`
      ).bind(id(), Number(topup.amount), `topup:${merchantRef}`, `Top-up QRIS ${merchantRef}`, nowIso(), merchantRef, Number(topup.amount)),
      env.DB.prepare(
        `UPDATE topups SET status = 'PAID', gateway_reference = ?, updated_at = ?
         WHERE merchant_ref = ? AND amount = ?`
      ).bind(gatewayRef, nowIso(), merchantRef, Number(topup.amount))
    ]);
  } else if (['EXPIRED', 'FAILED', 'REFUND'].includes(status)) {
    await env.DB.prepare(
      `UPDATE topups SET status = ?, gateway_reference = COALESCE(gateway_reference, ?), updated_at = ?
       WHERE merchant_ref = ? AND status != 'PAID'`
    ).bind(status, gatewayRef, nowIso(), merchantRef).run();
  }
  return json({ success: true });
}

async function handleApi(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method.toUpperCase();
  if (path === '/api/health' && method === 'GET') return json({ ok: true, app: 'AditStore OTP', mode: env.TRIPAY_MODE || 'sandbox' });
  if (path === '/api/payments/callback' && method === 'POST') return handleCallback(request, env);

  if (['/api/register', '/api/login'].includes(path) && method === 'POST') {
    const missing = requireConfig(env, ['SESSION_SECRET']);
    if (missing.length) return fail('SESSION_SECRET belum diatur pada Cloudflare Secrets.', 503, 'configuration_missing');
    const body = await readJson(request);
    if (!body) return fail('Format data tidak valid.');
    if (path === '/api/register') {
      const name = typeof body.name === 'string' ? body.name.trim().slice(0, 80) : '';
      const email = cleanEmail(body.email);
      const password = typeof body.password === 'string' ? body.password : '';
      if (name.length < 2) return fail('Nama minimal 2 karakter.');
      if (!validEmail(email)) return fail('Alamat email tidak valid.');
      if (password.length < 8 || password.length > 128) return fail('Password harus 8–128 karakter.');
      const already = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
      if (already) return fail('Email sudah terdaftar. Silakan login.', 409, 'email_exists');
      const uid = id();
      const hashed = await passwordHash(password);
      const isAdmin = cleanEmail(env.ADMIN_EMAIL || '') === email && !!email;
      try {
        await env.DB.batch([
          env.DB.prepare('INSERT INTO users (id, name, email, password_hash, password_salt, role, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
            .bind(uid, name, email, hashed.hash, hashed.salt, isAdmin ? 'admin' : 'customer', nowIso()),
          env.DB.prepare('INSERT INTO wallets (user_id, balance, updated_at) VALUES (?, 0, ?)').bind(uid, nowIso())
        ]);
      } catch (e) {
        return fail('Tidak berhasil membuat akun. Email mungkin sudah dipakai.', 409, 'register_failed');
      }
      const token = await makeSession(uid, env);
      return json({ user: { id: uid, name, email, role: isAdmin ? 'admin' : 'customer' }, balance: 0 }, 201, { 'Set-Cookie': sessionCookie(token) });
    }
    const email = cleanEmail(body.email);
    const password = typeof body.password === 'string' ? body.password : '';
    const user = await env.DB.prepare('SELECT id, name, email, role, password_hash, password_salt FROM users WHERE email = ?').bind(email).first();
    if (!user) return fail('Email atau password salah.', 401, 'invalid_credentials');
    const calculated = await passwordHash(password, user.password_salt);
    if (!timingSafeTextEqual(calculated.hash, user.password_hash)) return fail('Email atau password salah.', 401, 'invalid_credentials');
    const token = await makeSession(user.id, env);
    return json({ user: { id: user.id, name: user.name, email: user.email, role: user.role }, balance: await walletBalance(env, user.id) }, 200, { 'Set-Cookie': sessionCookie(token) });
  }
  if (path === '/api/logout' && method === 'POST') return json({ success: true }, 200, { 'Set-Cookie': clearSessionCookie() });

  const user = await sessionUser(request, env);
  const protectedPaths = ['/api/me', '/api/topups', '/api/orders'];
  if (!user && (protectedPaths.includes(path) || path.startsWith('/api/topups/') || path.startsWith('/api/orders/') || path === '/api/topups' || path === '/api/orders')) {
    return fail('Silakan login terlebih dahulu.', 401, 'unauthorized');
  }

  if (path === '/api/me' && method === 'GET') {
    const row = await env.DB.prepare('SELECT balance FROM wallets WHERE user_id = ?').bind(user.id).first();
    return json({ user, balance: Number(row?.balance || 0) });
  }

  if (path === '/api/services' && method === 'GET') {
    try {
      const params = new URLSearchParams();
      const q = (url.searchParams.get('q') || '').trim().slice(0, 80);
      const category = (url.searchParams.get('category') || '').trim().slice(0, 40);
      const page = url.searchParams.get('page');
      const limit = url.searchParams.get('limit');
      if (q) params.set('q', q);
      if (category) params.set('category', category);
      if (page) params.set('page', String(Math.max(1, Number(page) || 1)));
      if (limit) params.set('limit', String(Math.min(100, Math.max(1, Number(limit) || 20))));
      const result = await nokosFetch(env, `/api/v1/services${params.size ? `?${params}` : ''}`);
      return json(result);
    } catch (e) { return fail(e.message || 'Gagal mengambil katalog.', e.status || 502, 'catalog_error'); }
  }

  const countryMatch = path.match(/^\/api\/services\/([^/]+)\/countries$/);
  if (countryMatch && method === 'GET') {
    const provider = url.searchParams.get('provider') || 'provider_1';
    if (!/^provider_[1-5]$/.test(provider)) return fail('Provider tidak valid.');
    try {
      const serviceId = decodeURIComponent(countryMatch[1]);
      const result = await nokosFetch(env, `/api/v1/services/${encodeURIComponent(serviceId)}/countries?provider=${encodeURIComponent(provider)}`);
      return json(result);
    } catch (e) { return fail(e.message || 'Gagal mengambil wilayah.', e.status || 502, 'countries_error'); }
  }

  const offersMatch = path.match(/^\/api\/services\/([^/]+)\/offers$/);
  if (offersMatch && method === 'GET') {
    const provider = url.searchParams.get('provider') || 'provider_1';
    const country = url.searchParams.get('country_code') || '';
    if (!/^provider_[1-5]$/.test(provider)) return fail('Provider tidak valid.');
    if (!country.trim()) return fail('Pilih wilayah terlebih dahulu.');
    try {
      const serviceId = decodeURIComponent(offersMatch[1]);
      const result = await nokosFetch(env, `/api/v1/services/${encodeURIComponent(serviceId)}/offers?provider=${encodeURIComponent(provider)}&country_code=${encodeURIComponent(country)}`);
      const offers = (Array.isArray(result.data) ? result.data : []).map(offer => ({
        provider_id: String(offer.provider_id || ''),
        server_label: String(offer.server_label || 'Server'),
        stock: Number(offer.stock || 0),
        recommended: Boolean(offer.recommended),
        upstream_price: Number(offer.price || 0),
        price: markup(env, Number(offer.price || 0))
      }));
      return json({ ...result, data: offers });
    } catch (e) { return fail(e.message || 'Gagal mengambil penawaran.', e.status || 502, 'offers_error'); }
  }

  if (path === '/api/topups' && method === 'GET') {
    const rows = await env.DB.prepare('SELECT id, merchant_ref, amount, status, method, qr_url, pay_url, pay_code, expires_at, created_at FROM topups WHERE user_id = ? ORDER BY created_at DESC LIMIT 15').bind(user.id).all();
    return json({ data: rows.results || [] });
  }

  if (path === '/api/topups' && method === 'POST') {
    const missing = requireConfig(env, ['TRIPAY_API_KEY', 'TRIPAY_PRIVATE_KEY', 'TRIPAY_MERCHANT_CODE']);
    if (missing.length) return fail('QRIS belum aktif. Lengkapi TRIPAY_API_KEY, TRIPAY_PRIVATE_KEY, dan TRIPAY_MERCHANT_CODE pada Cloudflare Secrets.', 503, 'payment_not_configured');
    const body = await readJson(request);
    const min = safeInt(env.TOPUP_MIN || 5000, 1000, 5000000) || 5000;
    const max = safeInt(env.TOPUP_MAX || 5000000, min, 5000000) || 5000000;
    const amount = safeInt(body?.amount, min, max);
    if (!amount) return fail(`Nominal top-up harus Rp${min.toLocaleString('id-ID')}–Rp${max.toLocaleString('id-ID')}.`);
    const methodCode = String(env.TRIPAY_QRIS_METHOD || 'QRIS2').toUpperCase();
    if (!['QRIS', 'QRISC', 'QRIS2', 'QRIS_SHOPEEPAY'].includes(methodCode)) return fail('TRIPAY_QRIS_METHOD harus salah satu kode QRIS yang didukung.', 503, 'invalid_payment_method');
    const ref = `ADIT${Date.now()}${crypto.getRandomValues(new Uint8Array(5)).reduce((s, v) => s + v.toString(16).padStart(2, '0'), '')}`.slice(0, 32);
    const topupId = id();
    const created = nowIso();
    await env.DB.prepare(
      `INSERT INTO topups (id, user_id, merchant_ref, amount, method, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, 'CREATING', ?, ?)`
    ).bind(topupId, user.id, ref, amount, methodCode, created, created).run();
    const signature = await hmacHex(env.TRIPAY_PRIVATE_KEY, `${env.TRIPAY_MERCHANT_CODE}${ref}${amount}`);
    const form = new URLSearchParams();
    form.set('method', methodCode);
    form.set('merchant_ref', ref);
    form.set('amount', String(amount));
    form.set('customer_name', user.name.slice(0, 100));
    form.set('customer_email', user.email);
    form.set('order_items[0][sku]', 'ADITSTORE-TOPUP');
    form.set('order_items[0][name]', `Saldo AditStore Rp${amount}`);
    form.set('order_items[0][price]', String(amount));
    form.set('order_items[0][quantity]', '1');
    form.set('callback_url', `${url.origin}/api/payments/callback`);
    form.set('return_url', `${url.origin}/?payment=return`);
    form.set('expired_time', String(Math.floor(Date.now() / 1000) + 30 * 60));
    form.set('signature', signature);
    let gatewayResponse;
    try {
      const gateway = await fetch(`${tripayBase(env)}/transaction/create`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${env.TRIPAY_API_KEY}`, 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
        body: form.toString()
      });
      gatewayResponse = await gateway.json().catch(() => ({}));
      if (!gateway.ok || !gatewayResponse.success || !gatewayResponse.data) {
        const message = gatewayResponse.message || `Gateway QRIS merespons HTTP ${gateway.status}.`;
        await env.DB.prepare('UPDATE topups SET status = ?, updated_at = ? WHERE id = ? AND status != \'PAID\'').bind('FAILED', nowIso(), topupId).run();
        return fail(message, 502, 'gateway_error');
      }
    } catch {
      await env.DB.prepare('UPDATE topups SET status = ?, updated_at = ? WHERE id = ? AND status != \'PAID\'').bind('UNKNOWN', nowIso(), topupId).run();
      return fail('Tidak dapat memastikan hasil pembuatan transaksi QRIS. Periksa menu Top-up sebelum mencoba lagi agar tidak membuat pembayaran ganda.', 502, 'gateway_network_error');
    }
    const d = gatewayResponse.data;
    const expiry = d.expired_time ? new Date(Number(d.expired_time) * 1000).toISOString() : new Date(Date.now() + 30 * 60 * 1000).toISOString();
    await env.DB.prepare(
      `UPDATE topups SET gateway_reference = ?, status = CASE WHEN status IN ('PAID','EXPIRED','FAILED','REFUND') THEN status ELSE ? END,
       qr_url = ?, pay_url = ?, pay_code = ?, expires_at = ?, updated_at = ? WHERE id = ?`
    ).bind(String(d.reference || ''), String(d.status || 'UNPAID').toUpperCase(), d.qr_url || null, d.pay_url || d.checkout_url || null, d.pay_code || d.qr_string || null, expiry, nowIso(), topupId).run();
    const topup = await env.DB.prepare('SELECT id, merchant_ref, amount, status, method, qr_url, pay_url, pay_code, expires_at, created_at FROM topups WHERE id = ?').bind(topupId).first();
    return json({ data: topup }, 201);
  }

  if (path === '/api/orders' && method === 'GET') {
    const rows = await env.DB.prepare(
      'SELECT id, service_name, provider, country_code, provider_id, sell_price, number, status, otp_code, otp_message, expires_at, refunded_at, created_at, updated_at FROM orders WHERE user_id = ? ORDER BY created_at DESC LIMIT 30'
    ).bind(user.id).all();
    return json({ data: rows.results || [] });
  }

  if (path === '/api/orders' && method === 'POST') {
    if (!env.NOKOS_API_KEY) return fail('API Nokos Pusat belum dikonfigurasi.', 503, 'configuration_missing');
    const body = await readJson(request);
    if (!body) return fail('Format data tidak valid.');
    const serviceId = String(body.service_id || '').slice(0, 150);
    const provider = String(body.provider || 'provider_1');
    const countryCode = String(body.country_code || '').trim().slice(0, 40);
    const providerId = String(body.provider_id || '').slice(0, 120);
    const upstreamPrice = safeInt(body.upstream_price, 1, 100000000);
    const idem = request.headers.get('Idempotency-Key') || '';
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,100}$/.test(idem)) return fail('Idempotency-Key wajib dan formatnya tidak valid.');
    if (!serviceId || !/^provider_[1-5]$/.test(provider) || !countryCode || !providerId || !upstreamPrice) return fail('Data layanan/penawaran tidak lengkap.');
    const prior = await env.DB.prepare('SELECT * FROM orders WHERE user_id = ? AND idempotency_key = ?').bind(user.id, idem).first();
    if (prior) {
      // Recover a network-ambiguous purchase by retrying the SAME upstream idempotency key.
      // This prevents creating a second provider order and does not debit the customer again.
      if (prior.status === 'needs_review' && !prior.upstream_order_id) {
        try {
          const remote = await nokosFetch(env, '/api/v1/orders', {
            method: 'POST',
            headers: { 'Idempotency-Key': `adit-${prior.id.replace(/-/g, '')}` },
            body: JSON.stringify({ service_id: prior.service_id, provider: prior.provider, country_code: prior.country_code, provider_id: prior.provider_id, quoted_price: Number(prior.upstream_price) })
          });
          const d = remote.data || {};
          await env.DB.prepare(
            `UPDATE orders SET upstream_order_id = ?, number = ?, status = ?, otp_code = ?, otp_message = ?, expires_at = ?, updated_at = ? WHERE id = ? AND user_id = ?`
          ).bind(String(d.id || ''), d.number || null, String(d.status || 'pending').toLowerCase(), d.otp?.code || null, d.otp?.message || null, d.expires_at || null, nowIso(), prior.id, user.id).run();
          const recovered = await env.DB.prepare('SELECT id, service_name, provider, country_code, provider_id, sell_price, number, status, otp_code, otp_message, expires_at, created_at FROM orders WHERE id = ? AND user_id = ?').bind(prior.id, user.id).first();
          return json({ data: recovered, reused: true, recovered: true });
        } catch (e) {
          return json({ data: prior, reused: true, recovery_message: e.message || 'Status masih belum dapat dipastikan.' }, 202);
        }
      }
      return json({ data: prior, reused: true });
    }
    let offers;
    try {
      const result = await nokosFetch(env, `/api/v1/services/${encodeURIComponent(serviceId)}/offers?provider=${encodeURIComponent(provider)}&country_code=${encodeURIComponent(countryCode)}`);
      offers = Array.isArray(result.data) ? result.data : [];
    } catch (e) { return fail(e.message || 'Gagal memvalidasi harga.', e.status || 502, 'offer_validation_error'); }
    const selected = offers.find(o => String(o.provider_id) === providerId);
    if (!selected || Number(selected.price) !== upstreamPrice) return fail('Harga atau server sudah berubah. Muat ulang penawaran sebelum membeli.', 409, 'price_changed');
    const sellPrice = markup(env, upstreamPrice);
    const localId = id();
    const created = nowIso();
    let serviceName = serviceId;
    try {
      const svcResult = await nokosFetch(env, `/api/v1/services?q=${encodeURIComponent(serviceId)}&limit=100`);
      const services = Array.isArray(svcResult.data) ? svcResult.data : [];
      const match = services.find(s => String(s.id) === serviceId || String(s.slug) === serviceId);
      if (match?.name) serviceName = String(match.name).slice(0, 180);
    } catch { /* keep the service id as the fallback label */ }
    try {
      await env.DB.prepare(
        `INSERT INTO orders (id, user_id, idempotency_key, service_id, service_name, provider, country_code, provider_id,
          upstream_price, sell_price, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'processing', ?, ?)`
      ).bind(localId, user.id, idem, serviceId, serviceName, provider, countryCode, providerId, upstreamPrice, sellPrice, created, created).run();
    } catch {
      const existing = await env.DB.prepare('SELECT * FROM orders WHERE user_id = ? AND idempotency_key = ?').bind(user.id, idem).first();
      if (existing) return json({ data: existing, reused: true });
      return fail('Tidak bisa membuat pesanan lokal. Silakan muat ulang.', 500, 'order_create_failed');
    }
    const debit = await env.DB.prepare(
      `INSERT INTO wallet_transactions (id, user_id, kind, amount, reference, note, created_at)
       SELECT ?, ?, 'purchase', ?, ?, ?, ?
       WHERE COALESCE((SELECT balance FROM wallets WHERE user_id = ?), 0) >= ?
       ON CONFLICT(reference) DO NOTHING`
    ).bind(id(), user.id, -sellPrice, `order:${localId}:debit`, `Pembelian ${serviceName}`, created, user.id, sellPrice).run();
    if (Number(debit.meta?.changes || 0) === 0) {
      await env.DB.prepare("UPDATE orders SET status = 'failed', updated_at = ? WHERE id = ?").bind(nowIso(), localId).run();
      return fail('Saldo tidak cukup untuk pesanan ini.', 402, 'insufficient_balance');
    }
    const upstreamIdem = `adit-${localId.replace(/-/g, '')}`;
    try {
      const remote = await nokosFetch(env, '/api/v1/orders', {
        method: 'POST',
        headers: { 'Idempotency-Key': upstreamIdem },
        body: JSON.stringify({ service_id: serviceId, provider, country_code: countryCode, provider_id: providerId, quoted_price: upstreamPrice })
      });
      const d = remote.data || {};
      await env.DB.prepare(
        `UPDATE orders SET upstream_order_id = ?, number = ?, status = ?, otp_code = ?, otp_message = ?, expires_at = ?, updated_at = ? WHERE id = ?`
      ).bind(String(d.id || ''), d.number || null, String(d.status || 'pending').toLowerCase(), d.otp?.code || null, d.otp?.message || null, d.expires_at || null, nowIso(), localId).run();
      const result = await env.DB.prepare('SELECT id, service_name, provider, country_code, provider_id, sell_price, number, status, otp_code, otp_message, expires_at, created_at FROM orders WHERE id = ?').bind(localId).first();
      return json({ data: result }, 201);
    } catch (e) {
      // Only refund on a definite HTTP/API rejection. A network timeout is ambiguous: the upstream may have created the order.
      if (e.status) {
        await createLedger(env, { userId: user.id, kind: 'refund', amount: sellPrice, reference: `order:${localId}:refund`, note: `Refund otomatis: ${e.message}` });
        await env.DB.prepare("UPDATE orders SET status = 'failed', updated_at = ? WHERE id = ?").bind(nowIso(), localId).run();
        return fail(e.message || 'Pesanan ditolak penyedia. Saldo telah dikembalikan.', e.status >= 400 && e.status < 600 ? e.status : 502, 'upstream_order_error');
      }
      await env.DB.prepare("UPDATE orders SET status = 'needs_review', updated_at = ? WHERE id = ?").bind(nowIso(), localId).run();
      return fail('Status pembelian belum dapat dipastikan. Saldo ditahan sementara untuk mencegah pembelian ganda; buka riwayat pesanan dan periksa statusnya.', 502, 'order_status_uncertain');
    }
  }

  const orderMatch = path.match(/^\/api\/orders\/([^/]+)$/);
  if (orderMatch && ['GET', 'POST'].includes(method)) {
    const localId = decodeURIComponent(orderMatch[1]);
    const localOrder = await env.DB.prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?').bind(localId, user.id).first();
    if (!localOrder) return fail('Pesanan tidak ditemukan.', 404, 'order_not_found');
    if (!localOrder.upstream_order_id) return json({ data: localOrder });
    try {
      let remote;
      if (method === 'POST') {
        remote = await nokosFetch(env, `/api/v1/orders/${encodeURIComponent(localOrder.upstream_order_id)}`, { method: 'DELETE' });
      } else {
        remote = await nokosFetch(env, `/api/v1/orders/${encodeURIComponent(localOrder.upstream_order_id)}`);
      }
      const updated = await updateOrderFromUpstream(env, user, localOrder, remote);
      return json({ data: updated });
    } catch (e) { return fail(e.message || 'Gagal memperbarui status pesanan.', e.status || 502, 'order_status_error'); }
  }

  if (path === '/api/admin/summary' && method === 'GET') {
    if (!user || user.role !== 'admin') return fail('Akses admin diperlukan.', 403, 'forbidden');
    const customers = await env.DB.prepare('SELECT COUNT(*) AS total FROM users WHERE role = \'customer\'').first();
    const paid = await env.DB.prepare("SELECT COALESCE(SUM(amount),0) AS total FROM topups WHERE status = 'PAID'").first();
    const orders = await env.DB.prepare('SELECT COUNT(*) AS total FROM orders').first();
    const users = await env.DB.prepare(
      `SELECT u.id, u.name, u.email, u.created_at, COALESCE(w.balance,0) AS balance
       FROM users u LEFT JOIN wallets w ON w.user_id = u.id WHERE u.role = 'customer'
       ORDER BY u.created_at DESC LIMIT 100`
    ).all();
    return json({ customers: Number(customers?.total || 0), paid_topups: Number(paid?.total || 0), orders: Number(orders?.total || 0), users: users.results || [] });
  }

  return fail('Endpoint tidak ditemukan.', 404, 'not_found');
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      try { return await handleApi(request, env); }
      catch (e) {
        console.error('AditStore request failed:', e?.message || e);
        return fail('Terjadi kesalahan server. Periksa konfigurasi dan log Worker.', 500, 'internal_error');
      }
    }
    if (env.ASSETS) return env.ASSETS.fetch(request);
    return new Response('AditStore frontend assets are not configured.', { status: 404 });
  }
};
