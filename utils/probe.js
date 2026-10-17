// probe.js — WA OTP probe + state detection
// Method: ENC-based (ECDH X25519 + AES-256-GCM) — required by WA 2.22+
// Fallback: plain params for older endpoint fallback
//
// SETUP (satu kali):
//   1. node setup-apk.js /path/to/WhatsApp.apk
//   2. copy WA_CERT_DER dan WA_CLASSES_MD5 ke .env
//
// Set DEBUG=1 di .env buat raw log

import axios  from 'axios';
import crypto from 'crypto';

const DEBUG = process.env.DEBUG === '1';

// ─── constants ────────────────────────────────────────────────────────────────

// WA server X25519 public key (32 bytes raw) — dari RE-WA docs
// Dipakai untuk ECDH shared secret
const WA_SERVER_PUBKEY = Buffer.from(
  '8e8c0f74c3ebc5d7a6865c6c3c843856b06121cce8ea774d22fb6f122512302d',
  'hex'
);

// Precalculated PBKDF2 key untuk token generation — dari RE-WA docs
// Menggantikan step PBKDF2 dari APK
const TOKEN_PRECALC_KEY = Buffer.from(
  'eQV5aq/Cg63Gsq1sshN9T3gh+UUp0wIw0xgHYT1bnCjEqOJQKCRrWxdAe2yvsDeCJL+Y4G3PRD2HUF7oUgiGo8vGlNJOaux26k+A2F3hj8A=',
  'base64'
);

// Load dari .env (set oleh setup-apk.js)
// WA_CERT_DER   = base64 dari DER bytes signing cert APK
// WA_CLASSES_MD5 = base64 dari raw MD5 bytes classes.dex
const WA_CERT_DER    = process.env.WA_CERT_DER
  ? Buffer.from(process.env.WA_CERT_DER, 'base64')
  : null;
const WA_CLASSES_MD5 = process.env.WA_CLASSES_MD5
  ? Buffer.from(process.env.WA_CLASSES_MD5, 'base64')
  : null;

const TOKEN_READY = !!(WA_CERT_DER && WA_CLASSES_MD5);
if (!TOKEN_READY && DEBUG) {
  console.warn('[PROBE] WA_CERT_DER / WA_CLASSES_MD5 kosong — jalankan node setup-apk.js dulu');
}

// X25519 SPKI DER prefix (buat import raw key ke Node.js crypto)
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

// User-agent pool
const UA_POOL = [
  'WhatsApp/2.24.13.76 A',
  'WhatsApp/2.24.11.75 A',
  'WhatsApp/2.24.9.73 A',
  'WhatsApp/2.24.6.77 A',
  'WhatsApp/2.23.24.81 A',
];

// ─── helpers ──────────────────────────────────────────────────────────────────

const rndUA = () => UA_POOL[Math.floor(Math.random() * UA_POOL.length)];
const rndId = () => crypto.randomBytes(8).toString('hex');

function baseHeaders(ua) {
  return {
    'User-Agent':       ua,
    'Accept':           'application/json, text/plain, */*',
    'Accept-Language':  'id-ID,id;q=0.9,en-US;q=0.8',
    'Accept-Encoding':  'gzip, deflate, br',
    'Connection':       'keep-alive',
  };
}

function splitPhone(phone) {
  const d = phone.replace('+', '');
  if (d.startsWith('62') && d.length >= 11) return { cc: '62', inn: d.slice(2) };
  if (d.startsWith('60') && d.length >= 10) return { cc: '60', inn: d.slice(2) };
  if (d.startsWith('65') && d.length >= 10) return { cc: '65', inn: d.slice(2) };
  if (d.startsWith('1')  && d.length >= 11) return { cc: '1',  inn: d.slice(1) };
  if (d.length >= 10) return { cc: d.slice(0, 2), inn: d.slice(2) };
  return { cc: d.slice(0, 1), inn: d.slice(1) };
}

// ─── ENC encryption ───────────────────────────────────────────────────────────
// WA 2.22+ encrypt semua request params:
//   1. Generate ephemeral X25519 keypair
//   2. ECDH shared secret dengan WA server pubkey
//   3. AES-256-GCM encrypt query string (zero IV 12 bytes)
//   4. Payload: client_pubkey(32) + ciphertext + auth_tag(16)
//   5. Base64url → ENC GET param

function importX25519PubKey(rawBytes) {
  return crypto.createPublicKey({
    key:    Buffer.concat([X25519_SPKI_PREFIX, rawBytes]),
    format: 'der',
    type:   'spki',
  });
}

function encryptParams(queryString) {
  // Ephemeral X25519 keypair
  const { publicKey: clientPub, privateKey: clientPriv } =
    crypto.generateKeyPairSync('x25519');

  // Shared secret
  const serverKey    = importX25519PubKey(WA_SERVER_PUBKEY);
  const sharedSecret = crypto.diffieHellman({ privateKey: clientPriv, publicKey: serverKey });

  // AES-256-GCM — zero IV
  const iv      = Buffer.alloc(12, 0);
  const cipher  = crypto.createCipheriv('aes-256-gcm', sharedSecret, iv);
  const ct      = Buffer.concat([cipher.update(Buffer.from(queryString, 'utf8')), cipher.final()]);
  const authTag = cipher.getAuthTag(); // 16 bytes

  // Client pubkey raw (32 bytes): strip 12-byte DER prefix dari SPKI export
  const clientPubRaw = clientPub.export({ format: 'der', type: 'spki' }).subarray(12);

  // Final: pubkey(32) | ciphertext | authTag(16)
  return Buffer.concat([clientPubRaw, ct, authTag]).toString('base64url');
}

// ─── token generation ─────────────────────────────────────────────────────────
// HMAC-SHA1(precalc_key, certDER + classesMD5 + phoneDigits) → base64
// Butuh WA_CERT_DER dan WA_CLASSES_MD5 dari .env (set via setup-apk.js)

function buildToken(phone) {
  const digits = Buffer.from(phone.replace('+', ''), 'utf8');

  if (TOKEN_READY) {
    // Full proper token
    const data = Buffer.concat([WA_CERT_DER, WA_CLASSES_MD5, digits]);
    return crypto.createHmac('sha1', TOKEN_PRECALC_KEY).update(data).digest('base64');
  }

  // Fallback token — mungkin ditolak WA tapi worth trying
  const ts = Math.floor(Date.now() / 60_000).toString();
  return crypto.createHmac('sha1', TOKEN_PRECALC_KEY)
    .update(digits.toString('utf8') + ts)
    .digest('base64');
}

// ─── HTTP probes ──────────────────────────────────────────────────────────────

// Stage 1: exist check via ENC GET
async function existProbe(phone) {
  const { cc, inn } = splitPhone(phone);
  const ua = rndUA();

  const innerParams = new URLSearchParams({
    cc, in: inn, lg: 'id', lc: 'ID', id: rndId(),
  });

  const enc = encryptParams(innerParams.toString());

  try {
    const res = await axios.get('https://v.whatsapp.net/v2/exist', {
      params:         { ENC: enc },
      headers:        baseHeaders(ua),
      timeout:        10_000,
      validateStatus: () => true,
    });

    if (DEBUG) {
      console.log(`[EXIST] ${phone} | HTTP ${res.status} | ${JSON.stringify(res.data)}`);
    }

    return { status: res.status, body: res.data };
  } catch (err) {
    if (DEBUG) console.log(`[EXIST ERR] ${phone} | ${err.message}`);
    return { status: 0, body: null, err: err.message };
  }
}

// Stage 2: code request via ENC GET — trigger OTP, baca state dari response
async function codeProbe(phone) {
  const { cc, inn } = splitPhone(phone);
  const ua = rndUA();

  const innerParams = new URLSearchParams({
    cc,
    in:                  inn,
    lg:                  'id',
    lc:                  'ID',
    mistyped:            '6',
    multidevice:         '1',
    method:              'sms',
    sim_mcc:             '510',
    sim_mnc:             '001',
    network_radio_type:  '1',
    reason:              '',
    token:               buildToken(phone),
    id:                  rndId(),
    backup_token:        '',
  });

  const enc = encryptParams(innerParams.toString());

  try {
    const res = await axios.get('https://v.whatsapp.net/v2/code', {
      params:         { ENC: enc },
      headers:        baseHeaders(ua),
      timeout:        12_000,
      validateStatus: () => true,
    });

    if (DEBUG) {
      console.log(`[CODE] ${phone} | HTTP ${res.status} | ${JSON.stringify(res.data)}`);
    }

    return { status: res.status, body: res.data };
  } catch (err) {
    if (DEBUG) console.log(`[CODE ERR] ${phone} | ${err.message}`);
    return { status: 0, body: null, err: err.message };
  }
}

// ─── parse state ──────────────────────────────────────────────────────────────

function parseCodeBody(status, body, state) {
  if (!body) return state;

  const s      = String(body.status || '').toLowerCase();
  const reason = String(body.reason || '').toLowerCase();
  const retry  = parseInt(
    body.retry_after ?? body.sec_wait ?? body.retry_after_secs ?? body.retry ?? '0',
    10
  ) || 0;

  if (s === 'sent' || s === 'ok') {
    state.registered    = true;
    state.canReceiveOTP = true;
    state.cloneSupport  = body.voice_length !== undefined || body.flash_type !== undefined;
    return state;
  }
  if (s === 'too_recent' || s === 'too-recent' || reason === 'too_recent') {
    state.registered    = true;
    state.cooldown      = true;
    state.cooldownSecs  = retry > 0 ? retry : null;
    state.canReceiveOTP = false;
    return state;
  }
  if (s === 'blocked' || s === 'banned' || reason === 'blocked') {
    state.registered    = true;
    state.banned        = true;
    state.bannedType    = retry > 0 ? 'temporary' : 'permanent';
    state.canReceiveOTP = false;
    return state;
  }
  if (reason === 'too_many_requests' || s === 'rate_limit') {
    state.registered    = true;
    state.limitActive   = true;
    state.limitType     = 'rate';
    state.canReceiveOTP = false;
    return state;
  }
  if (reason === 'new_acct' || reason === 'new_account') {
    state.registered    = true;
    state.limitActive   = true;
    state.limitType     = 'new_account';
    state.canReceiveOTP = false;
    return state;
  }
  if (reason === 'spam') {
    state.registered    = true;
    state.limitActive   = true;
    state.limitType     = 'spam';
    state.canReceiveOTP = false;
    return state;
  }
  if (reason === 'no_routes' || s === 'no_routes') {
    state.registered     = true;
    state.noCloneSupport = true;
    state.canReceiveOTP  = false;
    return state;
  }
  if (reason === 'mismatch' || reason === 'no_multidevice') {
    state.registered     = true;
    state.noCloneSupport = true;
    state.canReceiveOTP  = false;
    return state;
  }
  if (reason === 'bad_token' || status === 401) {
    // Token rejected — APK values salah atau expired
    state.registered     = true;
    state.tokenRejected  = true;
    state.canReceiveOTP  = false;
    return state;
  }
  if (status === 403) {
    // Server reject → mungkin IP blocked atau token invalid
    state.registered    = true;
    state.canReceiveOTP = false;
    return state;
  }
  if (status === 200) {
    state.registered = true;
    return state;
  }
  return state;
}

// ─── export ───────────────────────────────────────────────────────────────────

/**
 * Format detik ke string human-readable
 */
export function fmtCooldown(secs) {
  if (!secs || secs <= 0) return null;
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  const parts = [];
  if (d) parts.push(`${d}h`);
  if (h) parts.push(`${h}j`);
  if (m) parts.push(`${m}m`);
  if (s && !d && !h) parts.push(`${s}d`);
  return parts.join(' ') || '< 1m';
}

/**
 * Probe satu nomor WA — 2-stage (ENC-based)
 * Stage 1: exist check (no OTP trigger)
 * Stage 2: code probe (cooldown / state detail)
 */
export async function probeNumber(phone) {
  const state = {
    phone,
    registered:     false,
    banned:         false,
    bannedType:     null,
    cooldown:       false,
    cooldownSecs:   null,
    cloneSupport:   false,
    noCloneSupport: false,
    limitActive:    false,
    limitType:      null,
    tokenRejected:  false,
    canReceiveOTP:  true,
    raw:            null,
    httpStatus:     0,
  };

  // Stage 1: exist check
  const exist = await existProbe(phone);
  state.raw        = exist.body;
  state.httpStatus = exist.status;

  if (exist.body) {
    const s      = String(exist.body.status  || '').toLowerCase();
    const reason = String(exist.body.reason  || '').toLowerCase();
    const login  = exist.body.login;

    // Jelas tidak terdaftar
    if (s === 'fail' && !login) {
      state.registered    = false;
      state.canReceiveOTP = false;
      return state;
    }

    // Terdaftar — lanjut ke stage 2 untuk cooldown check
    if (s === 'ok' && login) {
      state.registered = true;
    }
  }

  // Stage 2: code probe
  const code = await codeProbe(phone);
  state.raw        = code.body;
  state.httpStatus = code.status;

  parseCodeBody(code.status, code.body, state);

  return state;
}
