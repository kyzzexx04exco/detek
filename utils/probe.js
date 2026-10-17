// probe.js — WA OTP probe + state detection
// Target: https://v.whatsapp.net/v2/code
// Log raw response dengan DEBUG=1 di .env buat troubleshooting

import axios from 'axios';

const DEBUG = process.env.DEBUG === '1';

const HEADERS = {
  'User-Agent':      'WhatsApp/2.24.6.77 A',
  'Accept':          'application/json',
  'Accept-Language': 'id-ID,id;q=0.9',
  'Content-Type':    'application/x-www-form-urlencoded',
};

function buildToken(phone) {
  const ts  = Math.floor(Date.now() / 1000).toString(36);
  const raw = phone.replace('+', '') + ts + 'waprobe';
  return Buffer.from(raw).toString('base64').slice(0, 36);
}

function splitPhone(phone) {
  const digits = phone.replace('+', '');
  // coba cc 1, 2, 3 digit — ambil yang paling masuk akal
  // fallback: 2 digit
  if (digits.length >= 12) return { cc: digits.slice(0, 2), inn: digits.slice(2) };
  if (digits.length >= 10) return { cc: digits.slice(0, 2), inn: digits.slice(2) };
  return { cc: digits.slice(0, 1), inn: digits.slice(1) };
}

async function requestOTP(phone) {
  const { cc, inn } = splitPhone(phone);

  const params = new URLSearchParams({
    cc,
    in:               inn,
    lg:               'id',
    lc:               'ID',
    mistyped:         '6',
    multidevice:      '1',
    method:           'sms',
    sim_mcc:          '510',
    sim_mnc:          '001',
    network_radio_type: '1',
    reason:           '',
    token:            buildToken(phone),
    id:               Math.random().toString(36).slice(2, 12),
  });

  try {
    const res = await axios.post(
      `https://v.whatsapp.net/v2/code?${params.toString()}`,
      null,
      {
        headers:        HEADERS,
        timeout:        12000,
        validateStatus: () => true,
      }
    );

    if (DEBUG) {
      console.log(`[PROBE] ${phone} | HTTP ${res.status} | ${JSON.stringify(res.data)}`);
    }

    return { status: res.status, body: res.data };
  } catch (err) {
    if (DEBUG) console.log(`[PROBE ERR] ${phone} | ${err.message}`);
    return { status: 0, body: null, err: err.message };
  }
}

/**
 * Format detik ke string human-readable
 * @param {number} secs
 * @returns {string}
 */
export function fmtCooldown(secs) {
  if (!secs || secs <= 0) return null;
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  const parts = [];
  if (d) parts.push(`${d}d`);
  if (h) parts.push(`${h}j`);
  if (m) parts.push(`${m}m`);
  if (s && !d && !h) parts.push(`${s}s`);
  return parts.join(' ') || '< 1m';
}

/**
 * Probe satu nomor WA
 * @param {string} phone — E.164 dengan +
 * @returns {Promise<object>}
 */
export async function probeNumber(phone) {
  const { status, body } = await requestOTP(phone);

  const state = {
    phone,
    registered:     false,
    banned:         false,
    bannedType:     null,      // 'permanent' | 'temporary'
    cooldown:       false,
    cooldownSecs:   null,
    cloneSupport:   false,
    noCloneSupport: false,
    limitActive:    false,
    limitType:      null,      // 'spam' | 'new_account' | 'rate'
    canReceiveOTP:  true,
    raw:            body,
    httpStatus:     status,
  };

  if (!body) {
    state.canReceiveOTP = false;
    return state;
  }

  const s     = (body.status || '').toLowerCase();
  const reason = (body.reason || '').toLowerCase();
  const retry  = parseInt(body.retry_after ?? body.sec_wait ?? body.retry ?? '0', 10);

  // --- mapping response ---

  if (s === 'sent' || s === 'ok') {
    state.registered    = true;
    state.canReceiveOTP = true;
    // field ini muncul di nomor yang eligible multi-device
    state.cloneSupport  = body.voice_length !== undefined || body.flash_type !== undefined;
    return state;
  }

  if (s === 'too_recent' || s === 'too-recent' || reason === 'too_recent') {
    state.registered    = true;
    state.cooldown      = true;
    state.cooldownSecs  = retry || null;
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
    state.registered     = false;
    state.noCloneSupport = true;
    state.canReceiveOTP  = false;
    return state;
  }

  if (reason === 'mismatch' || reason === 'no_multidevice') {
    state.registered     = true;
    state.noCloneSupport = true;
    return state;
  }

  // fallback: kalau HTTP 200 tapi status ga dikenal → anggap registered
  if (status === 200) {
    state.registered = true;
    return state;
  }

  // HTTP 403 biasanya token problem — tandai biar bisa diretry manual
  if (status === 403) {
    state.registered    = true; // kemungkinan besar terdaftar
    state.canReceiveOTP = false;
    return state;
  }

  return state;
}
