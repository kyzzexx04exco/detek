// utils/probe.js
//
// METHOD: trigger OTP request ke berbagai service Indonesia yang pakai WA sebagai
// channel verifikasi, lalu baca HTTP response code + body untuk deteksi state.
//
// Logic:
//   - Tiap service dikirimi request registrasi/OTP dengan nomor target
//   - Response 200/201 → service berhasil kirim ke WA → nomor bisa terima OTP
//   - Response 429 + retry_after → WA cooldown aktif (dari sisi service)
//   - Response 4xx khusus → banned / limit / tidak terdaftar
//   - Voting dari semua service → hasil paling konsisten yang dipakai
//
// Kenapa ini lebih akurat dari probe langsung ke WA:
//   - Service ini pakai WhatsApp Business API resmi (Meta) — response-nya
//     mencerminkan state WA yang sesungguhnya
//   - Kalau nomor cooldown di WA, semua service yang coba kirim ke sana
//     akan dapat response "rate limited" atau "failed" dari Meta
//   - Kita baca signal itu tanpa harus punya akses WA API sendiri

import axios from 'axios';

const DEBUG   = process.env.DEBUG === '1';
const TIMEOUT = 12000;

// ─── UA pool ─────────────────────────────────────────────────────────────────
const UAS = [
  'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (Linux; Android 12; Samsung Galaxy S22) AppleWebKit/537.36 Chrome/119 Mobile Safari/537.36',
];
const ua = () => UAS[Math.floor(Math.random() * UAS.length)];

// ─── helpers ─────────────────────────────────────────────────────────────────

function log(...a) { if (DEBUG) console.log('[PROBE]', ...a); }

function parseRetry(headers, body) {
  // cari retry_after / sec_wait / Retry-After dari header atau body
  const h = parseInt(headers['retry-after'] || headers['x-retry-after'] || '0', 10);
  if (h > 0) return h;
  const b = body || {};
  return parseInt(b.retry_after ?? b.sec_wait ?? b.retryAfter ?? b.wait ?? '0', 10) || null;
}

async function hit(fn) {
  try { return await fn(); }
  catch (e) {
    if (e.response) return { status: e.response.status, data: e.response.data, headers: e.response.headers };
    log('network err:', e.message);
    return null;
  }
}

// ─── service probes ───────────────────────────────────────────────────────────
// Setiap fn return: { status, data, headers }
// Semua service ini pakai WA Business API atau WA Channel resmi

const services = [

  // 1. Tokopedia — register OTP via WA
  async (phone) => {
    const digits = phone.replace('+', '');
    return hit(() => axios.post(
      'https://accounts.tokopedia.com/otp/api/otp/request',
      { phone_number: digits, otp_type: 'whatsapp', mode: 'register' },
      { headers: { 'User-Agent': ua(), 'Content-Type': 'application/json', 'X-Device': 'android' }, timeout: TIMEOUT, validateStatus: () => true }
    ).then(r => ({ status: r.status, data: r.data, headers: r.headers })));
  },

  // 2. Shopee ID — request OTP WA
  async (phone) => {
    const digits = phone.replace('+62', '0'); // Shopee pakai format 08xx
    return hit(() => axios.post(
      'https://shopee.co.id/api/v2/user/otp/send',
      { phone: digits, channel: 'whatsapp', type: 1 },
      { headers: { 'User-Agent': ua(), 'Content-Type': 'application/json', 'Referer': 'https://shopee.co.id/' }, timeout: TIMEOUT, validateStatus: () => true }
    ).then(r => ({ status: r.status, data: r.data, headers: r.headers })));
  },

  // 3. Gojek — OTP WA channel
  async (phone) => {
    return hit(() => axios.post(
      'https://api.gojek.com/gootp/v1/otp/request',
      { phoneNumber: phone, channel: 'WHATSAPP', countryCode: phone.match(/^\+(\d{1,3})/)?.[1] || '62' },
      { headers: { 'User-Agent': ua(), 'Content-Type': 'application/json' }, timeout: TIMEOUT, validateStatus: () => true }
    ).then(r => ({ status: r.status, data: r.data, headers: r.headers })));
  },

  // 4. Traveloka — verifikasi nomor
  async (phone) => {
    return hit(() => axios.post(
      'https://api.traveloka.com/api/v1/auth/sendOtp',
      { phoneNumber: phone, otpChannel: 'WHATSAPP' },
      { headers: { 'User-Agent': ua(), 'Content-Type': 'application/json', 'X-Tvlk-App-Version': '4.0.0' }, timeout: TIMEOUT, validateStatus: () => true }
    ).then(r => ({ status: r.status, data: r.data, headers: r.headers })));
  },

  // 5. Bukalapak — OTP WA
  async (phone) => {
    return hit(() => axios.post(
      'https://api.bukalapak.com/v1/auth/otp/send',
      { phone: phone.replace('+', ''), channel: 'whatsapp' },
      { headers: { 'User-Agent': ua(), 'Content-Type': 'application/json' }, timeout: TIMEOUT, validateStatus: () => true }
    ).then(r => ({ status: r.status, data: r.data, headers: r.headers })));
  },

  // 6. OVO — phone verify WA
  async (phone) => {
    const digits = phone.replace('+62', '0');
    return hit(() => axios.post(
      'https://api.ovo.id/api/v1/auth/request-otp',
      { phoneNumber: digits, medium: 'whatsapp' },
      { headers: { 'User-Agent': ua(), 'Content-Type': 'application/json', 'X-App-Version': '3.81.0' }, timeout: TIMEOUT, validateStatus: () => true }
    ).then(r => ({ status: r.status, data: r.data, headers: r.headers })));
  },

];

// ─── interpret satu response ──────────────────────────────────────────────────

function interpret(res) {
  if (!res) return { signal: 'unreachable' };

  const { status, data, headers } = res;
  const body = data || {};
  const msg  = JSON.stringify(body).toLowerCase();

  log('status:', status, 'body:', msg.slice(0, 200));

  // ── cooldown / rate limit ──
  if (status === 429) {
    const secs = parseRetry(headers || {}, body);
    return { signal: 'cooldown', cooldownSecs: secs };
  }
  if (/too.?many|rate.?limit|cooldown|too.?recent|throttl/i.test(msg)) {
    const secs = parseRetry(headers || {}, body);
    return { signal: 'cooldown', cooldownSecs: secs };
  }

  // ── banned ──
  if (/banned|blocked|suspend/i.test(msg) && status !== 200) {
    return { signal: 'banned' };
  }

  // ── nomor tidak terdaftar WA ──
  if (/not.?register|no.?whatsapp|invalid.?number|number.?not.?exist/i.test(msg)) {
    return { signal: 'not_registered' };
  }

  // ── tidak support clone / multi-device tidak tersedia ──
  if (/no.?multidevice|not.?support|mismatch/i.test(msg)) {
    return { signal: 'no_clone' };
  }

  // ── limit akun baru ──
  if (/new.?account|new.?acct|new.?user.?limit/i.test(msg)) {
    return { signal: 'limit_new_account' };
  }

  // ── success: OTP berhasil dikirim ke WA → nomor aktif, tidak cooldown ──
  if (status === 200 || status === 201) {
    return { signal: 'ok' };
  }

  // ── 4xx lain → kemungkinan nomor invalid atau service ga support ──
  if (status >= 400 && status < 500) {
    return { signal: 'rejected', status };
  }

  // ── 5xx → service down, bukan info nomor ──
  if (status >= 500) {
    return { signal: 'service_error' };
  }

  return { signal: 'unknown' };
}

// ─── voting hasil semua service ──────────────────────────────────────────────

function vote(interpretations) {
  const signals = interpretations.map(i => i.signal);
  const counts  = {};
  for (const s of signals) counts[s] = (counts[s] || 0) + 1;

  log('vote signals:', signals);

  // prioritas signal — cooldown/banned lebih penting dari ok
  if (counts['cooldown']      > 0) {
    const cd = interpretations.find(i => i.signal === 'cooldown');
    return { winner: 'cooldown', cooldownSecs: cd?.cooldownSecs || null };
  }
  if (counts['banned']        > 0) return { winner: 'banned' };
  if (counts['not_registered']> 0) return { winner: 'not_registered' };
  if (counts['limit_new_account'] > 0) return { winner: 'limit_new_account' };
  if (counts['no_clone']      > 0) return { winner: 'no_clone' };

  // kalau mayoritas ok → nomor bersih
  if ((counts['ok'] || 0) >= 2) return { winner: 'ok' };

  // kalau semua rejected → kemungkinan format salah atau nomor invalid
  if (!counts['ok'] && (counts['rejected'] || 0) >= 2) return { winner: 'not_registered' };

  // kalau semua service error / unreachable
  if (!counts['ok'] && !counts['cooldown'] && !counts['banned']) {
    return { winner: 'unknown' };
  }

  return { winner: 'ok' };
}

// ─── main export ─────────────────────────────────────────────────────────────

/**
 * Probe satu nomor via multi-service trigger
 * @param {string} phone — E.164 dengan +
 */
export async function probeNumber(phone) {
  const state = {
    phone,
    registered:     true,
    isBusiness:     false,
    banned:         false,
    bannedType:     null,
    cooldown:       false,
    cooldownSecs:   null,
    cloneSupport:   null,   // null = tidak bisa deteksi via method ini
    noCloneSupport: false,
    limitActive:    false,
    limitType:      null,
    canReceiveOTP:  true,
    error:          null,
  };

  // jalankan semua service, tunggu semua selesai (parallel dengan timeout per-service)
  const results = await Promise.all(services.map(fn => fn(phone)));
  const interps = results.map(r => interpret(r));
  const { winner, cooldownSecs } = vote(interps);

  switch (winner) {
    case 'ok':
      state.registered    = true;
      state.canReceiveOTP = true;
      break;

    case 'cooldown':
      state.registered    = true;
      state.cooldown      = true;
      state.cooldownSecs  = cooldownSecs;
      state.canReceiveOTP = false;
      break;

    case 'banned':
      state.registered    = true;
      state.banned        = true;
      state.bannedType    = 'unknown';
      state.canReceiveOTP = false;
      break;

    case 'not_registered':
      state.registered     = false;
      state.noCloneSupport = true;
      state.canReceiveOTP  = false;
      break;

    case 'no_clone':
      state.registered     = true;
      state.noCloneSupport = true;
      state.canReceiveOTP  = true;
      break;

    case 'limit_new_account':
      state.registered    = true;
      state.limitActive   = true;
      state.limitType     = 'new_account';
      state.canReceiveOTP = false;
      break;

    default:
      // unknown — tandai error, anggap registered
      state.error         = 'response tidak konklusif';
      state.canReceiveOTP = true;
      break;
  }

  return state;
}
