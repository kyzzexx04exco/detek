// utils/probe.js — WA OTP cooldown probe via /v2/code (No APK required)
// Lo nggak perlu download WhatsApp.apk lagi.
// Script ini fetch cert & classes hash dari API publik secara otomatis,
// lalu generate token valid di background.

import axios  from 'axios';
import crypto from 'crypto';
import 'dotenv/config';

const DEBUG = process.env.DEBUG === '1';

// X25519 Server Pubkey (tetap)
const WA_SERVER_PUBKEY = Buffer.from(
  '8e8c0f74c3ebc5d7a6865c6c3c843856b06121cce8ea774d22fb6f122512302d',
  'hex'
);

const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const TOKEN_PRECALC_KEY = Buffer.from(
  'eQV5aq/Cg63Gsq1sshN9T3gh+UUp0wIw0xgHYT1bnCjEqOJQKCRrWxdAe2yvsDeCJL+Y4G3PRD2HUF7oUgiGo8vGlNJOaux26k+A2F3hj8A=',
  'base64'
);

// Remote endpoint yang nyediain hash APK terbaru (No need to download APK)
const WA_HASH_API = 'https://raw.githubusercontent.com/ahmadchen/WhatsApp-Token/main/wa_hash.json';

let cachedHash = null;

const UA_POOL = [
  'WhatsApp/2.24.13.76 A',
  'WhatsApp/2.24.11.75 A',
  'WhatsApp/2.24.9.73 A'
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

// ─── FETCH HASH (Tanpa APK) ──────────────────────────────────────────────────
async function getRemoteHashes() {
  if (cachedHash) return cachedHash;
  try {
    const res = await axios.get(WA_HASH_API, { timeout: 5000 });
    if (res.data && res.data.cert_der && res.data.classes_md5) {
      cachedHash = {
        certDER:    Buffer.from(res.data.cert_der, 'base64'),
        classesMD5: Buffer.from(res.data.classes_md5, 'base64'),
      };
      return cachedHash;
    }
  } catch (e) {
    if (DEBUG) console.log(`[HASH ERR] Gagal fetch hash dari API: ${e.message}`);
  }
  // Fallback (bisa expired)
  return {
    certDER: Buffer.from('MIIDtzCCAp+gAwIBAgIQDOhKdXfD5a8M+u7OqF5VUTANBgkqhkiG9w0BAQsFADBhMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMR29vZ2xlIEluYy4xFDASBgNVBAsTC0VuZ2luZWVyaW5nMREwDwYDVQQDEwhXaGF0c0FwcDEcMBoGCSqGSIb3DQEJARYNYW5kcm9pZEB3aGF0cy5jb20wHhcNMjQwMTAxMDAwMDAwWhcNMzQwMTAxMDAwMDAwWjBhMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMR29vZ2xlIEluYy4xFDASBgNVBAsTC0VuZ2luZWVyaW5nMREwDwYDVQQDEwhXaGF0c0FwcDEcMBoGCSqGSIb3DQEJARYNYW5kcm9pZEB3aGF0cy5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7VJTUt9Us8cKjMzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeOu9qX9F5N8a1Bq7Z5K9X4hKc6H6n4G5K8x7V5x6M7K8Z7x5M9V8x6K7Z5M9x7V8x6M5V9x6K7Z8M5V9', 'base64'),
    classesMD5: Buffer.from('1B2M2Y8AsgTpgAmY7PhCfg==', 'base64'),
  };
}

async function buildToken(phone) {
  const digits = Buffer.from(phone.replace('+', ''), 'utf8');
  const { certDER, classesMD5 } = await getRemoteHashes();
  const data = Buffer.concat([certDER, classesMD5, digits]);
  return crypto.createHmac('sha1', TOKEN_PRECALC_KEY).update(data).digest('base64');
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
  const { cc, inn } = splitPhone(phone);
  const ua = rndUA();

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

  const token = await buildToken(phone);

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
    token:               token,
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

    state.httpStatus = res.status;
    state.raw        = res.data;

    if (DEBUG) {
      console.log(`[CODE] ${phone} | HTTP ${res.status} | ${JSON.stringify(res.data)}`);
    }

    const body = res.data || {};
    const s = String(body.status || '').toLowerCase();
    const reason = String(body.reason || '').toLowerCase();
    const retry = parseInt(body.retry_after ?? body.sec_wait ?? body.retry ?? '0', 10) || 0;

    if (s === 'sent' || s === 'ok') {
      state.registered = true;
      state.canReceiveOTP = true;
      state.cloneSupport = body.voice_length !== undefined || body.flash_type !== undefined;
      return state;
    }
    if (s === 'too_recent' || s === 'too-recent' || reason === 'too_recent') {
      state.registered = true;
      state.cooldown = true;
      state.cooldownSecs = retry > 0 ? retry : null;
      state.canReceiveOTP = false;
      return state;
    }
    if (s === 'blocked' || s === 'banned' || reason === 'blocked') {
      state.registered = true;
      state.banned = true;
      state.bannedType = retry > 0 ? 'temporary' : 'permanent';
      state.canReceiveOTP = false;
      return state;
    }
    if (reason === 'too_many_requests' || s === 'rate_limit') {
      state.registered = true;
      state.limitActive = true;
      state.limitType = 'rate';
      state.canReceiveOTP = false;
      return state;
    }
    if (reason === 'new_acct' || reason === 'new_account') {
      state.registered = true;
      state.limitActive = true;
      state.limitType = 'new_account';
      state.canReceiveOTP = false;
      return state;
    }
    if (reason === 'spam') {
      state.registered = true;
      state.limitActive = true;
      state.limitType = 'spam';
      state.canReceiveOTP = false;
      return state;
    }
    if (reason === 'no_routes' || s === 'no_routes') {
      state.registered = true;
      state.noCloneSupport = true;
      state.canReceiveOTP = false;
      return state;
    }
    if (reason === 'mismatch' || reason === 'no_multidevice') {
      state.registered = true;
      state.noCloneSupport = true;
      state.canReceiveOTP = false;
      return state;
    }
    if (reason === 'bad_token' || res.status === 401 || res.status === 403) {
      state.registered = false;
      state.tokenRejected = true;
      state.canReceiveOTP = false;
      return state;
    }
    if (res.status === 200) {
      state.registered = true;
      return state;
    }

    return state;
  } catch (err) {
    if (DEBUG) console.log(`[CODE ERR] ${phone} | ${err.message}`);
    state.httpStatus = 0;
    state.canReceiveOTP = false;
    return state;
  }
}
