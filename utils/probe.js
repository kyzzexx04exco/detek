// utils/probe.js — Direct WA OTP cooldown probe
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

const WA_CERT_DER    = process.env.WA_CERT_DER ? Buffer.from(process.env.WA_CERT_DER, 'base64') : null;
const WA_CLASSES_MD5 = process.env.WA_CLASSES_MD5 ? Buffer.from(process.env.WA_CLASSES_MD5, 'base64') : null;
const TOKEN_READY    = !!(WA_CERT_DER && WA_CLASSES_MD5);

const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

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

function buildToken(phone) {
  const digits = Buffer.from(phone.replace('+', ''), 'utf8');
  const data = Buffer.concat([WA_CERT_DER, WA_CLASSES_MD5, digits]);
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
    ipLimited:      false,
    cloneSupport:   false,
    noCloneSupport: false,
    limitActive:    false,
    limitType:      null,
    tokenRejected:  false,
    canReceiveOTP:  true,
    raw:            null,
    httpStatus:     0,
    errorDetail:    null
  };

  if (!TOKEN_READY) {
    state.canReceiveOTP = false;
    state.tokenRejected = true;
    state.errorDetail = 'Token belum disetup (jalankan node setup-apk.js)';
    return state;
  }

  // ─── STAGE 1: CEK EXIST ────────────────────────────────────────────────────
  const existParams = new URLSearchParams({
    cc, in: inn, lg: 'id', lc: 'ID', id: rndId()
  });
  const existEnc = encryptParams(existParams.toString());

  try {
    const existRes = await axios.get('https://v.whatsapp.net/v2/exist', {
      params: { ENC: existEnc },
      headers: baseHeaders(ua),
      timeout: 10_000,
      validateStatus: () => true,
    });

    const existBody = existRes.data || {};
    if (existBody.status === 'ok' && existBody.login) {
      state.registered = true;
    } else if (existBody.status === 'fail' && !existBody.login) {
      if (existBody.reason !== 'bad_token' && existBody.reason !== 'bad_param') {
        state.registered = false;
        state.canReceiveOTP = false;
        return state;
      }
    }
  } catch (e) {
    if (DEBUG) console.log(`[EXIST ERR] ${phone} | ${e.message}`);
  }

  // ─── STAGE 2: CEK CODE (REQUEST OTP) ───────────────────────────────────────
  const token = buildToken(phone);
  
  const codeParams = new URLSearchParams({
    cc,
    in:                  inn,
    lg:                  'id',
    lc:                  'ID',
    mistyped:            '6',
    multidevice:         'true',
    method:              'sms',
    sim_mcc:             '510',
    sim_mnc:             '001',
    network_radio_type:  '1',
    reason:              '',
    token:               token,
    id:                  rndId(),
    backup_token:        '',
    entered:             '',
    authkey:             ''
  });

  const codeEnc = encryptParams(codeParams.toString());

  try {
    const codeRes = await axios.get('https://v.whatsapp.net/v2/code', {
      params:         { ENC: codeEnc },
      headers:        baseHeaders(ua),
      timeout:        12_000,
      validateStatus: () => true,
    });

    state.httpStatus = codeRes.status;
    state.raw        = codeRes.data;

    if (DEBUG) console.log(`[CODE] ${phone} | HTTP ${codeRes.status} | ${JSON.stringify(codeRes.data)}`);

    const body = codeRes.data || {};
    const s = String(body.status || '').toLowerCase();
    const reason = String(body.reason || '').toLowerCase();
    
    // Baca retry_after ATAU resend_after_seconds
    const retry = parseInt(
      body.retry_after ?? 
      body.resend_after_seconds ?? 
      body.sec_wait ?? 
      body.retry ?? 
      '0', 10
    ) || 0;

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

    if (reason === 'temporarily_unavailable') {
      state.registered = true;
      state.ipLimited = true;
      state.cooldownSecs = retry > 0 ? retry : 300;
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

    if (reason === 'no_routes' || reason === 'mismatch' || reason === 'no_multidevice') {
      state.registered = true;
      state.noCloneSupport = true;
      state.canReceiveOTP = false;
      return state;
    }

    if (reason === 'bad_param' || reason === 'bad_token' || codeRes.status === 401 || codeRes.status === 403) {
      state.tokenRejected = true;
      state.canReceiveOTP = false;
      state.errorDetail = `Param/Token Invalid: ${body.param || 'unknown'}`;
      return state;
    }

    return state;
  } catch (err) {
    if (DEBUG) console.log(`[CODE ERR] ${phone} | ${err.message}`);
    state.httpStatus = 0;
    state.canReceiveOTP = false;
    state.errorDetail = err.message;
    return state;
  }
}
