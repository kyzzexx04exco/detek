// utils/probe.js — WA Probe via Baileys (Pairing Code - PRODUCTION STABLE)
import makeWASocket, { useMultiFileAuthState, DisconnectReason } from '@whiskeysockets/baileys';
import pino from 'pino';

const logger = pino({ level: 'silent' });
let sock = null;
let isInitializing = false;

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

export async function initWA() {
  if (sock) return sock;
  if (isInitializing) {
    while (isInitializing) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    if (sock) return sock;
  }

  isInitializing = true;
  try {
    const { state, saveCreds } = await useMultiFileAuthState('auth_session');
    
    // FIX: Handle ESM/CJS export differences
    const socketFactory = makeWASocket.default || makeWASocket;
    
    sock = socketFactory({
      auth: state,
      logger,
      browser: ['Chrome', 'Windows', '10.0'],
      printQRInTerminal: false
    });

    sock.ev.on('creds.update', saveCreds);

    sock.ev.on('connection.update', (update) => {
      const { connection, lastDisconnect } = update;
      if (connection === 'close') {
        const code = lastDisconnect?.error?.output?.statusCode;
        if (code !== DisconnectReason.loggedOut) {
          sock = null; 
        }
      }
    });

    await new Promise(resolve => setTimeout(resolve, 2000));
  } catch (err) {
    sock = null;
    throw err;
  } finally {
    isInitializing = false;
  }

  return sock;
}

export async function probeNumber(phone) {
  let client;
  try {
    client = await initWA();
  } catch (e) {
    return {
      phone,
      registered:     false,
      banned:         false,
      cooldown:       false,
      canReceiveOTP:  false,
      errorDetail:    `Socket Init Failed: ${e.message}`
    };
  }

  const cleanPhone = phone.replace('+', '').replace(/[^0-9]/g, '');

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
    canReceiveOTP:  true,
    raw:            null,
    httpStatus:     200,
    errorDetail:    null
  };

  try {
    const code = await client.requestPairingCode(cleanPhone);
    
    state.registered = true;
    state.canReceiveOTP = true;
    state.cloneSupport = true; 
    state.raw = { pairing_code: code };
    
    return state;
  } catch (err) {
    const msg = String(err.message || err.text || err || '').toLowerCase();
    state.raw = { error: msg };

    if (msg.includes('rate-overlimit') || msg.includes('too_fast') || msg.includes('too_many_requests') || msg.includes('429')) {
      state.registered = true;
      state.cooldown = true;
      state.canReceiveOTP = false;
      state.cooldownSecs = 14400;
      state.limitType = 'rate';
    } else if (msg.includes('forbidden') || msg.includes('bad-request') || msg.includes('403')) {
      state.registered = true; 
      state.banned = true;
      state.bannedType = 'permanent';
      state.canReceiveOTP = false;
    } else if (msg.includes('item-not-found') || msg.includes('not-authorized') || msg.includes('404')) {
      state.registered = false;
      state.canReceiveOTP = false;
    } else {
      state.canReceiveOTP = false;
      state.errorDetail = msg;
    }

    return state;
  }
}
