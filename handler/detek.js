// handler/detek.js — /detek command + live monitor

import { parseNumbers, fmtDuration } from '../utils/validator.js';
import { probeNumber }               from '../utils/probe.js';

const sessions   = new Map();
const REFRESH_MS = 60_000;
const MONITOR_MS = 24 * 60 * 60 * 1000;

// ─── format pesan output ─────────────────────────────────────────────────────

function buildMessage(results, startTs) {
  const now    = Date.now();
  const remain = Math.max(0, Math.floor((startTs + MONITOR_MS - now) / 1000));
  const clock  = new Date().toLocaleTimeString('id-ID', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });

  const clean    = results.filter(r => r.registered && !r.cooldown && !r.banned && !r.limitActive && r.canReceiveOTP);
  const cooldown = results.filter(r => r.cooldown);
  const noOTP    = results.filter(r => !r.canReceiveOTP && !r.cooldown);

  let msg = `◉ OTP COOLDOWN MONITOR\n\n`;
  msg += `> ⚠️ Waktu cooldown bisa berubah sewaktu-waktu. Jika ada yang mencoba login ke nomor tersebut, cooldown akan direset ulang oleh WhatsApp.\n\n`;
  msg += `> Segera login ke nomor yang telah melakukan detek.\n\n`;

  msg += `> Nomor yang tidak cooldown\n`;
  if (clean.length) {
    clean.forEach(r => { msg += `${r.phone}\n`; });
  } else {
    msg += `(tidak ada)\n`;
  }
  msg += `\n`;

  msg += `> Nomor yang sedang cooldown\n\n`;
  if (cooldown.length) {
    cooldown.forEach(r => {
      const cd = r.cooldownSecs ? fmtDuration(r.cooldownSecs) : '?';
      msg += `${r.phone}\n  ${cd}\n\n`;
    });
  } else {
    msg += `(tidak ada)\n\n`;
  }

  msg += `> Nomor yang tidak dapat menerima OTP\n\n`;
  if (noOTP.length) {
    noOTP.forEach(r => {
      let reason;
      if (r.banned)              reason = 'Ke ban';
      else if (!r.registered)    reason = 'Gak Support Clone';
      else if (r.noCloneSupport) reason = 'Gak Support Clone';
      else if (r.limitActive)    reason = r.limitType === 'new_account' ? 'Akun baru (limit)' : 'Limit aktif';
      else                       reason = 'Tidak bisa terima OTP';
      msg += `${reason}\n${r.phone}\n\n`;
    });
  } else {
    msg += `(tidak ada)\n\n`;
  }

  msg += `⟳ ${clock}\n`;
  msg += `⏱ Monitor aktif: ${fmtDuration(remain) || '< 1m'} lagi\n`;
  msg += `↻ Diperbarui otomatis`;

  return msg;
}

async function runProbes(numbers) {
  const results = [];
  for (const num of numbers) {
    const r = await probeNumber(num);
    results.push(r);
    await new Promise(res => setTimeout(res, 1200));
  }
  return results;
}

function stopSession(chatId) {
  const s = sessions.get(chatId);
  if (s) { clearInterval(s.intervalId); sessions.delete(chatId); }
}

// ─── register handler ─────────────────────────────────────────────────────────

export function registerDetek(bot) {
  const handle = async (ctx) => {
    const text = (ctx.message?.text || '').trim();
    const raw  = text.replace(/^\/detek\s*/i, '').trim();

    if (!raw) return ctx.reply('⚠️ Kasih nomor dulu.\n\nContoh:\n`/detek +628xxx`', { parse_mode: 'Markdown' });

    const { valid, invalid } = parseNumbers(raw);
    if (!valid.length) return ctx.reply('❌ Tidak ada nomor valid.\n\nFormat: `+628xxxxxxxxx`', { parse_mode: 'Markdown' });

    const chatId = ctx.chat.id;
    stopSession(chatId);

    const loadMsg = await ctx.reply(
      `🔍 Memprobe ${valid.length} nomor via multi-service...${invalid.length ? `\n_(${invalid.length} dilewati)_` : ''}`,
      { parse_mode: 'Markdown' }
    );

    const startTs = Date.now();
    const results = await runProbes(valid);
    const sent    = await ctx.reply(buildMessage(results, startTs));
    await ctx.telegram.deleteMessage(chatId, loadMsg.message_id).catch(() => {});

    const intervalId = setInterval(async () => {
      const session = sessions.get(chatId);
      if (!session) return;

      if (Date.now() - session.startTs >= MONITOR_MS) {
        stopSession(chatId);
        await ctx.telegram.editMessageText(chatId, session.msgId, null,
          buildMessage(session.results, session.startTs) + '\n\n🔴 Monitor selesai.'
        ).catch(() => {});
        return;
      }

      const fresh = await runProbes(valid);
      session.results = fresh;
      await ctx.telegram.editMessageText(chatId, session.msgId, null, buildMessage(fresh, session.startTs)).catch(() => {});
    }, REFRESH_MS);

    sessions.set(chatId, { msgId: sent.message_id, numbers: valid, results, startTs, intervalId });
  };

  bot.command('detek', handle);

  bot.on('text', async (ctx, next) => {
    const text = (ctx.message?.text || '').trim();
    if (text.startsWith('/')) return next();
    const { valid } = parseNumbers(text);
    if (valid.length >= 1 && valid.length <= 20) {
      ctx.message.text = '/detek ' + text;
      return handle(ctx);
    }
    return next();
  });

  bot.command('stop', async (ctx) => {
    const chatId = ctx.chat.id;
    if (sessions.has(chatId)) { stopSession(chatId); return ctx.reply('🔴 Monitor dihentikan.'); }
    return ctx.reply('Tidak ada monitor aktif.');
  });
}
