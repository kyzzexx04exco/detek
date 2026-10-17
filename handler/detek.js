// handler/detek.js — /detek command + live monitor 24 jam

import { parseNumbers } from '../utils/validator.js';
import { probeNumber, fmtCooldown } from '../utils/probe.js';

// chatId -> { msgId, numbers, results, startTs, intervalId }
const sessions = new Map();

const REFRESH_MS  = 60_000;              // refresh tiap 1 menit
const MONITOR_MS  = 24 * 60 * 60 * 1000; // durasi monitor 24 jam
const PROBE_DELAY = 900;                  // delay antar probe (ms)

// ─── format output ────────────────────────────────────────────────────────────

function buildMessage(results, startTs) {
  const now    = Date.now();
  const remain = Math.max(0, Math.floor((startTs + MONITOR_MS - now) / 1000));
  const clock  = new Date().toLocaleTimeString('id-ID', {
    hour:   '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });

  const clean    = results.filter(r =>
    r.registered && !r.cooldown && !r.banned && !r.limitActive && r.canReceiveOTP
  );
  const cooldown = results.filter(r => r.cooldown);
  const noOTP    = results.filter(r =>
    !r.canReceiveOTP && !r.cooldown
  );

  let msg = `◉ OTP COOLDOWN MONITOR\n\n`;

  msg += `> ⚠️ Waktu cooldown bisa berubah sewaktu-waktu. Jika ada yang mencoba login ke nomor tersebut, cooldown akan direset ulang oleh WhatsApp.\n\n`;
  msg += `> Segera login ke nomor yang telah melakukan detek.\n\n`;

  // ── bersih ──
  msg += `> Nomor yang tidak cooldown\n`;
  if (clean.length) {
    clean.forEach(r => { msg += `${r.phone}\n`; });
  } else {
    msg += `(tidak ada)\n`;
  }

  msg += `\n`;

  // ── cooldown ──
  msg += `> Nomor yang sedang cooldown\n\n`;
  if (cooldown.length) {
    cooldown.forEach(r => {
      const cd = r.cooldownSecs ? fmtCooldown(r.cooldownSecs) : '?';
      msg += `${r.phone}\n  ${cd}\n\n`;
    });
  } else {
    msg += `(tidak ada)\n\n`;
  }

  // ── tidak bisa terima OTP ──
  msg += `> Nomor yang tidak dapat menerima OTP\n\n`;
  if (noOTP.length) {
    noOTP.forEach(r => {
      let reason;
      if (r.banned) {
        reason = r.bannedType === 'permanent'
          ? 'Ke ban (permanent)'
          : 'Ke ban (sementara)';
      } else if (!r.registered) {
        reason = 'Tidak terdaftar WA';
      } else if (r.noCloneSupport) {
        reason = 'Gak Support Clone';
      } else if (r.limitActive) {
        const lt = { spam: 'Spam limit', new_account: 'Akun baru', rate: 'Rate limit' };
        reason = lt[r.limitType] || 'Limit aktif';
      } else {
        reason = 'Tidak bisa terima OTP';
      }
      msg += `${reason}\n${r.phone}\n\n`;
    });
  } else {
    msg += `(tidak ada)\n\n`;
  }

  msg += `⟳ ${clock}\n`;
  msg += `⏱ Monitor aktif: ${fmtCooldown(remain) || '< 1m'} lagi\n`;
  msg += `↻ Diperbarui otomatis`;

  return msg;
}

// ─── probe semua nomor dengan delay ──────────────────────────────────────────

async function runProbes(numbers) {
  const results = [];
  for (const num of numbers) {
    const r = await probeNumber(num);
    results.push(r);
    await delay(PROBE_DELAY);
  }
  return results;
}

function delay(ms) {
  return new Promise(res => setTimeout(res, ms));
}

// ─── stop session ─────────────────────────────────────────────────────────────

function stopSession(chatId) {
  const s = sessions.get(chatId);
  if (s) {
    clearInterval(s.intervalId);
    sessions.delete(chatId);
  }
}

// ─── main handler ─────────────────────────────────────────────────────────────

export function registerDetek(bot) {

  const handle = async (ctx) => {
    const text = (ctx.message?.text || '').trim();
    const raw  = text.replace(/^\/detek\s*/i, '').trim();

    if (!raw) {
      return ctx.reply(
        '⚠️ Kasih nomor dulu.\n\nContoh:\n`/detek +628xxx`\n`/detek +628xxx +6281xxx`',
        { parse_mode: 'Markdown' }
      );
    }

    const { valid, invalid } = parseNumbers(raw);

    if (!valid.length) {
      return ctx.reply(
        '❌ Tidak ada nomor valid ditemukan.\n\nFormat: `+[kode negara][nomor]`\nContoh: `+628123456789`',
        { parse_mode: 'Markdown' }
      );
    }

    const chatId = ctx.chat.id;
    stopSession(chatId);

    const skippedNote = invalid.length
      ? `\n_(${invalid.length} nomor dilewati: tidak valid)_`
      : '';

    const loadMsg = await ctx.reply(
      `🔍 Memprobe ${valid.length} nomor...${skippedNote}`,
      { parse_mode: 'Markdown' }
    );

    const startTs = Date.now();
    let results   = await runProbes(valid);

    const firstMsg = await ctx.reply(buildMessage(results, startTs));

    // hapus loading message
    await ctx.telegram.deleteMessage(chatId, loadMsg.message_id).catch(() => {});

    // setup auto-refresh
    const intervalId = setInterval(async () => {
      const session = sessions.get(chatId);
      if (!session) return;

      // cek apakah sudah 24 jam
      if (Date.now() - session.startTs >= MONITOR_MS) {
        stopSession(chatId);
        await ctx.telegram.editMessageText(
          chatId,
          session.msgId,
          null,
          buildMessage(session.results, session.startTs) + '\n\n🔴 Monitor selesai.'
        ).catch(() => {});
        return;
      }

      // probe ulang
      const fresh = await runProbes(valid);
      session.results = fresh;

      await ctx.telegram.editMessageText(
        chatId,
        session.msgId,
        null,
        buildMessage(fresh, session.startTs)
      ).catch(() => {});

    }, REFRESH_MS);

    sessions.set(chatId, {
      msgId:      firstMsg.message_id,
      numbers:    valid,
      results,
      startTs,
      intervalId,
    });
  };

  // command /detek
  bot.command('detek', handle);

  // plain nomor tanpa command
  bot.on('text', async (ctx, next) => {
    const text = (ctx.message?.text || '').trim();
    if (text.startsWith('/')) return next();

    const { valid } = parseNumbers(text);
    // minimal 1 nomor, maksimal 20
    if (valid.length >= 1 && valid.length <= 20) {
      ctx.message.text = '/detek ' + text;
      return handle(ctx);
    }

    return next();
  });

  // /stop — hentikan monitor
  bot.command('stop', async (ctx) => {
    const chatId = ctx.chat.id;
    if (sessions.has(chatId)) {
      stopSession(chatId);
      return ctx.reply('🔴 Monitor dihentikan.');
    }
    return ctx.reply('Tidak ada monitor aktif.');
  });
}
