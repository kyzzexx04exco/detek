// index.js — entry point
import 'dotenv/config';
import { Telegraf } from 'telegraf';
import { registerDetek } from './handler/detek.js';
import { initWA } from './utils/probe.js';

if (!process.env.BOT_TOKEN) {
  console.error('❌ BOT_TOKEN tidak ditemukan di .env');
  process.exit(1);
}

const bot = new Telegraf(process.env.BOT_TOKEN);

(async () => {
  try {
    console.log('[+] Menyiapkan Baileys WebSocket...');
    await initWA();
    console.log('[✓] WebSocket siap (Pairing Code Mode).');
    
    registerDetek(bot);

    bot.command('start', ctx =>
      ctx.reply(
        '👋 Bot aktif.\n\n' +
        'Cara pakai:\n' +
        '`/detek +628xxx` — cek status & cooldown nomor\n' +
        'Atau kirim nomor langsung tanpa command.\n\n' +
        '`/stop` — hentikan monitor aktif',
        { parse_mode: 'Markdown' }
      )
    );

    bot.catch((err, ctx) => {
      console.error(`[BOT ERROR] ${ctx.updateType}:`, err.message);
    });

    bot.launch();
    console.log('✅ Bot running...');

    process.once('SIGINT',  () => bot.stop('SIGINT'));
    process.once('SIGTERM', () => bot.stop('SIGTERM'));
    
  } catch (err) {
    console.error('❌ Gagal inisialisasi WA WebSocket:', err.message);
    process.exit(1);
  }
})();
