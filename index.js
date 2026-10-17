// index.js — entry point
// Runtime: Node.js 18+
// Stack: Telegraf + axios

import 'dotenv/config';
import { Telegraf } from 'telegraf';
import { registerDetek } from './handler/detek.js';

if (!process.env.BOT_TOKEN) {
  console.error('❌ BOT_TOKEN tidak ditemukan di .env');
  process.exit(1);
}

const bot = new Telegraf(process.env.BOT_TOKEN);

// register semua handler
registerDetek(bot);

// /start
bot.command('start', ctx =>
  ctx.reply(
    '👋 Bot aktif.\n\n' +
    'Cara pakai:\n' +
    '`/detek +628xxx` — probe satu nomor\n' +
    '`/detek +628xxx +6281xxx` — probe banyak sekaligus\n' +
    'Atau kirim nomor langsung tanpa command.\n\n' +
    '`/stop` — hentikan monitor aktif',
    { parse_mode: 'Markdown' }
  )
);

// error handler global
bot.catch((err, ctx) => {
  console.error(`[BOT ERROR] ${ctx.updateType}:`, err.message);
});

bot.launch();
console.log('✅ Bot running...');

process.once('SIGINT',  () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));
