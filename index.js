// index.js — entry point
// Node.js 18+ | Telegraf + axios

import 'dotenv/config';
import { Telegraf } from 'telegraf';
import { registerDetek } from './handler/detek.js';

if (!process.env.BOT_TOKEN) {
  console.error('❌ BOT_TOKEN tidak ada di .env');
  process.exit(1);
}

const bot = new Telegraf(process.env.BOT_TOKEN);

registerDetek(bot);

bot.command('start', ctx => ctx.reply(
  '👋 Bot aktif.\n\n`/detek +628xxx` — probe nomor\n`/detek +628xxx +6281xxx` — banyak sekaligus\nAtau kirim nomor langsung.\n\n`/stop` — hentikan monitor',
  { parse_mode: 'Markdown' }
));

bot.catch((err, ctx) => {
  console.error(`[ERR] ${ctx?.updateType}:`, err.message);
});

bot.launch();
console.log('✅ Bot running...');

process.once('SIGINT',  () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));
