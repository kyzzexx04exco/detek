# wa-otp-monitor

Bot Telegram untuk monitor cooldown OTP WhatsApp.

## Setup

```bash
npm install
cp .env.example .env
# isi BOT_TOKEN di .env dengan token dari @BotFather
node index.js
```

## Cara pakai

```
/detek +628xxx
/detek +628xxx +6281xxx +62812xxx
```

Atau kirim nomor langsung tanpa command.

`/stop` — hentikan monitor aktif.

## Debug

Tambahkan `DEBUG=1` di `.env` untuk lihat raw response WA di console.

## Struktur

```
wa-otp-monitor/
├── index.js          — entry point
├── handler/
│   └── detek.js      — command handler + auto-refresh
├── utils/
│   ├── validator.js  — filter E.164 + WA prefix
│   └── probe.js      — HTTP probe ke WA endpoint
├── .env.example
└── package.json
```

## Note

Kalau probe balik 403 atau hasil aneh, aktifkan DEBUG=1 dan kirim
raw response-nya — kemungkinan token format perlu disesuaikan
dengan versi WA terbaru.
