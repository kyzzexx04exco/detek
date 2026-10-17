#!/usr/bin/env node
// setup-apk.js — extract WA_CERT_DER + WA_CLASSES_MD5 dari WhatsApp.apk
// Jalankan SATU KALI sebelum pakai bot:
//   npm install adm-zip --save-dev
//   node setup-apk.js /path/to/WhatsApp.apk
//
// Output: tambahin 2 baris ke .env

import AdmZip  from 'adm-zip';
import crypto  from 'crypto';
import fs      from 'fs';
import path    from 'path';

const apkPath = process.argv[2];

if (!apkPath) {
  console.error('Usage: node setup-apk.js /path/to/WhatsApp.apk');
  console.error('\nDownload APK dari: https://www.apkmirror.com/apk/whatsapp-inc/whatsapp/');
  process.exit(1);
}

if (!fs.existsSync(apkPath)) {
  console.error(`File not found: ${apkPath}`);
  process.exit(1);
}

console.log(`[+] Reading APK: ${apkPath}`);

const zip = new AdmZip(apkPath);

// ─── 1. Extract classesMD5 ────────────────────────────────────────────────────
// MD5(classes.dex) → raw 16 bytes → base64
let classesMD5B64;
{
  const dexEntry = zip.getEntry('classes.dex');
  if (!dexEntry) {
    console.error('[-] classes.dex tidak ditemukan di APK');
    process.exit(1);
  }
  const dexBytes  = dexEntry.getData();
  const md5Raw    = crypto.createHash('md5').update(dexBytes).digest(); // raw Buffer, 16 bytes
  classesMD5B64   = md5Raw.toString('base64');
  console.log(`[+] classes.dex MD5 (base64): ${classesMD5B64}`);
}

// ─── 2. Extract signing cert DER ─────────────────────────────────────────────
// APK signing cert ada di META-INF/CERT.RSA (atau *.RSA / *.DSA)
// Format: PKCS#7 SignedData. Cert DER ada di dalamnya.
let certDERB64;
{
  const rsaEntry = zip.getEntries().find(e =>
    /^META-INF\/.+\.(RSA|DSA|EC)$/i.test(e.entryName)
  );

  if (!rsaEntry) {
    console.error('[-] Signing cert tidak ditemukan (META-INF/*.RSA tidak ada)');
    process.exit(1);
  }

  const pkcs7Bytes = rsaEntry.getData();
  console.log(`[+] Found signing block: ${rsaEntry.entryName} (${pkcs7Bytes.length} bytes)`);

  // Parse PKCS#7 SignedData untuk ambil X.509 cert DER
  // PKCS#7 DER structure:
  //   SEQUENCE {
  //     OID (signedData = 1.2.840.113549.1.7.2)
  //     [0] {
  //       SEQUENCE (SignedData) {
  //         INTEGER (version)
  //         SET (digestAlgorithms)
  //         SEQUENCE (contentInfo)
  //         [0] { SEQUENCE (certificates) }   ← ini yang kita mau
  //         ...
  //       }
  //     }
  //   }

  const certDER = extractCertFromPKCS7(pkcs7Bytes);
  if (!certDER) {
    console.error('[-] Gagal parse cert dari PKCS#7. Coba manual dengan openssl:');
    console.error(`    openssl pkcs7 -in ${rsaEntry.entryName} -inform DER -print_certs`);
    process.exit(1);
  }

  certDERB64 = certDER.toString('base64');
  console.log(`[+] Cert DER (${certDER.length} bytes), base64: ${certDERB64.slice(0, 40)}...`);
}

// ─── 3. Tulis ke .env ─────────────────────────────────────────────────────────
const envPath   = path.join(path.dirname(apkPath), '.env');
const envExists = fs.existsSync(envPath);
const envFile   = envExists ? fs.readFileSync(envPath, 'utf8') : '';

// Filter out existing WA_ lines
const filtered = envFile
  .split('\n')
  .filter(l => !l.startsWith('WA_CERT_DER=') && !l.startsWith('WA_CLASSES_MD5='))
  .join('\n')
  .trimEnd();

const newContent = (filtered ? filtered + '\n' : '') +
  `WA_CERT_DER=${certDERB64}\n` +
  `WA_CLASSES_MD5=${classesMD5B64}\n`;

// Tulis ke .env di direktori project (satu level di atas apk jika apk di luar project)
const projectEnv = path.join(process.cwd(), '.env');
const projectEnvExists = fs.existsSync(projectEnv);
const projectEnvContent = projectEnvExists ? fs.readFileSync(projectEnv, 'utf8') : '';

const filteredProject = projectEnvContent
  .split('\n')
  .filter(l => !l.startsWith('WA_CERT_DER=') && !l.startsWith('WA_CLASSES_MD5='))
  .join('\n')
  .trimEnd();

const newProjectContent = (filteredProject ? filteredProject + '\n' : '') +
  `WA_CERT_DER=${certDERB64}\n` +
  `WA_CLASSES_MD5=${classesMD5B64}\n`;

fs.writeFileSync(projectEnv, newProjectContent);
console.log(`\n[✓] Ditulis ke ${projectEnv}`);
console.log('\n[✓] Setup selesai. Sekarang jalankan: node index.js');

// ─── parser PKCS#7 ────────────────────────────────────────────────────────────
// Minimal DER parser untuk extract cert dari PKCS#7 SignedData

function extractCertFromPKCS7(buf) {
  try {
    // Cari tag 0xa0 (context [0]) yang berisi certificates
    // Walk the ASN.1 structure
    const der = new DERParser(buf);
    const outer = der.readSequence(); // outer SEQUENCE
    outer.readOID();                  // skip OID (signedData)
    const tagged = outer.readTagged(0); // [0] EXPLICIT
    const signedData = tagged.readSequence(); // SignedData SEQUENCE
    signedData.readInteger();             // skip version
    signedData.readSet();                 // skip digestAlgorithms
    signedData.readSequence();            // skip contentInfo
    // [0] certificates
    const certs = signedData.readTagged(0);
    const cert = certs.readSequence_raw();  // first cert, raw DER
    return cert;
  } catch (e) {
    if (DEBUG_APK) console.error('[PKCS7 parse error]', e.message);
    return null;
  }
}

const DEBUG_APK = process.env.DEBUG === '1';

class DERParser {
  constructor(buf, offset = 0, length = buf.length) {
    this.buf    = buf;
    this.offset = offset;
    this.end    = offset + length;
  }

  peek() { return this.buf[this.offset]; }

  readByte() {
    if (this.offset >= this.end) throw new Error('DER: unexpected end');
    return this.buf[this.offset++];
  }

  readTag() { return this.readByte(); }

  readLength() {
    const b = this.readByte();
    if (b < 0x80) return b;
    const nBytes = b & 0x7f;
    let len = 0;
    for (let i = 0; i < nBytes; i++) len = (len << 8) | this.readByte();
    return len;
  }

  readTLV() {
    const tag = this.readTag();
    const len = this.readLength();
    const start = this.offset;
    this.offset += len;
    return { tag, value: this.buf.subarray(start, this.offset) };
  }

  readTLV_raw() {
    const start = this.offset;
    const tag   = this.readTag();
    const lenStart = this.offset;
    const len   = this.readLength();
    const dataStart = this.offset;
    this.offset += len;
    return this.buf.subarray(start, this.offset);
  }

  child(value) {
    return new DERParser(value, 0, value.length);
  }

  readSequence() {
    const { tag, value } = this.readTLV();
    if ((tag & 0x1f) !== 0x10 && tag !== 0x30) throw new Error(`Expected SEQUENCE, got 0x${tag.toString(16)}`);
    return this.child(value);
  }

  readSequence_raw() {
    return this.readTLV_raw();
  }

  readSet() {
    const { tag, value } = this.readTLV();
    if (tag !== 0x31) throw new Error(`Expected SET, got 0x${tag.toString(16)}`);
    return this.child(value);
  }

  readOID() {
    const { tag, value } = this.readTLV();
    if (tag !== 0x06) throw new Error(`Expected OID, got 0x${tag.toString(16)}`);
    return value;
  }

  readInteger() {
    const { tag, value } = this.readTLV();
    if (tag !== 0x02) throw new Error(`Expected INTEGER, got 0x${tag.toString(16)}`);
    return value;
  }

  readTagged(n) {
    const expected = 0xa0 | n;
    const { tag, value } = this.readTLV();
    if (tag !== expected) throw new Error(`Expected [${n}] (0x${expected.toString(16)}), got 0x${tag.toString(16)}`);
    return this.child(value);
  }

  hasMore() { return this.offset < this.end; }
}
