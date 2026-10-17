#!/usr/bin/env node
// setup-apk.js — extract WA_CERT_DER + WA_CLASSES_MD5 dari WhatsApp.apk
//   npm install
//   node setup-apk.js /path/to/WhatsApp.apk

import AdmZip  from 'adm-zip';
import crypto  from 'crypto';
import fs      from 'fs';
import path    from 'path';

const DEBUG_APK = process.env.DEBUG === '1';

const apkPath = process.argv[2];

if (!apkPath) {
  console.error('Usage: node setup-apk.js /path/to/WhatsApp.apk');
  process.exit(1);
}

if (!fs.existsSync(apkPath)) {
  console.error(`File not found: ${apkPath}`);
  process.exit(1);
}

console.log(`[+] Reading APK: ${apkPath}`);

let zip;
try {
  zip = new AdmZip(apkPath);
} catch (e) {
  console.error(`[-] Gagal buka APK: ${e.message}`);
  process.exit(1);
}

// ─── 1. classesMD5 ────────────────────────────────────────────────────────────
let classesMD5B64;
{
  const dexEntry = zip.getEntry('classes.dex');
  if (!dexEntry) {
    console.error('[-] classes.dex tidak ditemukan di APK');
    process.exit(1);
  }
  const dexBytes = dexEntry.getData();
  const md5Raw   = crypto.createHash('md5').update(dexBytes).digest();
  classesMD5B64  = md5Raw.toString('base64');
  console.log(`[+] classes.dex MD5 (base64): ${classesMD5B64}`);
}

// ─── 2. signing cert DER dari PKCS#7 ─────────────────────────────────────────
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

  const certDER = extractCertFromPKCS7(pkcs7Bytes);
  if (!certDER) {
    console.error('[-] Gagal parse cert dari PKCS#7.');
    process.exit(1);
  }

  certDERB64 = certDER.toString('base64');
  console.log(`[+] Cert DER (${certDER.length} bytes), base64: ${certDERB64.slice(0, 40)}...`);
}

// ─── 3. tulis .env di cwd ────────────────────────────────────────────────────
const projectEnv        = path.join(process.cwd(), '.env');
const projectEnvExists  = fs.existsSync(projectEnv);
const projectEnvContent = projectEnvExists ? fs.readFileSync(projectEnv, 'utf8') : '';

const filtered = projectEnvContent
  .split('\n')
  .filter(l => !l.startsWith('WA_CERT_DER=') && !l.startsWith('WA_CLASSES_MD5='))
  .join('\n')
  .trimEnd();

const newContent = (filtered ? filtered + '\n' : '') +
  `WA_CERT_DER=${certDERB64}\n` +
  `WA_CLASSES_MD5=${classesMD5B64}\n`;

fs.writeFileSync(projectEnv, newContent);
console.log(`\n[✓] Ditulis ke ${projectEnv}`);
console.log('[✓] Setup selesai. Sekarang jalankan: node probe.js +628xxx');

// ─── PKCS#7 parser ────────────────────────────────────────────────────────────
// ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
// SignedData  ::= SEQUENCE { version, digestAlgorithms SET, encapContentInfo,
//                            certificates [0] IMPLICIT, ... }
// Path: outer.seq -> skip OID -> [0] -> SignedData.seq -> skip version ->
//       skip SET -> skip encapContentInfo SEQUENCE -> [0] certificates ->
//       first certificate = SEQUENCE (raw)

function extractCertFromPKCS7(buf) {
  try {
    const der        = new DERParser(buf);
    const outer      = der.readSequence();
    outer.readOID();                         // signedData OID
    const tagged     = outer.readTagged(0);  // [0] EXPLICIT → SignedData
    const signedData = tagged.readSequence(); // SignedData SEQUENCE
    signedData.readInteger();                // version
    signedData.readSet();                    // digestAlgorithms
    signedData.readSequence();               // encapContentInfo (skip whole)
    const certsField = signedData.readTagged(0); // [0] IMPLICIT certificates
    // certsField is a SET OF Certificate — read first SEQUENCE
    const cert = certsField.readSequence_raw();
    // Verify it's a plausible X.509 SEQUENCE
    if (!cert || cert.length < 100 || cert[0] !== 0x30) {
      throw new Error('extracted cert not a SEQUENCE');
    }
    return cert;
  } catch (e) {
    if (DEBUG_APK) console.error('[PKCS7 parse error]', e.message);
    return null;
  }
}

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

  readLength() {
    const b = this.readByte();
    if (b < 0x80) return b;
    const nBytes = b & 0x7f;
    if (nBytes === 0 || nBytes > 4) throw new Error('DER: bad length');
    let len = 0;
    for (let i = 0; i < nBytes; i++) len = (len << 8) | this.readByte();
    return len;
  }

  readTLV() {
    const tag   = this.readByte();
    const len   = this.readLength();
    const start = this.offset;
    if (start + len > this.end) throw new Error('DER: length overflow');
    this.offset += len;
    return { tag, value: this.buf.subarray(start, this.offset) };
  }

  readTLV_raw() {
    const start    = this.offset;
    this.readByte();        // tag
    this.readLength();      // length
    const len      = this.offset - start - 1 - (this.buf[start + 1] < 0x80 ? 1 : 1 + (this.buf[start + 1] & 0x7f));
    // simpler: recompute
    this.offset = start;
    this.readByte();
    const lenBytes = this.readByte();
    const nLen     = lenBytes < 0x80 ? lenBytes : (() => {
      let n = 0;
      for (let i = 0; i < (lenBytes & 0x7f); i++) n = (n << 8) | this.readByte();
      return n;
    })();
    this.offset += nLen;
    return this.buf.subarray(start, this.offset);
  }

  child(value) { return new DERParser(value, 0, value.length); }

  readSequence() {
    const { tag, value } = this.readTLV();
    if (tag !== 0x30) throw new Error(`Expected SEQUENCE, got 0x${tag.toString(16)}`);
    return this.child(value);
  }

  readSequence_raw() { return this.readTLV_raw(); }

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
