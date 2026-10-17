// setup-apk.js — Auto-fetch APK, extract cert + classes MD5, write .env
// Jalankan: node setup-apk.js

import axios  from 'axios';
import AdmZip from 'adm-zip';
import crypto from 'crypto';
import fs     from 'fs';
import path   from 'path';

const DEBUG_APK = process.env.DEBUG === '1';

async function main() {
  console.log('[+] Auto-fetching latest WhatsApp APK from APKPure...');
  
  let buffer;
  try {
    const res = await axios({
      method: 'get',
      url: 'https://d.apkpure.com/b/APK/com.whatsapp?version=latest',
      responseType: 'arraybuffer',
      maxRedirects: 10,
      timeout: 120_000,
      headers: { 'User-Agent': 'Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36' }
    });
    buffer = Buffer.from(res.data);
  } catch (e) {
    console.error('[-] Download failed:', e.message);
    process.exit(1);
  }

  if (buffer.length < 10 * 1024 * 1024) {
    console.error('[-] File terlalu kecil, kemungkinan kena block atau bukan APK.');
    process.exit(1);
  }

  console.log(`[+] Downloaded ${(buffer.length / 1024 / 1024).toFixed(1)} MB`);
  const zip = new AdmZip(buffer);

  // 1. Extract classesMD5
  const dexEntry = zip.getEntry('classes.dex');
  if (!dexEntry) {
    console.error('[-] classes.dex tidak ditemukan.');
    process.exit(1);
  }
  const md5Raw = crypto.createHash('md5').update(dexEntry.getData()).digest();
  const classesMD5B64 = md5Raw.toString('base64');
  console.log(`[+] classes.dex MD5: ${classesMD5B64}`);

  // 2. Extract cert DER
  const rsaEntry = zip.getEntries().find(e =>
    /^META-INF\/.+\.(RSA|DSA|EC)$/i.test(e.entryName)
  );
  if (!rsaEntry) {
    console.error('[-] Signing cert tidak ditemukan.');
    process.exit(1);
  }

  const certDER = extractCertFromPKCS7(rsaEntry.getData());
  if (!certDER) {
    console.error('[-] Gagal parse cert PKCS#7.');
    process.exit(1);
  }
  const certDERB64 = certDER.toString('base64');
  console.log(`[+] Cert DER extracted (${certDER.length} bytes)`);

  // 3. Tulis ke .env
  const projectEnv = path.join(process.cwd(), '.env');
  const envContent = fs.existsSync(projectEnv) ? fs.readFileSync(projectEnv, 'utf8') : '';
  const filtered = envContent.split('\n')
    .filter(l => !l.startsWith('WA_CERT_DER=') && !l.startsWith('WA_CLASSES_MD5='))
    .join('\n')
    .trimEnd();

  fs.writeFileSync(projectEnv, (filtered ? filtered + '\n' : '') +
    `WA_CERT_DER=${certDERB64}\n` +
    `WA_CLASSES_MD5=${classesMD5B64}\n`
  );
  console.log(`[✓] Hash berhasil disimpan ke .env`);
}

function extractCertFromPKCS7(buf) {
  try {
    const der        = new DERParser(buf);
    const outer      = der.readSequence();
    outer.readOID();
    const tagged     = outer.readTagged(0);
    const signedData = tagged.readSequence();
    signedData.readInteger();
    signedData.readSet();
    signedData.readSequence();
    const certsField = signedData.readTagged(0);
    const cert = certsField.readSequence_raw();
    if (!cert || cert.length < 100 || cert[0] !== 0x30) throw new Error('not a SEQUENCE');
    return cert;
  } catch (e) {
    if (DEBUG_APK) console.error('[PKCS7 error]', e.message);
    return null;
  }
}

class DERParser {
  constructor(buf, offset = 0, length = buf.length) {
    this.buf = buf; this.offset = offset; this.end = offset + length;
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
    const tag = this.readByte();
    const len = this.readLength();
    const start = this.offset;
    if (start + len > this.end) throw new Error('DER: length overflow');
    this.offset += len;
    return { tag, value: this.buf.subarray(start, this.offset) };
  }
  readTLV_raw() {
    const start = this.offset;
    this.readByte();
    const lenBytes = this.readByte();
    const nLen = lenBytes < 0x80 ? lenBytes : (() => {
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
    if (tag !== expected) throw new Error(`Expected [${n}], got 0x${tag.toString(16)}`);
    return this.child(value);
  }
  hasMore() { return this.offset < this.end; }
}

main().catch(e => { console.error(e); process.exit(1); });
