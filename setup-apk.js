// setup-apk.js — Auto-fetch APK, extract multi-dex MD5, cert, & auto-sync User-Agent
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
      timeout: 180_000,
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' }
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

  // ─── 1. Ekstrak Versi dari AndroidManifest.xml ─────────────────────────────
  let appVersion = '2.24.13.76'; // Fallback
  try {
    const manifest = zip.getEntry('AndroidManifest.xml');
    if (manifest) {
      const str = manifest.getData().toString('utf8');
      const match = str.match(/(\d{1,2}\.\d{1,2}\.\d{1,2}\.\d{1,2})/);
      if (match && match[1]) appVersion = match[1];
    }
  } catch (e) {}
  console.log(`[+] APK Version Detected: ${appVersion}`);

  // ─── 2. Ekstrak Multi-Dex MD5 ──────────────────────────────────────────────
  console.log('[+] Processing Multi-Dex (classes*.dex)...');
  const dexEntries = zip.getEntries()
    .filter(e => /^classes\d*\.dex$/i.test(e.entryName))
    .sort((a, b) => a.entryName.localeCompare(b.entryName, undefined, { numeric: true }));

  if (dexEntries.length === 0) {
    console.error('[-] File classes.dex tidak ditemukan.');
    process.exit(1);
  }

  const hashList = [];
  for (const entry of dexEntries) {
    const fileHash = crypto.createHash('md5').update(entry.getData()).digest();
    hashList.push(fileHash);
  }
  // Gabungkan seluruh hash dex sesuai urutan (Fix Multi-Dex)
  const finalDexMD5 = crypto.createHash('md5').update(Buffer.concat(hashList)).digest('base64');
  console.log(`[+] Combined Multi-Dex MD5 (Base64): ${finalDexMD5}`);

  // ─── 3. Ekstrak Cert DER ───────────────────────────────────────────────────
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

  // ─── 4. Tulis ke .env (Sertakan WA_UA) ─────────────────────────────────────
  const projectEnv = path.join(process.cwd(), '.env');
  const envContent = fs.existsSync(projectEnv) ? fs.readFileSync(projectEnv, 'utf8') : '';
  const filtered = envContent.split('\n')
    .filter(l => !l.startsWith('WA_CERT_DER=') && !l.startsWith('WA_CLASSES_MD5=') && !l.startsWith('WA_UA='))
    .join('\n')
    .trimEnd();

  fs.writeFileSync(projectEnv, (filtered ? filtered + '\n' : '') +
    `WA_CERT_DER=${certDERB64}\n` +
    `WA_CLASSES_MD5=${finalDexMD5}\n` +
    `WA_UA=WhatsApp/${appVersion} A\n`
  );
  console.log(`\n[✓] Berhasil update .env (Hash + Versi UA: WhatsApp/${appVersion} A)`);
}

function extractCertFromPKCS7(buf) {
  try {
    const der = new DERParser(buf);
    const outer = der.readSequence();
    outer.readOID();
    const tagged = outer.readTagged(0);
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
}

main().catch(e => { console.error(e); process.exit(1); });
