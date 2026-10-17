// utils/validator.js

const VALID_CC = new Set([
  '1','7','20','27','30','31','32','33','34','36','39','40','41',
  '43','44','45','46','47','48','49','51','52','53','54','55','56',
  '57','58','60','61','62','63','64','65','66','81','82','84','86',
  '90','91','92','93','94','95','98','212','213','216','218','220',
  '221','222','223','224','225','226','227','228','229','230','231',
  '232','233','234','235','236','237','238','239','240','241','242',
  '243','244','245','246','247','248','249','250','251','252','253',
  '254','255','256','257','258','260','261','262','263','264','265',
  '266','267','268','269','291','297','298','299','350','351','352',
  '353','354','355','356','357','358','359','370','371','372','373',
  '374','375','376','377','380','381','382','385','386','387','389',
  '420','421','423','500','501','502','503','504','505','506','507',
  '509','591','592','593','595','597','598','670','673','674','675',
  '676','677','678','679','680','685','686','687','689','692','850',
  '852','853','855','856','880','886','960','961','962','963','964',
  '965','966','967','968','970','971','972','973','974','975','976',
  '977','992','993','994','995','996','998'
]);

const WA_PREFIX = {
  '62':  /^8[1-9]\d{6,10}$/,
  '1':   /^[2-9]\d{9}$/,
  '44':  /^7\d{9}$/,
  '91':  /^[6-9]\d{9}$/,
  '60':  /^1\d{7,9}$/,
  '65':  /^[89]\d{7}$/,
  '63':  /^9\d{9}$/,
  '66':  /^[689]\d{8}$/,
  '84':  /^[35789]\d{8}$/,
  '86':  /^1[3-9]\d{9}$/,
  '82':  /^1\d{8,9}$/,
  '81':  /^[789]0\d{8}$/,
  '265': /^[89]\d{7,8}$/,
  '27':  /^[67]\d{8}$/,
  '234': /^[789]\d{9}$/,
  '254': /^7\d{8}$/,
  '255': /^[67]\d{8}$/,
};

function extractCC(digits) {
  for (const len of [3, 2, 1]) {
    const cc = digits.slice(0, len);
    if (VALID_CC.has(cc)) return cc;
  }
  return null;
}

export function parseNumbers(text) {
  const valid   = [];
  const invalid = [];
  const tokens  = text.match(/\+\d[\d\s\-]{3,17}\d|\d{7,15}/g) || [];

  for (const raw of tokens) {
    const cleaned    = raw.replace(/[\s\-]/g, '');
    const normalized = cleaned.startsWith('+') ? cleaned : '+' + cleaned;
    const digits     = normalized.slice(1);

    if (digits.length < 7 || digits.length > 15) { invalid.push(normalized); continue; }

    const cc = extractCC(digits);
    if (!cc) { invalid.push(normalized); continue; }

    const local = digits.slice(cc.length);
    const rule  = WA_PREFIX[cc];
    if (rule && !rule.test(local)) { invalid.push(normalized); continue; }

    valid.push(normalized);
  }

  return { valid: [...new Set(valid)], invalid };
}

export function fmtDuration(secs) {
  if (!secs || secs <= 0) return null;
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  const parts = [];
  if (d) parts.push(`${d}d`);
  if (h) parts.push(`${h}j`);
  if (m) parts.push(`${m}m`);
  if (s && !d && !h) parts.push(`${s}s`);
  return parts.join(' ') || '< 1m';
}
