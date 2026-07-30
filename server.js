/**
 * KG Bidding - Diamond stocklist bidding platform
 * Single-server app: Express + SQLite (node:sqlite, built into Node.js >= 22.13)
 *
 * ENV:
 *   PORT            (default 3000)
 *   ADMIN_PASSWORD  (default "changeme123" - CHANGE IN PRODUCTION)
 *   DATA_DIR        (default ./data - where the SQLite DB lives)
 */
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');
const XLSX = require('xlsx');
const ExcelJS = require('exceljs');
const { DatabaseSync } = require('node:sqlite');

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'changeme123';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new DatabaseSync(path.join(DATA_DIR, 'bidding.db'));
try { db.exec('PRAGMA journal_mode = WAL'); } catch (e) { /* WAL unsupported on this filesystem - default journal is fine */ }
/* better-sqlite3-style transaction helper */
db.transaction = fn => (...args) => {
  db.exec('BEGIN');
  try { const r = fn(...args); db.exec('COMMIT'); return r; }
  catch (e) { db.exec('ROLLBACK'); throw e; }
};

db.exec(`
CREATE TABLE IF NOT EXISTS clients (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  company TEXT NOT NULL,
  contact TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  client_id INTEGER,
  is_admin INTEGER DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  terms TEXT DEFAULT '',
  end_time INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'live',
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS stones (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id INTEGER NOT NULL,
  stone_id TEXT NOT NULL,
  location TEXT, shape TEXT, cts REAL, color TEXT, clarity TEXT,
  cut TEXT, pol TEXT, symm TEXT, fluor TEXT,
  depth_pct REAL, table_pct REAL, measurements TEXT, ratio REAL,
  disc REAL, price_ct REAL, amount REAL, rap REAL,
  lab TEXT, report_no TEXT,
  product_url TEXT, cert_url TEXT, video_url TEXT,
  details_json TEXT,
  UNIQUE(event_id, stone_id)
);
CREATE TABLE IF NOT EXISTS bids (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id INTEGER NOT NULL,
  stone_pk INTEGER NOT NULL,
  client_id INTEGER NOT NULL,
  bid_disc REAL,
  bid_per_ct REAL NOT NULL,
  bid_amount REAL NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(stone_pk, client_id)
);
`);
try { db.exec('ALTER TABLE clients ADD COLUMN password_hash TEXT'); } catch (e) { /* column already exists */ }
try { db.exec('ALTER TABLE events ADD COLUMN headers_json TEXT'); } catch (e) { /* column already exists */ }
/* email verification: existing rows default to 0, so they verify once on next login */
try { db.exec('ALTER TABLE clients ADD COLUMN email_verified INTEGER DEFAULT 0'); } catch (e) { /* exists */ }
db.exec(`
CREATE TABLE IF NOT EXISTS otps (
  contact TEXT PRIMARY KEY,
  code_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  sent_count INTEGER NOT NULL DEFAULT 1,
  first_sent_at INTEGER NOT NULL,
  last_sent_at INTEGER NOT NULL,
  payload TEXT
);
`);

const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 } });

/* ---------------- helpers ---------------- */
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i > -1) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function setCookie(res, name, value) {
  res.append('Set-Cookie', name + '=' + encodeURIComponent(value) + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=' + (60 * 60 * 24 * 30));
}
/* Stateless signed tokens - no DB row needed, so logins survive server restarts */
const SECRET = process.env.SECRET || crypto.createHash('sha256').update('kg-bidding-' + ADMIN_PASSWORD).digest('hex');
function signPayload(p) { return crypto.createHmac('sha256', SECRET).update(p).digest('hex'); }
function makeToken(kind, id) {
  const p = kind + '.' + (id || 0) + '.' + Date.now();
  return p + '.' + signPayload(p);
}
function parseToken(t) {
  if (!t) return null;
  const parts = String(t).split('.');
  if (parts.length !== 4) return null;
  const p = parts.slice(0, 3).join('.');
  if (signPayload(p) !== parts[3]) return null;
  const ts = Number(parts[2]);
  if (!isFinite(ts) || Date.now() - ts > 30 * 24 * 3600 * 1000) return null;
  return { kind: parts[0], id: Number(parts[1]) };
}
function getSession(req) {
  const ck = parseCookies(req);
  const c = parseToken(ck.sid_c);
  const a = parseToken(ck.sid_a);
  const client_id = c && c.kind === 'c' ? c.id : null;
  const is_admin = a && a.kind === 'a' ? 1 : 0;
  if (!client_id && !is_admin) return null;
  return { client_id, is_admin };
}
function requireClient(req, res, next) {
  const s = getSession(req);
  if (!s || !s.client_id) return res.status(401).json({ error: 'Not logged in' });
  req.client = db.prepare('SELECT * FROM clients WHERE id = ?').get(s.client_id);
  if (!req.client) return res.status(401).json({ error: 'Not logged in' });
  next();
}
function requireAdmin(req, res, next) {
  const s = getSession(req);
  if (!s || !s.is_admin) return res.status(401).json({ error: 'Admin login required' });
  next();
}
function hashPw(pw) {
  const salt = crypto.randomBytes(8).toString('hex');
  return salt + ':' + crypto.scryptSync(String(pw), salt, 32).toString('hex');
}
function verifyPw(pw, stored) {
  if (!stored) return false;
  const parts = String(stored).split(':');
  if (parts.length !== 2) return false;
  try { return crypto.timingSafeEqual(Buffer.from(parts[1], 'hex'), crypto.scryptSync(String(pw), parts[0], 32)); }
  catch (e) { return false; }
}
const round2 = n => Math.round(n * 100) / 100;

/* ---------------- email one-time passcodes ---------------- */
const OTP_TTL_MS      = 10 * 60 * 1000;  /* code valid for 10 minutes */
const OTP_MAX_TRIES   = 5;               /* wrong guesses before the code dies */
const OTP_RESEND_WAIT = 60 * 1000;       /* 60s between sends */
const OTP_MAX_SENDS   = 5;               /* per hour, per address */
const OTP_SEND_WINDOW = 60 * 60 * 1000;

/* ---------------- outbound mail: SMTP, Mailgun or Resend ----------------
   Whichever is configured is used automatically, in this order.

   SMTP   :  SMTP_USER, SMTP_PASS  (+ optional SMTP_HOST, SMTP_PORT)
             For Google Workspace / Gmail use an App Password, not the
             account password. Defaults suit Gmail: smtp.gmail.com:465.
   Mailgun:  MAILGUN_API_KEY, MAILGUN_DOMAIN, MAILGUN_REGION ('eu' for EU accounts)
   Resend :  RESEND_API_KEY
   All    :  FROM_EMAIL  e.g.  K.Girdharlal Bidding <bidding@kgirdharlal.com>
*/
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = (process.env.SMTP_PASS || '').replace(/\s+/g, ''); /* Google shows the App Password in 4 spaced blocks */
const SMTP_HOST = process.env.SMTP_HOST || 'smtp.gmail.com';
const SMTP_PORT = Number(process.env.SMTP_PORT || 465);
let smtpTransport = null;
function getSmtp() {
  if (!smtpTransport) {
    const nodemailer = require('nodemailer');
    smtpTransport = nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT,
      secure: SMTP_PORT === 465,           /* 465 = implicit TLS, 587 = STARTTLS */
      auth: { user: SMTP_USER, pass: SMTP_PASS },
      pool: true, maxConnections: 2, maxMessages: 50,
      connectionTimeout: 15000, greetingTimeout: 10000, socketTimeout: 20000
    });
  }
  return smtpTransport;
}
const MAILGUN_API_KEY = process.env.MAILGUN_API_KEY || '';
const MAILGUN_DOMAIN  = process.env.MAILGUN_DOMAIN || '';
const MAILGUN_REGION  = (process.env.MAILGUN_REGION || '').trim().toLowerCase();
const MAILGUN_BASE    = process.env.MAILGUN_API_BASE ||
  (MAILGUN_REGION === 'eu' ? 'https://api.eu.mailgun.net' : 'https://api.mailgun.net');

const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const RESEND_API_URL = process.env.RESEND_API_URL || 'https://api.resend.com/emails';

const FROM_EMAIL = process.env.FROM_EMAIL ||
  (SMTP_USER ? 'K.Girdharlal Bidding <' + SMTP_USER + '>'
   : MAILGUN_DOMAIN ? 'K.Girdharlal Bidding <bidding@' + MAILGUN_DOMAIN + '>'
                    : 'K.Girdharlal Bidding <onboarding@resend.dev>');
/* Optional: mail goes out from a noreply address, but replies land somewhere real. */
const REPLY_TO = (process.env.REPLY_TO || '').trim();
/* pull the bare address out of  Name <addr@host>  */
const bareAddr = s => {
  const m = /<([^>]+)>/.exec(String(s || ''));
  return (m ? m[1] : String(s || '')).trim().toLowerCase();
};

const mailProvider = () =>
  (SMTP_USER && SMTP_PASS) ? 'smtp'
  : (MAILGUN_API_KEY && MAILGUN_DOMAIN) ? 'mailgun'
  : (RESEND_API_KEY ? 'resend' : null);
const mailReady = () => !!mailProvider();

/* ---------------- daily send cap ----------------
   Safety limit while testing. Set MAIL_DAILY_CAP in Render to any number;
   leave it out (or set 0) for no limit. Counted per India-time day. */
const MAIL_DAILY_CAP = Math.max(0, Number(process.env.MAIL_DAILY_CAP || 0) || 0);
db.exec('CREATE TABLE IF NOT EXISTS mail_usage (day TEXT PRIMARY KEY, sent INTEGER NOT NULL DEFAULT 0)');
const istDay = () => new Date(Date.now() + 5.5 * 3600 * 1000).toISOString().slice(0, 10);
function mailSentToday() {
  const r = db.prepare('SELECT sent FROM mail_usage WHERE day = ?').get(istDay());
  return r ? r.sent : 0;
}
function noteMailSent() {
  db.prepare('INSERT INTO mail_usage (day, sent) VALUES (?,1) ' +
             'ON CONFLICT(day) DO UPDATE SET sent = sent + 1').run(istDay());
}
function mailUsage() {
  return { sent_today: mailSentToday(), daily_cap: MAIL_DAILY_CAP || null,
           remaining: MAIL_DAILY_CAP ? Math.max(0, MAIL_DAILY_CAP - mailSentToday()) : null };
}

async function sendMail(to, subject, html) {
  const provider = mailProvider();
  if (!provider) throw new Error('Email service is not configured.');

  if (MAIL_DAILY_CAP && mailSentToday() >= MAIL_DAILY_CAP) {
    throw new Error('Daily email limit reached (' + MAIL_DAILY_CAP + ' for today). ' +
      'Raise or remove MAIL_DAILY_CAP in Render → Environment to send more.');
  }

  /* ---- SMTP (Google Workspace / Microsoft 365 / any mail host) ---- */
  if (provider === 'smtp') {
    try {
      const msg = { from: FROM_EMAIL, to, subject, html };
      if (REPLY_TO) msg.replyTo = REPLY_TO;
      await getSmtp().sendMail(msg);
      noteMailSent();
      return true;
    } catch (e) {
      const msg = String(e && e.message || e);
      let hint = '';
      if (/Invalid login|Username and Password not accepted|535|534/i.test(msg)) {
        hint = ' Check SMTP_USER and SMTP_PASS. For Gmail you must use a 16-character App Password ' +
               '(not your normal password), and 2-Step Verification has to be switched on for that account.';
      } else if (/ETIMEDOUT|ECONNREFUSED|ENOTFOUND|timeout/i.test(msg)) {
        hint = ' Could not reach ' + SMTP_HOST + ':' + SMTP_PORT + '. Try SMTP_PORT=587 if 465 is blocked.';
      } else if (/5\.7\.0|not allowed|Sender address rejected|553|554/i.test(msg)) {
        hint = ' The mail host would not accept this sender. FROM_EMAIL should normally be the same address as SMTP_USER.';
      }
      console.error('[mail] smtp ' + SMTP_HOST + ':' + SMTP_PORT + ' :: ' + msg.slice(0, 300));
      throw new Error('Mail server rejected the message.' + hint);
    }
  }

  let r, where;
  if (provider === 'mailgun') {
    where = MAILGUN_BASE + '/v3/' + MAILGUN_DOMAIN + '/messages';
    const form = new URLSearchParams();
    form.set('from', FROM_EMAIL);
    form.set('to', to);
    form.set('subject', subject);
    form.set('html', html);
    if (REPLY_TO) form.set('h:Reply-To', REPLY_TO);
    r = await fetch(where, {
      method: 'POST',
      headers: {
        /* Mailgun uses HTTP Basic auth with the literal username "api" */
        'Authorization': 'Basic ' + Buffer.from('api:' + MAILGUN_API_KEY).toString('base64'),
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: form.toString()
    });
  } else {
    where = RESEND_API_URL;
    r = await fetch(where, {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + RESEND_API_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify(Object.assign({ from: FROM_EMAIL, to: [to], subject, html },
        REPLY_TO ? { reply_to: REPLY_TO } : {}))
    });
  }

  if (!r.ok) {
    const body = await r.text().catch(() => '');
    /* translate the failures that actually happen in setup into plain English */
    let hint = '';
    if (r.status === 401) {
      hint = provider === 'mailgun'
        ? ' Check MAILGUN_API_KEY. If your Mailgun account is on the EU region, also set MAILGUN_REGION=eu.'
        : ' Check RESEND_API_KEY.';
    } else if (r.status === 404 && provider === 'mailgun') {
      hint = ' Mailgun does not recognise MAILGUN_DOMAIN (' + MAILGUN_DOMAIN + ') on this region.' +
             ' Confirm the domain in Mailgun and whether the account is US or EU.';
    } else if (r.status === 403) {
      hint = ' The sender address may not be authorised for this domain — check FROM_EMAIL.';
    }
    console.error('[mail] ' + provider + ' ' + r.status + ' ' + where + ' :: ' + body.slice(0, 300));
    throw new Error('Mail provider rejected the message (' + r.status + ').' + hint);
  }
  noteMailSent();
  return true;
}

/* ---------------- OTP master switch ----------------
   Set OTP_ENABLED=false in Render to sign in the old way, with no codes at all.
   Use that while getting email working, then switch it on. Nobody gets locked
   out in the meantime, and the admin Test Email button still works either way. */
const OTP_ENABLED = !/^(false|0|no|off)$/i.test(String(process.env.OTP_ENABLED || 'true').trim());

const isEmail = s => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(String(s || '').trim());
function makeOtp() {
  /* 6 digits, uniform, no modulo bias */
  return String(crypto.randomInt(0, 1000000)).padStart(6, '0');
}
const hashOtp = code => crypto.createHmac('sha256', SECRET).update('otp:' + code).digest('hex');
function otpMatches(code, stored) {
  try {
    return crypto.timingSafeEqual(Buffer.from(hashOtp(code), 'hex'), Buffer.from(stored, 'hex'));
  } catch (e) { return false; }
}
/* Email clients cannot render inline SVG, so the real logo is served as a PNG
   from the portal itself. Images are often blocked, so the alt text carries
   the name and the tagline stays as live text underneath. */
const PUBLIC_URL = (process.env.PUBLIC_URL || 'https://bidding.kgirdharlal.com').replace(/\/+$/, '');
const emailLogo = () =>
  `<img src="${PUBLIC_URL}/logo.png" width="210" alt="K.GIRDHARLAL" ` +
  `style="display:block;margin:0 auto;border:0;outline:none;text-decoration:none;height:auto;max-width:210px">`;

function otpEmailHtml(code, isNew) {
  return `<div style="margin:0;padding:28px 12px;background:#eef4f7;font-family:'Segoe UI',Arial,sans-serif">
<table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="max-width:520px;margin:0 auto;background:#fff;border:1px solid #dbe6ea;border-radius:14px">
<tr><td style="padding:26px 30px 6px;text-align:center;border-bottom:1px solid #eef4f6">
  ${emailLogo()}
  <div style="font-size:11px;letter-spacing:2.6px;color:#0a7488;margin:16px 0 18px">BIDDING PORTAL</div>
</td></tr>
<tr><td style="padding:26px 30px 8px;color:#1d2b35;font-size:15px;line-height:1.6">
  <p style="margin:0 0 14px">${isNew
    ? 'Use the code below to confirm your email address and finish creating your bidding account.'
    : 'Use the code below to confirm your email address and sign in.'}</p>
</td></tr>
<tr><td style="padding:4px 30px 10px;text-align:center">
  <div style="display:inline-block;background:#eef9fc;border:1px solid #b9dde8;border-radius:12px;padding:16px 30px">
    <div style="font-size:34px;letter-spacing:11px;font-weight:700;color:#075f72;font-family:Consolas,monospace">${code}</div>
  </div>
</td></tr>
<tr><td style="padding:12px 30px 26px;color:#5a6f7c;font-size:13px;line-height:1.65">
  <p style="margin:0 0 8px">This code expires in <b>10 minutes</b> and can be used once.</p>
  <p style="margin:0">If you didn't try to sign in, you can ignore this email — no account or bid has been created.</p>
</td></tr>
<tr><td style="padding:14px 30px;border-top:1px solid #eef4f6;color:#8a9aa4;font-size:11.5px;text-align:center">
  © ${new Date().getFullYear()} K.Girdharlal &amp; Co. · This is an automated message.
</td></tr>
</table></div>`;
}

/* ---------------- client auth ---------------- */
app.post('/api/client-login', async (req, res) => {
  let { name, company, contact, password } = req.body || {};
  name = (name || '').trim().slice(0, 120);
  company = (company || '').trim().slice(0, 160);
  contact = (contact || '').trim().toLowerCase().slice(0, 160);
  password = String(password || '');
  if (!name || !company || !contact) return res.status(400).json({ error: 'Name, company and email/mobile are all required.' });
  if (contact.length < 5) return res.status(400).json({ error: 'Please enter a valid email or mobile number.' });
  if (password.length > 200) return res.status(400).json({ error: 'Password is too long.' });
  if (password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters.' });

  const client = db.prepare('SELECT * FROM clients WHERE contact = ?').get(contact);

  /* ── OTP switched off: behave exactly as before codes existed ── */
  if (!OTP_ENABLED) {
    let c = client;
    if (!c) {
      const info = db.prepare('INSERT INTO clients (name, company, contact, created_at, password_hash, email_verified) VALUES (?,?,?,?,?,0)')
        .run(name, company, contact, Date.now(), hashPw(password));
      c = db.prepare('SELECT * FROM clients WHERE id = ?').get(Number(info.lastInsertRowid));
    } else if (!c.password_hash) {
      db.prepare('UPDATE clients SET name = ?, company = ?, password_hash = ? WHERE id = ?')
        .run(name, company, hashPw(password), c.id);
      c = db.prepare('SELECT * FROM clients WHERE id = ?').get(c.id);
    } else {
      if (!verifyPw(password, c.password_hash)) {
        return res.status(401).json({ error: 'Wrong password for this email. If you have forgotten it, contact K.Girdharlal to reset it.' });
      }
      db.prepare('UPDATE clients SET name = ?, company = ? WHERE id = ?').run(name, company, c.id);
      c = db.prepare('SELECT * FROM clients WHERE id = ?').get(c.id);
    }
    delete c.password_hash;
    setCookie(res, 'sid_c', makeToken('c', c.id));
    return res.json({ client: c });
  }

  /* ── already verified: straight in, password must match ── */
  if (client && client.email_verified) {
    if (!client.password_hash) {
      /* admin reset the password — adopt the one just entered */
      db.prepare('UPDATE clients SET name = ?, company = ?, password_hash = ? WHERE id = ?')
        .run(name, company, hashPw(password), client.id);
    } else {
      if (!verifyPw(password, client.password_hash)) {
        return res.status(401).json({ error: 'Wrong password for this email. If you have forgotten it, contact K.Girdharlal to reset it.' });
      }
      db.prepare('UPDATE clients SET name = ?, company = ? WHERE id = ?').run(name, company, client.id);
    }
    const fresh = db.prepare('SELECT * FROM clients WHERE id = ?').get(client.id);
    delete fresh.password_hash;
    setCookie(res, 'sid_c', makeToken('c', fresh.id));
    return res.json({ client: fresh });
  }

  /* ── not yet verified: an emailed code is required ── */
  if (!isEmail(contact)) {
    return res.status(400).json({
      error: 'Please sign in with an email address — we send a verification code to confirm it. ' +
             'If your account was set up with a mobile number, contact K.Girdharlal and we will verify it for you.'
    });
  }
  /* for an existing unverified account, check the password before sending anything */
  if (client && client.password_hash && !verifyPw(password, client.password_hash)) {
    return res.status(401).json({ error: 'Wrong password for this email. If you have forgotten it, contact K.Girdharlal to reset it.' });
  }
  if (!mailReady()) {
    return res.status(503).json({ error: 'Email verification is temporarily unavailable. Please contact K.Girdharlal.' });
  }

  const now = Date.now();
  const prev = db.prepare('SELECT * FROM otps WHERE contact = ?').get(contact);
  if (prev) {
    if (now - prev.last_sent_at < OTP_RESEND_WAIT) {
      const wait = Math.ceil((OTP_RESEND_WAIT - (now - prev.last_sent_at)) / 1000);
      return res.status(429).json({ error: 'A code was just sent. Please wait ' + wait + ' seconds before requesting another.', otp_required: true, contact });
    }
    if (now - prev.first_sent_at < OTP_SEND_WINDOW && prev.sent_count >= OTP_MAX_SENDS) {
      return res.status(429).json({ error: 'Too many codes requested for this email. Please try again in an hour, or contact K.Girdharlal.' });
    }
  }

  const code = makeOtp();
  const payload = JSON.stringify({ name, company, pw: hashPw(password) });
  const rolling = prev && (now - prev.first_sent_at < OTP_SEND_WINDOW);
  db.prepare(
    'INSERT INTO otps (contact, code_hash, expires_at, attempts, sent_count, first_sent_at, last_sent_at, payload) ' +
    'VALUES (?,?,?,0,?,?,?,?) ON CONFLICT(contact) DO UPDATE SET ' +
    'code_hash = excluded.code_hash, expires_at = excluded.expires_at, attempts = 0, ' +
    'sent_count = excluded.sent_count, first_sent_at = excluded.first_sent_at, ' +
    'last_sent_at = excluded.last_sent_at, payload = excluded.payload'
  ).run(contact, hashOtp(code), now + OTP_TTL_MS,
        rolling ? prev.sent_count + 1 : 1,
        rolling ? prev.first_sent_at : now, now, payload);

  /* Answer the browser straight away so the code-entry screen appears instantly,
     then hand the message to the mail server in the background. Waiting on SMTP
     added a two-to-three second stall on the password screen. */
  res.json({ otp_required: true, contact, is_new: !client, expires_in: Math.floor(OTP_TTL_MS / 1000) });

  sendMail(contact, 'Your K.Girdharlal verification code: ' + code, otpEmailHtml(code, !client))
    .catch(e => {
      /* Keep the row so "Send a new code" still works, and clear the 60s wait so
         the client can retry at once — the retry reports the real error. */
      db.prepare('UPDATE otps SET last_sent_at = 0 WHERE contact = ?').run(contact);
      console.error('[otp] send failed for ' + contact + ' :: ' + (e && e.message));
    });
});

/* ---------------- verify the emailed code ---------------- */
app.post('/api/verify-otp', (req, res) => {
  const contact = String((req.body || {}).contact || '').trim().toLowerCase().slice(0, 160);
  const code = String((req.body || {}).code || '').replace(/\D/g, '');
  if (!contact || code.length !== 6) return res.status(400).json({ error: 'Please enter the 6-digit code from your email.' });

  const row = db.prepare('SELECT * FROM otps WHERE contact = ?').get(contact);
  if (!row) return res.status(400).json({ error: 'That code has expired. Please request a new one.' });
  if (Date.now() > row.expires_at) {
    db.prepare('DELETE FROM otps WHERE contact = ?').run(contact);
    return res.status(400).json({ error: 'That code has expired. Please request a new one.' });
  }
  if (row.attempts >= OTP_MAX_TRIES) {
    db.prepare('DELETE FROM otps WHERE contact = ?').run(contact);
    return res.status(429).json({ error: 'Too many incorrect attempts. Please request a new code.' });
  }
  if (!otpMatches(code, row.code_hash)) {
    const used = row.attempts + 1;
    const left = OTP_MAX_TRIES - used;
    if (left <= 0) {
      /* burn the code immediately rather than leaving a dead row behind */
      db.prepare('DELETE FROM otps WHERE contact = ?').run(contact);
      return res.status(429).json({ error: 'Too many incorrect attempts. Please request a new code.' });
    }
    db.prepare('UPDATE otps SET attempts = ? WHERE contact = ?').run(used, contact);
    return res.status(401).json({
      error: 'That code is not correct. ' + left + ' attempt' + (left === 1 ? '' : 's') + ' remaining.'
    });
  }

  let p = {};
  try { p = JSON.parse(row.payload || '{}'); } catch (e) { p = {}; }
  let client = db.prepare('SELECT * FROM clients WHERE contact = ?').get(contact);
  if (!client) {
    /* the account is created only now, once the address is proven */
    const info = db.prepare(
      'INSERT INTO clients (name, company, contact, created_at, password_hash, email_verified) VALUES (?,?,?,?,?,1)'
    ).run(p.name || '', p.company || '', contact, Date.now(), p.pw || null);
    client = db.prepare('SELECT * FROM clients WHERE id = ?').get(Number(info.lastInsertRowid));
  } else {
    db.prepare('UPDATE clients SET name = ?, company = ?, password_hash = COALESCE(?, password_hash), email_verified = 1 WHERE id = ?')
      .run(p.name || client.name, p.company || client.company, p.pw || null, client.id);
    client = db.prepare('SELECT * FROM clients WHERE id = ?').get(client.id);
  }
  db.prepare('DELETE FROM otps WHERE contact = ?').run(contact);
  delete client.password_hash;
  setCookie(res, 'sid_c', makeToken('c', client.id));
  res.json({ client });
});

/* ---------------- send a fresh code ---------------- */
app.post('/api/resend-otp', async (req, res) => {
  const contact = String((req.body || {}).contact || '').trim().toLowerCase().slice(0, 160);
  if (!isEmail(contact)) return res.status(400).json({ error: 'Please enter a valid email address.' });
  const row = db.prepare('SELECT * FROM otps WHERE contact = ?').get(contact);
  if (!row) return res.status(400).json({ error: 'Please start again from the sign-in form.' });
  if (!mailReady()) return res.status(503).json({ error: 'Email verification is temporarily unavailable. Please contact K.Girdharlal.' });

  const now = Date.now();
  if (now - row.last_sent_at < OTP_RESEND_WAIT) {
    const wait = Math.ceil((OTP_RESEND_WAIT - (now - row.last_sent_at)) / 1000);
    return res.status(429).json({ error: 'Please wait ' + wait + ' more second' + (wait === 1 ? '' : 's') + ' before requesting another code.' });
  }
  const rolling = now - row.first_sent_at < OTP_SEND_WINDOW;
  if (rolling && row.sent_count >= OTP_MAX_SENDS) {
    return res.status(429).json({ error: 'Too many codes requested for this email. Please try again in an hour, or contact K.Girdharlal.' });
  }
  const code = makeOtp();
  db.prepare('UPDATE otps SET code_hash = ?, expires_at = ?, attempts = 0, sent_count = ?, first_sent_at = ?, last_sent_at = ? WHERE contact = ?')
    .run(hashOtp(code), now + OTP_TTL_MS, rolling ? row.sent_count + 1 : 1, rolling ? row.first_sent_at : now, now, contact);
  const exists = db.prepare('SELECT id FROM clients WHERE contact = ?').get(contact);
  try {
    await sendMail(contact, 'Your K.Girdharlal verification code: ' + code, otpEmailHtml(code, !exists));
  } catch (e) {
    return res.status(502).json({ error: 'We could not send the verification email. Please try again shortly.' });
  }
  res.json({ ok: true, expires_in: Math.floor(OTP_TTL_MS / 1000) });
});

app.get('/api/me', (req, res) => {
  const s = getSession(req);
  /* otp_enabled must be present even with no session — the login page reads it */
  if (!s) return res.json({ client: null, admin: false, otp_enabled: OTP_ENABLED });
  const client = s.client_id ? db.prepare('SELECT * FROM clients WHERE id = ?').get(s.client_id) : null;
  if (client) delete client.password_hash; /* never send the stored hash to the browser */
  res.json({ client: client || null, admin: !!s.is_admin, otp_enabled: OTP_ENABLED });
});

app.post('/api/logout', (req, res) => {
  const kind = (req.body || {}).kind;
  if (kind !== 'a') res.append('Set-Cookie', 'sid_c=; Path=/; Max-Age=0');
  if (kind !== 'c') res.append('Set-Cookie', 'sid_a=; Path=/; Max-Age=0');
  res.append('Set-Cookie', 'sid=; Path=/; Max-Age=0');
  res.json({ ok: true });
});

/* ---------------- client: event + stones + bids ---------------- */
function activeEvent() {
  return db.prepare("SELECT * FROM events WHERE status = 'live' ORDER BY created_at DESC LIMIT 1").get() || null;
}
function eventIsOpen(ev) {
  return ev && ev.status === 'live' && Date.now() < ev.end_time;
}

app.get('/api/event', (req, res) => {
  res.json({ event: activeEvent() || null, server_time: Date.now() });
});

app.get('/api/stones', requireClient, (req, res) => {
  const ev = activeEvent();
  if (!ev) return res.json({ event: null, stones: [], server_time: Date.now() });
  const stones = db.prepare('SELECT * FROM stones WHERE event_id = ? ORDER BY cts DESC').all(ev.id);
  res.json({ event: ev, stones, server_time: Date.now() });
});

app.get('/api/my-bids', requireClient, (req, res) => {
  const ev = activeEvent();
  if (!ev) return res.json({ bids: [] });
  const bids = db.prepare('SELECT * FROM bids WHERE event_id = ? AND client_id = ?').all(ev.id, req.client.id);
  res.json({ bids });
});

app.post('/api/bids', requireClient, (req, res) => {
  const ev = activeEvent();
  if (!eventIsOpen(ev)) return res.status(400).json({ error: 'Bidding is closed.' });
  const items = Array.isArray(req.body.bids) ? req.body.bids : [];
  if (!items.length) return res.status(400).json({ error: 'No bids submitted.' });
  const getStone = db.prepare('SELECT * FROM stones WHERE id = ? AND event_id = ?');
  const upsert = db.prepare(
    'INSERT INTO bids (event_id, stone_pk, client_id, bid_disc, bid_per_ct, bid_amount, created_at, updated_at) ' +
    'VALUES (?,?,?,?,?,?,?,?) ' +
    'ON CONFLICT(stone_pk, client_id) DO UPDATE SET ' +
    'bid_disc = excluded.bid_disc, bid_per_ct = excluded.bid_per_ct, ' +
    'bid_amount = excluded.bid_amount, updated_at = excluded.updated_at'
  );
  let saved = 0;
  const tx = db.transaction(() => {
    for (const it of items) {
      const stone = getStone.get(Number(it.stone_pk), ev.id);
      if (!stone) throw new Error('Invalid stone in bid.');
      const perCt = Number(it.bid_per_ct);
      if (!isFinite(perCt) || perCt <= 0) throw new Error('Invalid bid price for stone ' + stone.stone_id + '.');
      const amount = round2(perCt * stone.cts);
      let disc = null;
      if (stone.rap && stone.rap > 0) disc = round2((1 - perCt / stone.rap) * 100);
      /* Bids must be on the expensive side: discount no higher than the ask discount.
         Enforced here as well as in the browser so it cannot be bypassed. */
      if (stone.disc != null && disc != null && disc > stone.disc + 0.001) {
        throw new Error('Bid on ' + stone.stone_id + ' is at ' + disc.toFixed(2) +
          '% discount, which is below the asking price. Maximum allowed discount is ' +
          Number(stone.disc).toFixed(2) + '%.');
      }
      /* Sanity ceiling — catches a mistyped extra digit. Twice the Rap rate is far
         above any realistic bid, so anything beyond it is a typo, not an offer. */
      if (stone.rap && stone.rap > 0 && perCt > stone.rap * 2) {
        throw new Error('Bid of $' + round2(perCt).toLocaleString('en-US') + '/ct on ' +
          stone.stone_id + ' looks like a typo — it is more than double the Rap rate of $' +
          Number(stone.rap).toLocaleString('en-US') + '/ct. Please check the figure.');
      }
      const now = Date.now();
      upsert.run(ev.id, stone.id, req.client.id, disc, round2(perCt), amount, now, now);
      saved++;
    }
  });
  try { tx(); } catch (e) { return res.status(400).json({ error: e.message }); }
  res.json({ ok: true, saved });
});

app.delete('/api/bids/:stonePk', requireClient, (req, res) => {
  const ev = activeEvent();
  if (!eventIsOpen(ev)) return res.status(400).json({ error: 'Bidding is closed.' });
  db.prepare('DELETE FROM bids WHERE event_id = ? AND stone_pk = ? AND client_id = ?')
    .run(ev.id, Number(req.params.stonePk), req.client.id);
  res.json({ ok: true });
});

/* ---------------- admin ---------------- */
app.post('/api/admin/login', (req, res) => {
  if (((req.body || {}).password || '') !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Wrong password.' });
  setCookie(res, 'sid_a', makeToken('a'));
  res.json({ ok: true });
});

/* Parse an uploaded stocklist xlsx into stone rows */
function parseStocklist(buffer) {
  const wb = XLSX.read(buffer, { type: 'buffer', cellDates: false });
  const ws = wb.Sheets[wb.SheetNames[0]];
  if (!ws || !ws['!ref']) throw new Error('The Excel file appears to be empty.');
  const range = XLSX.utils.decode_range(ws['!ref']);
  const headers = [];
  for (let c = range.s.c; c <= range.e.c; c++) {
    const cell = ws[XLSX.utils.encode_cell({ r: range.s.r, c })];
    headers.push(cell ? String(cell.v).trim() : '');
  }
  const norm = h => String(h).toUpperCase().replace(/[^A-Z0-9%/$.]/g, '');
  const H = headers.map(norm);
  const col = (...names) => {
    for (const n of names) {
      const i = H.indexOf(norm(n));
      if (i !== -1) return i;
    }
    return -1;
  };
  const idx = {
    stoneId: col('STONE ID', 'STONEID', 'STONE NO', 'SERIAL NO', 'PACKET NO'),
    loc: col('LOC.', 'LOC', 'LOCATION'),
    shape: col('SHAPE'),
    cts: col('CTS', 'CARAT', 'CARATS', 'WEIGHT'),
    color: col('COLOR', 'COL'),
    clarity: col('CLARITY', 'CLA', 'PURITY'),
    cut: col('CUT'),
    pol: col('POL', 'POLISH'),
    symm: col('SYMM', 'SYM', 'SYMMETRY'),
    fluor: col('FLUOR', 'FLO', 'FLUORESCENCE', 'FLR'),
    depth: col('DEPTH %', 'DEPTH%', 'DEPTH'),
    table: col('TABLE %', 'TABLE%', 'TABLE'),
    length: col('LENGTH'), width: col('WIDTH'), height: col('HEIGHT'),
    ratio: col('L/W RATIO', 'RATIO'),
    disc: col('DISC', 'DISC%', 'DISCOUNT'),
    priceCt: col('PRICE($/ct)', 'PRICE($/CT)', '$/CT', 'PRICE/CT', 'PRICE'),
    amount: col('AMT($)', 'AMT', 'AMOUNT', 'TOTAL'),
    rap: col('RAP', 'RAP RATE', 'RAPRATE'),
    lab: col('LAB'),
    reportNo: col('REPORT NO.', 'REPORT NO', 'CERT NO', 'CERTIFICATE NO'),
    video: col('VIDEO', 'VIDEO LINK', 'VIDEO URL')
  };
  if (idx.stoneId === -1) throw new Error('Could not find a "STONE ID" column in the file.');
  if (idx.cts === -1) throw new Error('Could not find a "CTS" (carats) column in the file.');

  const stones = [];
  for (let r = range.s.r + 1; r <= range.e.r; r++) {
    const cellAt = c => (c === -1 ? undefined : ws[XLSX.utils.encode_cell({ r, c })]);
    const val = c => { const cell = cellAt(c); return cell ? cell.v : null; };
    const num = c => { const v = val(c); const n = Number(v); return (v === null || v === '' || !isFinite(n)) ? null : n; };
    const str = c => { const v = val(c); return v == null ? '' : String(v).trim(); };
    const link = c => { const cell = cellAt(c); return cell && cell.l && cell.l.Target ? String(cell.l.Target) : ''; };

    const stoneId = str(idx.stoneId);
    if (!stoneId) continue;
    const cts = num(idx.cts);
    if (!cts) continue;

    const L = num(idx.length), W = num(idx.width), Ht = num(idx.height);
    const meas = (L && W && Ht) ? (L + '*' + W + '*' + Ht) : '';

    /* Keep every column from the source file, in its original order, so the
       client download can reproduce the stocklist format exactly. 'NONE' is a
       real grading value and is preserved; only truly blank cells are skipped. */
    const details = {};
    for (let c = range.s.c; c <= range.e.c; c++) {
      const h = headers[c - range.s.c];
      if (!h) continue;
      const cell = ws[XLSX.utils.encode_cell({ r, c })];
      const v = cell ? cell.v : null;
      if (v !== null && v !== undefined && String(v).trim() !== '') {
        details[h] = v;
      }
    }

    stones.push({
      stone_id: stoneId,
      location: str(idx.loc), shape: str(idx.shape), cts,
      color: str(idx.color), clarity: str(idx.clarity),
      cut: str(idx.cut), pol: str(idx.pol), symm: str(idx.symm), fluor: str(idx.fluor),
      depth_pct: num(idx.depth), table_pct: num(idx.table),
      measurements: meas, ratio: num(idx.ratio),
      disc: num(idx.disc), price_ct: num(idx.priceCt), amount: num(idx.amount), rap: num(idx.rap),
      lab: str(idx.lab), report_no: str(idx.reportNo),
      product_url: link(idx.stoneId),
      cert_url: link(idx.reportNo),
      video_url: str(idx.video) || link(idx.video),
      details_json: JSON.stringify(details)
    });
  }
  if (!stones.length) throw new Error('No valid stone rows found in the file.');

  /* A repeated STONE ID would otherwise fail deep in the insert with a raw
     "UNIQUE constraint failed" message. Catch it here and say which ones. */
  const seenIds = new Map();
  const dupes = [];
  stones.forEach((s, i) => {
    const key = s.stone_id.toUpperCase();
    if (seenIds.has(key)) dupes.push(s.stone_id + ' (rows ' + (seenIds.get(key) + 2) + ' and ' + (i + 2) + ')');
    else seenIds.set(key, i);
  });
  if (dupes.length) {
    throw new Error('This file lists the same STONE ID more than once: ' +
      dupes.slice(0, 5).join('; ') +
      (dupes.length > 5 ? ' …and ' + (dupes.length - 5) + ' more' : '') +
      '. Please remove the duplicate rows and upload again.');
  }

  /* keep the source column order so downloads can reproduce the exact format,
     including columns that happen to be empty for every row */
  stones.sourceHeaders = headers.filter(h => h && String(h).trim() !== '');
  return stones;
}

app.post('/api/admin/events', requireAdmin, upload.single('file'), (req, res) => {
  try {
    const name = (req.body.name || '').trim();
    const terms = (req.body.terms || '').trim();
    const endTime = Number(req.body.end_time);
    if (!name) return res.status(400).json({ error: 'Event name is required.' });
    if (!isFinite(endTime) || endTime <= Date.now()) return res.status(400).json({ error: 'End time must be in the future.' });
    if (!req.file) return res.status(400).json({ error: 'Please attach the stocklist Excel file.' });

    const stones = parseStocklist(req.file.buffer);
    const ins = db.prepare(
      'INSERT INTO stones (event_id, stone_id, location, shape, cts, color, clarity, cut, pol, symm, fluor, ' +
      'depth_pct, table_pct, measurements, ratio, disc, price_ct, amount, rap, lab, report_no, ' +
      'product_url, cert_url, video_url, details_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
    );
    const tx = db.transaction(() => {
      db.exec("UPDATE events SET status = 'closed' WHERE status = 'live'");
      const info = db.prepare("INSERT INTO events (name, terms, end_time, status, created_at, headers_json) VALUES (?,?,?,'live',?,?)")
        .run(name, terms, endTime, Date.now(), JSON.stringify(stones.sourceHeaders || []));
      const evId = Number(info.lastInsertRowid);
      for (const s of stones) {
        ins.run(evId, s.stone_id, s.location, s.shape, s.cts, s.color, s.clarity, s.cut, s.pol, s.symm, s.fluor,
          s.depth_pct, s.table_pct, s.measurements, s.ratio, s.disc, s.price_ct, s.amount, s.rap, s.lab, s.report_no,
          s.product_url, s.cert_url, s.video_url, s.details_json);
      }
      return evId;
    });
    const evId = tx();
    res.json({ ok: true, event_id: evId, stones: stones.length });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.get('/api/admin/events', requireAdmin, (req, res) => {
  const events = db.prepare(
    'SELECT e.*, ' +
    '(SELECT COUNT(*) FROM stones s WHERE s.event_id = e.id) AS stone_count, ' +
    '(SELECT COUNT(*) FROM bids b WHERE b.event_id = e.id) AS bid_count, ' +
    '(SELECT COUNT(DISTINCT b.client_id) FROM bids b WHERE b.event_id = e.id) AS bidder_count ' +
    'FROM events e ORDER BY e.created_at DESC').all();
  res.json({ events, server_time: Date.now() });
});

app.patch('/api/admin/events/:id', requireAdmin, (req, res) => {
  const ev = db.prepare('SELECT * FROM events WHERE id = ?').get(Number(req.params.id));
  if (!ev) return res.status(404).json({ error: 'Event not found.' });
  if (req.body.status && ['live', 'closed'].includes(req.body.status)) {
    db.prepare('UPDATE events SET status = ? WHERE id = ?').run(req.body.status, ev.id);
    if (req.body.status === 'live') {
      db.prepare("UPDATE events SET status = 'closed' WHERE status = 'live' AND id != ?").run(ev.id);
    }
  }
  if (req.body.end_time) {
    const t = Number(req.body.end_time);
    if (isFinite(t)) db.prepare('UPDATE events SET end_time = ? WHERE id = ?').run(t, ev.id);
  }
  res.json({ ok: true });
});

app.get('/api/admin/events/:id/summary', requireAdmin, (req, res) => {
  const ev = db.prepare('SELECT * FROM events WHERE id = ?').get(Number(req.params.id));
  if (!ev) return res.status(404).json({ error: 'Event not found.' });
  const clients = db.prepare(
    'SELECT c.id, c.name, c.company, c.contact, COUNT(b.id) AS bid_count, ' +
    'ROUND(SUM(b.bid_amount), 2) AS total_amount, MAX(b.updated_at) AS last_bid_at ' +
    'FROM bids b JOIN clients c ON c.id = b.client_id WHERE b.event_id = ? ' +
    'GROUP BY c.id ORDER BY total_amount DESC').all(ev.id);
  res.json({ event: ev, clients, server_time: Date.now() });
});

app.get('/api/admin/events/:id/clients/:clientId/bids', requireAdmin, (req, res) => {
  const bids = db.prepare(
    'SELECT b.*, s.stone_id, s.shape, s.cts, s.color, s.clarity, s.cut, s.pol, s.symm, s.fluor, ' +
    's.rap, s.disc AS ask_disc, s.price_ct AS ask_per_ct, s.amount AS ask_amount, s.lab, s.report_no ' +
    'FROM bids b JOIN stones s ON s.id = b.stone_pk ' +
    'WHERE b.event_id = ? AND b.client_id = ? ORDER BY s.cts DESC')
    .all(Number(req.params.id), Number(req.params.clientId));
  const client = db.prepare('SELECT * FROM clients WHERE id = ?').get(Number(req.params.clientId));
  if (client) delete client.password_hash;
  res.json({ client, bids });
});

app.get('/api/admin/clients', requireAdmin, (req, res) => {
  const clients = db.prepare(
    'SELECT c.id, c.name, c.company, c.contact, c.created_at, ' +
    'CASE WHEN c.password_hash IS NULL THEN 0 ELSE 1 END AS has_password, ' +
    'COALESCE(c.email_verified, 0) AS email_verified, ' +
    '(SELECT COUNT(*) FROM bids b WHERE b.client_id = c.id) AS total_bids ' +
    'FROM clients c ORDER BY c.created_at DESC').all();
  res.json({ clients });
});

/* ---------------- admin: bids bifurcated company-wise ---------------- */
app.get('/api/admin/events/:id/export-by-company', requireAdmin, async (req, res) => {
  const ev = db.prepare('SELECT * FROM events WHERE id = ?').get(Number(req.params.id));
  if (!ev) return res.status(404).json({ error: 'Event not found.' });

  const rows = db.prepare(
    'SELECT b.bid_disc, b.bid_per_ct, b.bid_amount, b.updated_at, ' +
    'c.company, c.name AS person, c.contact, ' +
    's.details_json, s.stone_id, s.cts, s.disc AS ask_disc, s.price_ct AS ask_ct, s.rap ' +
    'FROM bids b JOIN clients c ON c.id = b.client_id JOIN stones s ON s.id = b.stone_pk ' +
    'WHERE b.event_id = ? ORDER BY c.company COLLATE NOCASE, s.cts DESC').all(ev.id);

  /* group by company name (case/space-insensitive), merging multiple contacts */
  const groups = new Map();
  for (const r of rows) {
    const key = String(r.company || 'Unknown').trim().toLowerCase().replace(/\s+/g, ' ');
    if (!groups.has(key)) groups.set(key, { company: String(r.company || 'Unknown').trim(), rows: [], people: new Map() });
    const g = groups.get(key);
    g.rows.push(r);
    if (!g.people.has(r.contact)) g.people.set(r.contact, r.person);
  }

  const base = stocklistHeaders(ev.id);
  const headers = base.concat(['BID DISC%', 'BID $/CT', 'BID AMOUNT $', 'BID PLACED / UPDATED', 'BIDDER', 'BIDDER CONTACT']);
  const wb = new ExcelJS.Workbook();
  wb.creator = 'K.Girdharlal Bidding Portal';

  /* ---- sheet 1: summary ---- */
  const sum = wb.addWorksheet('Summary');
  const sumHead = ['COMPANY', 'CONTACT PERSON(S)', 'EMAIL / MOBILE', 'STONES BID', 'TOTAL CTS', 'TOTAL BID AMOUNT $', 'AVG BID $/CT', 'LAST ACTIVITY'];
  sum.columns = [{ width: 34 }, { width: 26 }, { width: 34 }, { width: 12 }, { width: 11 }, { width: 20 }, { width: 14 }, { width: 22 }];
  sum.addRow(sumHead);

  const ordered = [...groups.values()].sort((a, b) =>
    b.rows.reduce((s, r) => s + r.bid_amount, 0) - a.rows.reduce((s, r) => s + r.bid_amount, 0));

  let grandAmt = 0, grandStones = 0;
  for (const g of ordered) {
    const amt = g.rows.reduce((s, r) => s + r.bid_amount, 0);
    const cts = g.rows.reduce((s, r) => s + (r.cts || 0), 0);
    const last = Math.max(...g.rows.map(r => r.updated_at));
    grandAmt += amt; grandStones += g.rows.length;
    sum.addRow([
      g.company, [...g.people.values()].join(', '), [...g.people.keys()].join(', '),
      g.rows.length, round2(cts), round2(amt), cts ? round2(amt / cts) : '',
      new Date(last).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })
    ]);
  }
  const gt = sum.addRow(['GRAND TOTAL', '', '', grandStones, '', round2(grandAmt), '', '']);
  gt.font = { bold: true };
  gt.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFE6F6FA' } };
  styleHeader(sum, sumHead.length);
  sum.getRow(1).getCell(6).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF188A52' } };
  sum.spliceRows(1, 0, ['Bids by Company — ' + ev.name]);
  sum.getRow(1).font = { bold: true, size: 13 };
  sum.mergeCells(1, 1, 1, sumHead.length);

  /* ---- one sheet per company ---- */
  const used = new Set(['Summary']);
  for (const g of ordered) {
    let nm = (g.company || 'Unknown').replace(/[\\\/\?\*\[\]:]/g, ' ').trim().slice(0, 28) || 'Company';
    let base2 = nm, k = 2;
    while (used.has(nm)) { nm = (base2.slice(0, 25) + ' ' + k++).trim(); }
    used.add(nm);

    const ws = wb.addWorksheet(nm);
    sizeCols(ws, headers);
    ws.addRow(headers);
    let amt = 0, cts = 0;
    for (const r of g.rows) {
      let d = {};
      try { d = JSON.parse(r.details_json || '{}'); } catch (e) { d = {}; }
      const line = base.map(h => clean(d[h]));
      line.push(
        r.bid_disc == null ? '' : round2(r.bid_disc),
        round2(r.bid_per_ct),
        round2(r.bid_amount),
        new Date(r.updated_at).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
        r.person, r.contact
      );
      ws.addRow(line);
      amt += r.bid_amount; cts += r.cts || 0;
    }
    const tRow = new Array(headers.length).fill('');
    tRow[0] = 'TOTAL — ' + g.rows.length + ' stone' + (g.rows.length === 1 ? '' : 's');
    const ci = base.indexOf('CTS');
    if (ci !== -1) tRow[ci] = round2(cts);
    tRow[headers.length - 4] = round2(amt);
    const tr = ws.addRow(tRow);
    tr.font = { bold: true };
    tr.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFE6F6FA' } };
    styleHeader(ws, headers.length);
  }

  if (!ordered.length) {
    const ws = wb.addWorksheet('No Bids');
    ws.addRow(['No bids have been placed for this event yet.']);
  }

  const fname = 'BidsByCompany_' + ev.name.replace(/[^a-zA-Z0-9-_]/g, '_') + '_' + new Date().toISOString().slice(0, 10) + '.xlsx';
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition', 'attachment; filename="' + fname + '"');
  await wb.xlsx.write(res);
  res.end();
});

/* ---------------- admin: full database backup ---------------- */
app.get('/api/admin/backup', requireAdmin, (req, res) => {
  const tmp = path.join(DATA_DIR, 'backup-tmp-' + Date.now() + '.db');
  try {
    db.exec("VACUUM INTO '" + tmp.replace(/'/g, "''") + "'");
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', 'attachment; filename="kg-bidding-backup-' + new Date().toISOString().slice(0, 10) + '.db"');
    const stream = fs.createReadStream(tmp);
    stream.pipe(res);
    stream.on('close', () => fs.unlink(tmp, () => {}));
    stream.on('error', () => { fs.unlink(tmp, () => {}); res.end(); });
  } catch (e) {
    fs.unlink(tmp, () => {});
    res.status(500).json({ error: e.message });
  }
});

/* ---------------- admin: reset a client's password ---------------- */
app.post('/api/admin/clients/:id/reset-password', requireAdmin, (req, res) => {
  db.prepare('UPDATE clients SET password_hash = NULL WHERE id = ?').run(Number(req.params.id));
  res.json({ ok: true });
});

/* ---------------- admin: check the email setup ----------------
   Sends a real test message and reports exactly what the provider said,
   so mail configuration can be diagnosed without reading server logs. */
app.post('/api/admin/test-email', requireAdmin, async (req, res) => {
  const to = String((req.body || {}).to || '').trim();
  const provider = mailProvider();
  const cfg = {
    provider: provider || 'none',
    otp_enabled: OTP_ENABLED,
    from: FROM_EMAIL,
    reply_to: REPLY_TO || null,
    smtp_user: provider === 'smtp' ? SMTP_USER : null,
    mailgun_domain: provider === 'mailgun' ? MAILGUN_DOMAIN : null,
    mailgun_region: provider === 'mailgun' ? (MAILGUN_REGION === 'eu' ? 'eu' : 'us') : null,
    endpoint: provider === 'smtp' ? SMTP_HOST + ':' + SMTP_PORT
            : provider === 'mailgun' ? MAILGUN_BASE + '/v3/' + MAILGUN_DOMAIN + '/messages'
            : provider === 'resend' ? RESEND_API_URL : null,
    usage: mailUsage()
  };
  /* The usual trap: sending as an address the mail host does not own.
     Gmail silently rewrites it, so the test can "pass" yet arrive from the wrong address. */
  if (provider === 'smtp' && SMTP_USER && bareAddr(FROM_EMAIL) !== SMTP_USER.trim().toLowerCase()) {
    cfg.warning = 'FROM_EMAIL (' + bareAddr(FROM_EMAIL) + ') is not the account being signed into (' +
      SMTP_USER + '). This only works if that address is a verified alias or "Send mail as" identity ' +
      'on the account — otherwise the mail host may reject it, or quietly replace it with ' + SMTP_USER +
      '. Check what address the test message actually arrives from.';
  }
  if (!provider) {
    return res.status(400).json({
      ok: false, config: cfg,
      error: 'No email provider is configured. Add SMTP_USER + SMTP_PASS (or MAILGUN_API_KEY + MAILGUN_DOMAIN, or RESEND_API_KEY) in Render → Environment.'
    });
  }
  if (!isEmail(to)) return res.status(400).json({ ok: false, config: cfg, error: 'Enter a valid email address to send the test to.' });
  try {
    await sendMail(to, 'K.Girdharlal portal — email test',
      '<div style="font-family:Segoe UI,Arial,sans-serif;font-size:15px;color:#1d2b35">' +
      '<p>This is a test message from your bidding portal.</p>' +
      '<p>If you are reading this, verification codes will reach your clients correctly.</p>' +
      '<p style="color:#5a6f7c;font-size:13px">Sent via ' + provider + ' · from ' + FROM_EMAIL + '</p></div>');
    cfg.usage = mailUsage();
    res.json({ ok: true, config: cfg, message: 'Test email accepted by ' + provider + '. Check the inbox for ' + to + '.' });
  } catch (e) {
    res.status(502).json({ ok: false, config: cfg, error: e.message });
  }
});

/* ---------------- admin: verification override ----------------
   Needed for clients whose account uses a mobile number and who therefore
   cannot receive an email code, and for anyone stuck on delivery problems. */
app.post('/api/admin/clients/:id/set-verified', requireAdmin, (req, res) => {
  const v = (req.body || {}).verified ? 1 : 0;
  const c = db.prepare('SELECT id, contact FROM clients WHERE id = ?').get(Number(req.params.id));
  if (!c) return res.status(404).json({ error: 'Client not found.' });
  db.prepare('UPDATE clients SET email_verified = ? WHERE id = ?').run(v, c.id);
  if (!v) db.prepare('DELETE FROM otps WHERE contact = ?').run(c.contact);
  res.json({ ok: true, verified: v });
});

/* ---------------- admin: stones with no bids ---------------- */
app.get('/api/admin/events/:id/nobids', requireAdmin, (req, res) => {
  const exists = db.prepare('SELECT id FROM events WHERE id = ?').get(Number(req.params.id));
  if (!exists) return res.status(404).json({ error: 'Event not found.' });
  const stones = db.prepare(
    'SELECT s.* FROM stones s WHERE s.event_id = ? AND NOT EXISTS ' +
    '(SELECT 1 FROM bids b WHERE b.stone_pk = s.id) ORDER BY s.cts DESC').all(Number(req.params.id));
  res.json({ stones });
});

/* ---------------- admin: email each bidder their bid summary ---------------- */
function bidEmailHtml(clientName, evName, terms, rows, total) {
  const fmtN = n => n == null ? '-' : Number(n).toLocaleString('en-US', { maximumFractionDigits: 2 });
  const tr = rows.map(r =>
    '<tr>' +
    '<td style="padding:8px 10px;border-bottom:1px solid #e3eaee;font-weight:600">' + r.stone_id + '</td>' +
    '<td style="padding:8px 10px;border-bottom:1px solid #e3eaee">' + (r.shape || '') + ' ' + fmtN(r.cts) + 'ct ' + (r.color || '') + ' ' + (r.clarity || '') + '</td>' +
    '<td style="padding:8px 10px;border-bottom:1px solid #e3eaee;text-align:right">' + (r.bid_disc == null ? '-' : fmtN(r.bid_disc) + '%') + '</td>' +
    '<td style="padding:8px 10px;border-bottom:1px solid #e3eaee;text-align:right">$' + fmtN(r.bid_per_ct) + '</td>' +
    '<td style="padding:8px 10px;border-bottom:1px solid #e3eaee;text-align:right;font-weight:700">$' + fmtN(r.bid_amount) + '</td>' +
    '</tr>').join('');
  return '<div style="font-family:Segoe UI,Arial,sans-serif;max-width:640px;margin:0 auto;color:#1b2437">' +
    '<div style="background:#fff;border:1px solid #dbe6ea;border-bottom:none;padding:24px;border-radius:12px 12px 0 0;text-align:center">' +
    emailLogo() +
    '<div style="font-size:11px;letter-spacing:2.6px;color:#0a7488;margin-top:14px">BIDDING PORTAL</div></div>' +
    '<div style="height:2px;background:#10A6C2"></div>' +
    '<div style="border:1px solid #e3eaee;border-top:none;padding:24px;border-radius:0 0 12px 12px">' +
    '<p>Dear ' + clientName + ',</p>' +
    '<p>Thank you for participating in <b>' + evName + '</b>. Below is a summary of the bids you placed:</p>' +
    '<table style="border-collapse:collapse;width:100%;font-size:13px">' +
    '<tr style="background:#E6F6FA;color:#0b7d95"><th style="padding:8px 10px;text-align:left">Stone ID</th><th style="padding:8px 10px;text-align:left">Details</th><th style="padding:8px 10px;text-align:right">Bid Disc%</th><th style="padding:8px 10px;text-align:right">Bid $/Ct</th><th style="padding:8px 10px;text-align:right">Amount</th></tr>' +
    tr +
    '<tr><td colspan="4" style="padding:10px;text-align:right;font-weight:700">TOTAL</td><td style="padding:10px;text-align:right;font-weight:700;color:#10A6C2">$' + fmtN(total) + '</td></tr>' +
    '</table>' +
    (terms ? '<p style="font-size:12px;color:#66788a">Terms: ' + terms + '</p>' : '') +
    '<p style="font-size:12px;color:#66788a">All bids are firm and binding as per the bidding terms accepted on the portal. K.Girdharlal reserves the right to accept or reject any bid at its sole discretion. This is an automated summary; please do not reply to this email.</p>' +
    '</div></div>';
}
app.post('/api/admin/events/:id/email-bids', requireAdmin, async (req, res) => {
  if (!mailReady()) return res.status(400).json({ error: 'Email service is not configured yet. Add SMTP_USER + SMTP_PASS (or Mailgun / Resend keys) in Render → Environment, then use the Test Email button.' });
  const ev = db.prepare('SELECT * FROM events WHERE id = ?').get(Number(req.params.id));
  if (!ev) return res.status(404).json({ error: 'Event not found.' });
  const clients = db.prepare(
    'SELECT DISTINCT c.* FROM bids b JOIN clients c ON c.id = b.client_id WHERE b.event_id = ?').all(ev.id);
  const perClient = db.prepare(
    'SELECT b.*, s.stone_id, s.shape, s.cts, s.color, s.clarity FROM bids b JOIN stones s ON s.id = b.stone_pk ' +
    'WHERE b.event_id = ? AND b.client_id = ? ORDER BY s.cts DESC');
  let sent = 0, skipped = 0, failed = 0, lastError = '';
  for (const c of clients) {
    if (!c.contact || c.contact.indexOf('@') === -1) { skipped++; continue; }
    const rows = perClient.all(ev.id, c.id);
    const total = rows.reduce((a, r) => a + r.bid_amount, 0);
    try {
      await sendMail(c.contact,
        'Your bid summary - ' + ev.name + ' | K.Girdharlal',
        bidEmailHtml(c.name, ev.name, ev.terms, rows, round2(total)));
      sent++;
    } catch (e) { failed++; lastError = e.message; }
  }
  res.json({
    ok: true, sent, skipped, failed,
    note: skipped ? skipped + ' bidder(s) registered with a mobile number instead of email and could not be emailed.' : undefined,
    error_detail: failed ? lastError : undefined
  });
});

/* ---------------- client: download own bids as Excel ---------------- */
/* ---------------- stocklist-format export helpers ---------------- */
/* Rebuild the original stocklist column order for an event from the stored
   per-stone detail objects (insertion order preserved from the upload). */
function stocklistHeaders(eventId) {
  /* preferred: the exact header row captured at upload (covers columns that are
     empty in every row, e.g. "DOR rough no") */
  const ev = db.prepare('SELECT headers_json FROM events WHERE id = ?').get(eventId);
  if (ev && ev.headers_json) {
    try {
      const h = JSON.parse(ev.headers_json);
      if (Array.isArray(h) && h.length) return h;
    } catch (e) { /* fall through to derivation below */ }
  }
  /* fallback for events uploaded before headers were recorded */
  const rows = db.prepare('SELECT details_json FROM stones WHERE event_id = ?').all(eventId);
  const seen = new Set();
  const order = [];
  for (const r of rows) {
    let d = {};
    try { d = JSON.parse(r.details_json || '{}'); } catch (e) { d = {}; }
    for (const k of Object.keys(d)) {
      if (!seen.has(k)) { seen.add(k); order.push(k); }
    }
  }
  return order;
}
/* Excel arithmetic leaves float noise (31043.789999999997) — tidy it for display */
function clean(v) {
  if (v === null || v === undefined || v === '') return '';
  const n = Number(v);
  if (typeof v === 'number' || (isFinite(n) && String(v).trim() !== '' && !isNaN(n))) {
    return Math.abs(n - Math.round(n)) < 1e-9 ? Math.round(n) : Number(n.toFixed(4));
  }
  return v;
}
const BID_COLS = ['MY BID DISC%', 'MY BID $/CT', 'MY BID AMOUNT $', 'BID PLACED / UPDATED'];
function styleHeader(ws, n) {
  const h = ws.getRow(1);
  h.font = { bold: true, color: { argb: 'FFFFFFFF' }, size: 10 };
  h.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF10A6C2' } };
  h.alignment = { vertical: 'middle', horizontal: 'center', wrapText: true };
  h.height = 26;
  /* highlight the appended bid columns in a second accent */
  for (let c = n - BID_COLS.length + 1; c <= n; c++) {
    h.getCell(c).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF188A52' } };
  }
  ws.views = [{ state: 'frozen', xSplit: 1, ySplit: 1 }];
  ws.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: n } };
}
function sizeCols(ws, headers) {
  ws.columns = headers.map(h => ({
    width: Math.min(30, Math.max(10, String(h).length + 3))
  }));
}

app.get('/api/my-bids/export', requireClient, async (req, res) => {
  const ev = activeEvent();
  if (!ev) return res.status(400).json({ error: 'No live event.' });
  const rows = db.prepare(
    'SELECT b.bid_disc, b.bid_per_ct, b.bid_amount, b.updated_at, s.details_json, s.cts ' +
    'FROM bids b JOIN stones s ON s.id = b.stone_pk ' +
    'WHERE b.event_id = ? AND b.client_id = ? ORDER BY s.cts DESC').all(ev.id, req.client.id);

  const base = stocklistHeaders(ev.id);
  const headers = base.concat(BID_COLS);
  const wb = new ExcelJS.Workbook();
  wb.creator = 'K.Girdharlal Bidding Portal';
  const ws = wb.addWorksheet('My Bids');
  sizeCols(ws, headers);
  ws.addRow(headers);

  let total = 0, totalCts = 0;
  for (const r of rows) {
    let d = {};
    try { d = JSON.parse(r.details_json || '{}'); } catch (e) { d = {}; }
    const line = base.map(h => clean(d[h]));
    line.push(
      r.bid_disc == null ? '' : round2(r.bid_disc),
      round2(r.bid_per_ct),
      round2(r.bid_amount),
      new Date(r.updated_at).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })
    );
    ws.addRow(line);
    total += r.bid_amount;
    totalCts += r.cts || 0;
  }

  /* totals row under the bid columns */
  const tRow = new Array(headers.length).fill('');
  tRow[0] = 'TOTAL — ' + rows.length + ' stone' + (rows.length === 1 ? '' : 's');
  const ctsIdx = base.indexOf('CTS');
  if (ctsIdx !== -1) tRow[ctsIdx] = round2(totalCts);
  tRow[headers.length - 2] = round2(total);
  const tr = ws.addRow(tRow);
  tr.font = { bold: true };
  tr.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFE6F6FA' } };

  styleHeader(ws, headers.length);
  const fname = 'MyBids_' + ev.name.replace(/[^a-zA-Z0-9-_]/g, '_') + '_' + new Date().toISOString().slice(0, 10) + '.xlsx';
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition', 'attachment; filename="' + fname + '"');
  await wb.xlsx.write(res);
  res.end();
});

/* ---------------- Excel export ---------------- */
app.get('/api/admin/events/:id/export', requireAdmin, async (req, res) => {
  const ev = db.prepare('SELECT * FROM events WHERE id = ?').get(Number(req.params.id));
  if (!ev) return res.status(404).json({ error: 'Event not found.' });

  const stones = db.prepare('SELECT * FROM stones WHERE event_id = ? ORDER BY cts DESC').all(ev.id);
  const allBids = db.prepare(
    'SELECT b.*, c.name AS client_name, c.company, c.contact, s.stone_id ' +
    'FROM bids b JOIN clients c ON c.id = b.client_id JOIN stones s ON s.id = b.stone_pk ' +
    'WHERE b.event_id = ?').all(ev.id);
  const bidsByStone = {};
  for (const b of allBids) (bidsByStone[b.stone_pk] = bidsByStone[b.stone_pk] || []).push(b);

  const wb = new ExcelJS.Workbook();
  wb.creator = 'KG Bidding';
  const headerStyle = ws => {
    ws.getRow(1).font = { bold: true, color: { argb: 'FFFFFFFF' } };
    ws.getRow(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1E3A5F' } };
    ws.views = [{ state: 'frozen', ySplit: 1 }];
  };

  /* Sheet 1: stone-wise comparison with best bid */
  const cmp = wb.addWorksheet('Stone Comparison');
  cmp.columns = [
    { header: 'Stone ID', key: 'sid', width: 14 }, { header: 'Shape', key: 'shape', width: 9 },
    { header: 'Cts', key: 'cts', width: 8 }, { header: 'Col', key: 'col', width: 6 },
    { header: 'Cla', key: 'cla', width: 7 }, { header: 'Cut/Pol/Sym', key: 'cps', width: 12 },
    { header: 'Fluor', key: 'flo', width: 9 }, { header: 'Rap', key: 'rap', width: 10 },
    { header: 'Ask Disc%', key: 'adisc', width: 10 }, { header: 'Ask $/Ct', key: 'act', width: 10 },
    { header: 'Ask Amt $', key: 'aamt', width: 12 }, { header: '# Bids', key: 'nbids', width: 7 },
    { header: 'Best Bid $/Ct', key: 'bct', width: 12 }, { header: 'Best Bid Disc%', key: 'bdisc', width: 13 },
    { header: 'Best Bid Amt $', key: 'bamt', width: 13 }, { header: 'Best Bidder', key: 'bwho', width: 26 },
    { header: 'Best vs Ask %', key: 'gap', width: 12 }
  ];
  for (const s of stones) {
    const bs = (bidsByStone[s.id] || []).slice().sort((a, b) => b.bid_per_ct - a.bid_per_ct);
    const best = bs[0];
    cmp.addRow({
      sid: s.stone_id, shape: s.shape, cts: s.cts, col: s.color, cla: s.clarity,
      cps: [s.cut, s.pol, s.symm].filter(Boolean).join('-'), flo: s.fluor, rap: s.rap,
      adisc: s.disc, act: s.price_ct, aamt: s.amount, nbids: bs.length,
      bct: best ? best.bid_per_ct : null, bdisc: best ? best.bid_disc : null,
      bamt: best ? best.bid_amount : null,
      bwho: best ? (best.company + ' (' + best.client_name + ')') : '',
      gap: best && s.price_ct ? round2((best.bid_per_ct / s.price_ct - 1) * 100) : null
    });
  }
  headerStyle(cmp);

  /* Sheet 2: all bids flat */
  const flat = wb.addWorksheet('All Bids');
  flat.columns = [
    { header: 'Company', key: 'co', width: 24 }, { header: 'Client Name', key: 'cn', width: 18 },
    { header: 'Contact', key: 'ct', width: 24 }, { header: 'Stone ID', key: 'sid', width: 14 },
    { header: 'Bid Disc%', key: 'bd', width: 10 }, { header: 'Bid $/Ct', key: 'bp', width: 10 },
    { header: 'Bid Amount $', key: 'ba', width: 12 }, { header: 'Placed / Updated', key: 'ts', width: 22 }
  ];
  const sortedBids = allBids.slice().sort((a, b) =>
    a.company.localeCompare(b.company) || a.stone_id.localeCompare(b.stone_id));
  for (const b of sortedBids) {
    flat.addRow({
      co: b.company, cn: b.client_name, ct: b.contact, sid: b.stone_id,
      bd: b.bid_disc, bp: b.bid_per_ct, ba: b.bid_amount,
      ts: new Date(b.updated_at).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })
    });
  }
  headerStyle(flat);

  /* Sheet 3: stones that received no bids */
  const nb = wb.addWorksheet('No Bids');
  nb.columns = [
    { header: 'Stone ID', key: 'sid', width: 14 }, { header: 'Shape', key: 'sh', width: 9 },
    { header: 'Cts', key: 'cts', width: 8 }, { header: 'Col', key: 'col', width: 6 },
    { header: 'Cla', key: 'cla', width: 7 }, { header: 'Cut/Pol/Sym', key: 'cps', width: 12 },
    { header: 'Fluor', key: 'flo', width: 9 }, { header: 'Rap', key: 'rap', width: 10 },
    { header: 'Ask Disc%', key: 'ad', width: 10 }, { header: 'Ask $/Ct', key: 'ac', width: 10 },
    { header: 'Ask Amt $', key: 'aa', width: 12 }, { header: 'Lab', key: 'lab', width: 7 }
  ];
  for (const s of stones) {
    if (bidsByStone[s.id]) continue;
    nb.addRow({
      sid: s.stone_id, sh: s.shape, cts: s.cts, col: s.color, cla: s.clarity,
      cps: [s.cut, s.pol, s.symm].filter(Boolean).join('-'), flo: s.fluor,
      rap: s.rap, ad: s.disc, ac: s.price_ct, aa: s.amount, lab: s.lab
    });
  }
  headerStyle(nb);

  /* One sheet per client */
  const clients = db.prepare(
    'SELECT DISTINCT c.* FROM bids b JOIN clients c ON c.id = b.client_id WHERE b.event_id = ?').all(ev.id);
  const usedNames = new Set(['Stone Comparison', 'All Bids', 'No Bids']);
  const perClient = db.prepare(
    'SELECT b.*, s.stone_id, s.shape, s.cts, s.color, s.clarity, s.rap, s.disc AS adisc, s.price_ct AS act ' +
    'FROM bids b JOIN stones s ON s.id = b.stone_pk ' +
    'WHERE b.event_id = ? AND b.client_id = ? ORDER BY s.cts DESC');
  for (const c of clients) {
    let base = String(c.company || c.name).replace(/[\\/?*\[\]:]/g, '').slice(0, 26) || ('Client ' + c.id);
    let nm = base, i = 2;
    while (usedNames.has(nm)) nm = base + ' (' + (i++) + ')';
    usedNames.add(nm);
    const ws = wb.addWorksheet(nm);
    ws.columns = [
      { header: 'Stone ID', key: 'sid', width: 14 }, { header: 'Shape', key: 'sh', width: 9 },
      { header: 'Cts', key: 'cts', width: 8 }, { header: 'Col', key: 'col', width: 6 },
      { header: 'Cla', key: 'cla', width: 7 }, { header: 'Rap', key: 'rap', width: 10 },
      { header: 'Ask Disc%', key: 'ad', width: 10 }, { header: 'Ask $/Ct', key: 'ac', width: 10 },
      { header: 'Bid Disc%', key: 'bd', width: 10 }, { header: 'Bid $/Ct', key: 'bp', width: 10 },
      { header: 'Bid Amount $', key: 'ba', width: 12 }, { header: 'Placed / Updated', key: 'ts', width: 22 }
    ];
    const rows = perClient.all(ev.id, c.id);
    let total = 0;
    for (const r of rows) {
      total += r.bid_amount;
      ws.addRow({
        sid: r.stone_id, sh: r.shape, cts: r.cts, col: r.color, cla: r.clarity, rap: r.rap,
        ad: r.adisc, ac: r.act, bd: r.bid_disc, bp: r.bid_per_ct, ba: r.bid_amount,
        ts: new Date(r.updated_at).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })
      });
    }
    const tr = ws.addRow({ sid: 'TOTAL', ba: round2(total) });
    tr.font = { bold: true };
    headerStyle(ws);
  }

  const fname = 'Bids_' + ev.name.replace(/[^a-zA-Z0-9-_]/g, '_') + '_' + new Date().toISOString().slice(0, 10) + '.xlsx';
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition', 'attachment; filename="' + fname + '"');
  await wb.xlsx.write(res);
  res.end();
});

/* ---------------- pages ---------------- */
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
/* public landing page */
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
/* the bidding portal itself (clients reach this via "Enter Portal") */
app.get('/portal', (req, res) => res.sendFile(path.join(__dirname, 'public', 'portal.html')));

app.listen(PORT, () => console.log('KG Bidding running on port ' + PORT));
