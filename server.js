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
function newToken() { return crypto.randomBytes(32).toString('hex'); }

function getSession(req) {
  const token = parseCookies(req).sid;
  if (!token) return null;
  return db.prepare('SELECT * FROM sessions WHERE token = ?').get(token) || null;
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
const round2 = n => Math.round(n * 100) / 100;

/* ---------------- client auth ---------------- */
app.post('/api/client-login', (req, res) => {
  let { name, company, contact } = req.body || {};
  name = (name || '').trim();
  company = (company || '').trim();
  contact = (contact || '').trim().toLowerCase();
  if (!name || !company || !contact) return res.status(400).json({ error: 'Name, company and email/mobile are all required.' });
  if (contact.length < 5) return res.status(400).json({ error: 'Please enter a valid email or mobile number.' });

  let client = db.prepare('SELECT * FROM clients WHERE contact = ?').get(contact);
  if (!client) {
    const info = db.prepare('INSERT INTO clients (name, company, contact, created_at) VALUES (?,?,?,?)')
      .run(name, company, contact, Date.now());
    client = db.prepare('SELECT * FROM clients WHERE id = ?').get(Number(info.lastInsertRowid));
  } else {
    db.prepare('UPDATE clients SET name = ?, company = ? WHERE id = ?').run(name, company, client.id);
    client = db.prepare('SELECT * FROM clients WHERE id = ?').get(client.id);
  }
  const token = newToken();
  db.prepare('INSERT INTO sessions (token, client_id, is_admin, created_at) VALUES (?,?,0,?)').run(token, client.id, Date.now());
  setCookie(res, 'sid', token);
  res.json({ client });
});

app.get('/api/me', (req, res) => {
  const s = getSession(req);
  if (!s) return res.json({ client: null, admin: false });
  const client = s.client_id ? db.prepare('SELECT * FROM clients WHERE id = ?').get(s.client_id) : null;
  res.json({ client: client || null, admin: !!s.is_admin });
});

app.post('/api/logout', (req, res) => {
  const token = parseCookies(req).sid;
  if (token) db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
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
  const token = newToken();
  db.prepare('INSERT INTO sessions (token, client_id, is_admin, created_at) VALUES (?, NULL, 1, ?)').run(token, Date.now());
  setCookie(res, 'sid', token);
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

    const details = {};
    for (let c = range.s.c; c <= range.e.c; c++) {
      const h = headers[c - range.s.c];
      if (!h) continue;
      const cell = ws[XLSX.utils.encode_cell({ r, c })];
      const v = cell ? cell.v : null;
      if (v !== null && v !== undefined && String(v).trim() !== '' && String(v).trim() !== 'NONE') {
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
      const info = db.prepare("INSERT INTO events (name, terms, end_time, status, created_at) VALUES (?,?,?,'live',?)")
        .run(name, terms, endTime, Date.now());
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
  res.json({ client, bids });
});

app.get('/api/admin/clients', requireAdmin, (req, res) => {
  const clients = db.prepare(
    'SELECT c.*, (SELECT COUNT(*) FROM bids b WHERE b.client_id = c.id) AS total_bids ' +
    'FROM clients c ORDER BY c.created_at DESC').all();
  res.json({ clients });
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

  /* One sheet per client */
  const clients = db.prepare(
    'SELECT DISTINCT c.* FROM bids b JOIN clients c ON c.id = b.client_id WHERE b.event_id = ?').all(ev.id);
  const usedNames = new Set(['Stone Comparison', 'All Bids']);
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
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log('KG Bidding running on port ' + PORT));
