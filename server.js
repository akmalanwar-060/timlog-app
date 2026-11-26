require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const PORT = process.env.PORT || 3000;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || '';
const SUMOPOD_API_KEY = process.env.SUMOPOD_API_KEY || '';
const SUMOPOD_BASE = 'https://api-pay-sandbox.sumopod.com/api/v1';
const REPORT_PRICE = 15000;

// ===== DATABASE (file timlog.db dibuat otomatis) =====
const db = new DatabaseSync(path.join(__dirname, 'timlog.db'));
db.exec(`
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL, role TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY, user_id TEXT NOT NULL, created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS classes (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, lecturer_id TEXT NOT NULL, deadline TEXT
  );
  CREATE TABLE IF NOT EXISTS teams (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, code TEXT UNIQUE NOT NULL,
    leader_id TEXT NOT NULL, class_id TEXT
  );
  CREATE TABLE IF NOT EXISTS team_members (
    team_id TEXT NOT NULL, user_id TEXT NOT NULL, PRIMARY KEY (team_id, user_id)
  );
  CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY, team_id TEXT NOT NULL, title TEXT NOT NULL,
    assignee_id TEXT NOT NULL, weight INTEGER NOT NULL, deadline TEXT,
    status TEXT NOT NULL DEFAULT 'todo', file TEXT DEFAULT '', note TEXT DEFAULT ''
  );
  CREATE TABLE IF NOT EXISTS payments (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL, team_id TEXT, order_id TEXT,
    amount INTEGER NOT NULL, status TEXT NOT NULL, expires_at TEXT, payment_link_url TEXT
  );
  CREATE TABLE IF NOT EXISTS webhook_log (id TEXT PRIMARY KEY, received_at TEXT NOT NULL);
`);

const q = sql => db.prepare(sql);
const now = () => new Date().toISOString();
const newCode = () => 'TIM-' + Math.floor(1000 + Math.random() * 9000);

// ===== PASSWORD & SESI =====
function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt + ':' + crypto.scryptSync(pw, salt, 64).toString('hex');
}
function checkPassword(pw, stored) {
  const [salt, hash] = stored.split(':');
  const test = crypto.scryptSync(pw, salt, 64);
  return crypto.timingSafeEqual(test, Buffer.from(hash, 'hex'));
}
function newSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  q('INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)').run(token, userId, now());
  return token;
}
function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer /, '');
  const u = q('SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?').get(token);
  if (!u) return res.status(401).json({ error: 'Belum login' });
  req.user = u;
  next();
}
const onlyRole = (...roles) => (req, res, next) =>
  roles.includes(req.user.role) ? next() : res.status(403).json({ error: 'Peran ini tidak punya akses' });

// ===== HELPER KELOMPOK =====
function isLeader(teamId, userId) {
  return !!q('SELECT 1 FROM teams WHERE id = ? AND leader_id = ?').get(teamId, userId);
}
function isMember(teamId, userId) {
  return !!q('SELECT 1 FROM team_members WHERE team_id = ? AND user_id = ?').get(teamId, userId);
}
function teamSummary(teamId) {
  const team = q('SELECT * FROM teams WHERE id = ?').get(teamId);
  if (!team) return null;
  const tasks = q('SELECT * FROM tasks WHERE team_id = ?').all(teamId);
  const total = tasks.reduce((s, t) => s + t.weight, 0);
  const approved = tasks.filter(t => t.status === 'approved');
  const shareOf = uid => {
    const w = approved.filter(t => t.assignee_id === uid).reduce((s, t) => s + t.weight, 0);
    return total ? Math.round((w / total) * 100) : 0;
  };
  const members = q('SELECT u.id, u.name FROM team_members m JOIN users u ON u.id = m.user_id WHERE m.team_id = ?')
    .all(teamId)
    .map(m => ({ id: m.id, name: m.name, isLeader: m.id === team.leader_id, share: shareOf(m.id) }));
  const approvedWeight = approved.reduce((s, t) => s + t.weight, 0);
  return {
    id: team.id, name: team.name, code: team.code, leaderId: team.leader_id, classId: team.class_id,
    totalWeight: total,
    progress: total ? Math.round((approvedWeight / total) * 100) : 0,
    members,
    tasks: tasks.map(t => ({
      id: t.id, title: t.title, assigneeId: t.assignee_id, weight: t.weight,
      deadline: t.deadline, status: t.status, file: t.file, note: t.note,
    })),
  };
}

// ===== PEMBAYARAN =====
function paymentView(id) {
  const p = q('SELECT * FROM payments WHERE id = ?').get(id);
  if (!p) return null;
  const expired = p.status === 'pending' && p.expires_at && new Date(p.expires_at) < new Date();
  return {
    id: p.id, orderId: p.order_id, amount: p.amount, teamId: p.team_id,
    status: expired ? 'expired' : p.status, expiresAt: p.expires_at, paymentLinkUrl: p.payment_link_url,
  };
}

function verifySignature(secret, id, timestamp, rawBody, signatureHeader) {
  if (!secret || !id || !timestamp || !signatureHeader) return false;
  const nowSec = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSec - Number(timestamp)) > 300) return false;
  const secretBytes = Buffer.from(secret.replace('whsec_', ''), 'base64');
  const expected = crypto.createHmac('sha256', secretBytes)
    .update(`${id}.${timestamp}.${rawBody}`).digest('base64');
  const expectedBuf = Buffer.from(expected);
  return signatureHeader.split(' ').some(part => {
    const sigBuf = Buffer.from(part.split(',')[1] || '');
    return sigBuf.length === expectedBuf.length && crypto.timingSafeEqual(sigBuf, expectedBuf);
  });
}

function handleWebhook(req, res) {
  const id = req.headers['svix-id'];
  const timestamp = req.headers['svix-timestamp'];
  const signature = req.headers['svix-signature'];
  const rawBody = req.body.toString('utf8');

  if (!verifySignature(WEBHOOK_SECRET, id, timestamp, rawBody, signature)) {
    console.log('Signature TIDAK valid. ID:', id);
    return res.sendStatus(401);
  }
  if (q('SELECT 1 FROM webhook_log WHERE id = ?').get(id)) return res.sendStatus(200);
  q('INSERT INTO webhook_log (id, received_at) VALUES (?, ?)').run(id, now());

  let event;
  try { event = JSON.parse(rawBody); } catch (e) { return res.sendStatus(400); }
  const type = event.event_type || event.type || '';
  console.log('Event diterima:', type);

  const d = event.data || {};
  const pid = d.payment_id || d.id;
  // TODO: ganti dengan nama event pembayaran sukses yang pasti setelah dikonfirmasi
  const isPaid = /completed|paid|success|settled/i.test(type);
  if (isPaid && pid) {
    q("UPDATE payments SET status = 'paid' WHERE id = ?").run(pid);
    console.log('Pembayaran lunas:', pid);
  }
  res.sendStatus(200);
}

// ===== APP =====
const app = express();
app.use(express.static(path.join(__dirname, 'public')));
app.get('/api/health', (req, res) => res.json({ status: 'OK' }));
app.post('/webhook', express.raw({ type: '*/*' }), handleWebhook);
app.use('/api', express.json());

// --- Akun ---
app.post('/api/auth/register', (req, res) => {
  const { name, email, password, role } = req.body || {};
  if (!name || !email || !password || password.length < 6)
    return res.status(400).json({ error: 'Data belum lengkap, password minimal 6 karakter' });
  if (!['mahasiswa', 'ketua', 'dosen'].includes(role))
    return res.status(400).json({ error: 'Peran tidak valid' });
  const e = String(email).trim().toLowerCase();
  if (q('SELECT id FROM users WHERE email = ?').get(e))
    return res.status(409).json({ error: 'Email sudah terdaftar' });
  const id = crypto.randomUUID();
  q('INSERT INTO users (id, name, email, password_hash, role) VALUES (?, ?, ?, ?, ?)')
    .run(id, String(name).trim(), e, hashPassword(password), role);
  const u = q('SELECT * FROM users WHERE id = ?').get(id);
  res.json({ token: newSession(id), user: { id, name: u.name, email: e, role } });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  const u = q('SELECT * FROM users WHERE email = ?').get(String(email || '').trim().toLowerCase());
  if (!u || !checkPassword(String(password || ''), u.password_hash))
    return res.status(401).json({ error: 'Email atau password salah' });
  res.json({ token: newSession(u.id), user: { id: u.id, name: u.name, email: u.email, role: u.role } });
});

app.post('/api/auth/logout', auth, (req, res) => {
  const token = (req.headers.authorization || '').replace(/^Bearer /, '');
  q('DELETE FROM sessions WHERE token = ?').run(token);
  res.json({ ok: true });
});

app.get('/api/auth/me', auth, (req, res) => {
  res.json({ id: req.user.id, name: req.user.name, email: req.user.email, role: req.user.role });
});

// --- Kelas (dosen) ---
app.get('/api/classes', auth, (req, res) => {
  const rows = req.user.role === 'dosen'
    ? q('SELECT * FROM classes WHERE lecturer_id = ?').all(req.user.id)
    : q('SELECT * FROM classes').all();
  res.json(rows.map(c => ({ id: c.id, name: c.name, deadline: c.deadline })));
});

app.post('/api/classes', auth, onlyRole('dosen'), (req, res) => {
  const { name, deadline } = req.body || {};
  if (!name) return res.status(400).json({ error: 'Nama kelas wajib diisi' });
  const id = crypto.randomUUID();
  q('INSERT INTO classes (id, name, lecturer_id, deadline) VALUES (?, ?, ?, ?)')
    .run(id, String(name).trim(), req.user.id, deadline || null);
  res.json({ id, name: String(name).trim(), deadline: deadline || null });
});

// --- Kelompok ---
app.post('/api/teams', auth, onlyRole('ketua'), (req, res) => {
  const { name, classId } = req.body || {};
  if (!name) return res.status(400).json({ error: 'Nama kelompok wajib diisi' });
  const id = crypto.randomUUID();
  let code;
  do { code = newCode(); } while (q('SELECT 1 FROM teams WHERE code = ?').get(code));
  q('INSERT INTO teams (id, name, code, leader_id, class_id) VALUES (?, ?, ?, ?, ?)')
    .run(id, String(name).trim(), code, req.user.id, classId || null);
  q('INSERT INTO team_members (team_id, user_id) VALUES (?, ?)').run(id, req.user.id);
  res.json(teamSummary(id));
});

app.post('/api/teams/join', auth, onlyRole('mahasiswa', 'ketua'), (req, res) => {
  const code = String((req.body || {}).code || '').trim().toUpperCase();
  const team = q('SELECT * FROM teams WHERE code = ?').get(code);
  if (!team) return res.status(404).json({ error: 'Kode undangan tidak ditemukan' });
  if (isMember(team.id, req.user.id)) return res.status(409).json({ error: 'Anda sudah tergabung di kelompok ini' });
  q('INSERT INTO team_members (team_id, user_id) VALUES (?, ?)').run(team.id, req.user.id);
  res.json(teamSummary(team.id));
});

app.get('/api/teams/mine', auth, (req, res) => {
  const row = q('SELECT t.id FROM teams t JOIN team_members m ON m.team_id = t.id WHERE m.user_id = ? LIMIT 1').get(req.user.id);
  res.json(row ? teamSummary(row.id) : null);
});

// --- Tugas ---
app.post('/api/teams/:id/tasks', auth, onlyRole('ketua'), (req, res) => {
  const team = q('SELECT * FROM teams WHERE id = ?').get(req.params.id);
  if (!team || !isLeader(team.id, req.user.id))
    return res.status(403).json({ error: 'Hanya ketua kelompok ini yang bisa membuat tugas' });
  const { title, assigneeId, weight, deadline } = req.body || {};
  const w = Number(weight);
  if (!title || !assigneeId || !(w > 0)) return res.status(400).json({ error: 'Data tugas belum lengkap' });
  if (!isMember(team.id, assigneeId)) return res.status(400).json({ error: 'Penerima tugas bukan anggota' });
  const used = q('SELECT COALESCE(SUM(weight), 0) AS s FROM tasks WHERE team_id = ?').get(team.id).s;
  if (used + w > 100) return res.status(400).json({ error: `Sisa bobot hanya ${100 - used}%` });
  q('INSERT INTO tasks (id, team_id, title, assignee_id, weight, deadline) VALUES (?, ?, ?, ?, ?, ?)')
    .run(crypto.randomUUID(), team.id, String(title).trim(), assigneeId, w, deadline || null);
  res.json(teamSummary(team.id));
});

app.post('/api/tasks/:id/submit', auth, (req, res) => {
  const t = q('SELECT * FROM tasks WHERE id = ?').get(req.params.id);
  if (!t || t.assignee_id !== req.user.id) return res.status(403).json({ error: 'Ini bukan tugas Anda' });
  if (!['todo', 'revision'].includes(t.status))
    return res.status(400).json({ error: 'Tugas tidak bisa diunggah sekarang' });
  const file = String((req.body || {}).file || '').trim();
  if (!file) return res.status(400).json({ error: 'Nama file bukti wajib diisi' });
  q("UPDATE tasks SET status = 'submitted', file = ?, note = '' WHERE id = ?").run(file, t.id);
  res.json(teamSummary(t.team_id));
});

app.post('/api/tasks/:id/review', auth, onlyRole('ketua'), (req, res) => {
  const t = q('SELECT * FROM tasks WHERE id = ?').get(req.params.id);
  if (!t || !isLeader(t.team_id, req.user.id)) return res.status(403).json({ error: 'Hanya ketua kelompok ini' });
  if (t.status !== 'submitted') return res.status(400).json({ error: 'Tugas belum dikirim untuk diperiksa' });
  const { action, note } = req.body || {};
  if (action === 'approve') {
    q("UPDATE tasks SET status = 'approved', note = '' WHERE id = ?").run(t.id);
  } else if (action === 'revise') {
    if (!note) return res.status(400).json({ error: 'Catatan revisi wajib diisi' });
    q("UPDATE tasks SET status = 'revision', note = ? WHERE id = ?").run(String(note).trim(), t.id);
  } else {
    return res.status(400).json({ error: 'Aksi tidak valid' });
  }
  res.json(teamSummary(t.team_id));
});

// --- Pembayaran laporan (QRIS sekali pakai) ---
app.post('/api/payments', auth, async (req, res) => {
  if (!SUMOPOD_API_KEY) return res.status(500).json({ error: 'SUMOPOD_API_KEY belum diisi di .env' });
  const teamId = (req.body || {}).teamId || null;
  if (teamId && !isMember(teamId, req.user.id))
    return res.status(403).json({ error: 'Bukan anggota kelompok ini' });
  const orderId = 'RPT-' + Date.now() + '-' + crypto.randomBytes(3).toString('hex');
  try {
    const r = await fetch(SUMOPOD_BASE + '/payments', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Api-Key': SUMOPOD_API_KEY },
      body: JSON.stringify({
        order_id: orderId, amount: REPORT_PRICE, currency: 'IDR',
        expires_in_hours: 1, payment_method_type_code: 'QRIS_INSTANT',
      }),
    });
    const data = await r.json();
    if (!r.ok || !data.payment_id)
      return res.status(502).json({ error: 'Gagal membuat pembayaran', detail: data });
    q('INSERT INTO payments (id, user_id, team_id, order_id, amount, status, expires_at, payment_link_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(data.payment_id, req.user.id, teamId, orderId, REPORT_PRICE, 'pending', data.expires_at, data.payment_link_url);
    res.json(paymentView(data.payment_id));
  } catch (e) {
    res.status(500).json({ error: 'Tidak bisa terhubung ke Sumopod' });
  }
});

app.get('/api/payments/:id', auth, (req, res) => {
  const p = q('SELECT * FROM payments WHERE id = ?').get(req.params.id);
  if (!p || p.user_id !== req.user.id) return res.status(404).json({ error: 'Tidak ditemukan' });
  res.json(paymentView(p.id));
});

// --- Laporan kontribusi ---
// Dosen: bebas akses kelompok di kelasnya. Mahasiswa/ketua: harus anggota dan sudah bayar.
app.get('/api/teams/:id/report', auth, (req, res) => {
  const team = q('SELECT * FROM teams WHERE id = ?').get(req.params.id);
  if (!team) return res.status(404).json({ error: 'Kelompok tidak ditemukan' });
  const isLecturer = req.user.role === 'dosen' &&
    !!q('SELECT 1 FROM classes WHERE id = ? AND lecturer_id = ?').get(team.class_id, req.user.id);
  const paid = !!q("SELECT 1 FROM payments WHERE team_id = ? AND user_id = ? AND status = 'paid'")
    .get(team.id, req.user.id);
  if (!isLecturer && !(isMember(team.id, req.user.id) && paid))
    return res.status(403).json({ error: 'Laporan belum dibayar atau bukan akses Anda' });
  res.json(teamSummary(team.id));
});

// --- Monitoring dosen ---
app.get('/api/classes/:id/teams', auth, onlyRole('dosen'), (req, res) => {
  const c = q('SELECT * FROM classes WHERE id = ? AND lecturer_id = ?').get(req.params.id, req.user.id);
  if (!c) return res.status(403).json({ error: 'Kelas ini bukan milik Anda' });
  const ids = q('SELECT id FROM teams WHERE class_id = ?').all(c.id);
  res.json(ids.map(t => teamSummary(t.id)));
});
app.listen(PORT, () => console.log(`Server berjalan di http://localhost:${PORT}`));