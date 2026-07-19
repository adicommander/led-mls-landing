const express = require('express');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const { pool, init, log } = require('./src/db');
const mail = require('./src/mail');

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) { console.error('JWT_SECRET is required'); process.exit(1); }

const SESSION_HOURS = 12;
const CODE_TTL_MIN = 10;
const MAX_CODE_ATTEMPTS = 5;
const MAX_LOGIN_FAILURES = 8;
const LOCK_MINUTES = 15;

app.set('trust proxy', 1);
app.use(express.json({ limit: '64kb' }));
app.use(cookieParser());
app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options', 'DENY');
  res.set('Referrer-Policy', 'same-origin');
  next();
});

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false });
const leadLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 15, standardHeaders: true, legacyHeaders: false });

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const publicUser = (u) => ({ id: u.id, email: u.email, name: u.name, first_name: u.first_name, last_name: u.last_name, phone: u.phone, role: u.role, is_active: u.is_active, must_change_password: u.must_change_password, created_at: u.created_at });

function setSessionCookie(res, user) {
  const token = jwt.sign({ uid: user.id, role: user.role, typ: 'session' }, JWT_SECRET, { expiresIn: `${SESSION_HOURS}h` });
  res.cookie('mls_session', token, {
    httpOnly: true, secure: true, sameSite: 'lax',
    maxAge: SESSION_HOURS * 3600 * 1000, path: '/',
  });
}

async function auth(req, res, next) {
  try {
    const payload = jwt.verify(req.cookies.mls_session || '', JWT_SECRET);
    if (payload.typ !== 'session') throw new Error('bad type');
    const { rows } = await pool.query('SELECT * FROM users WHERE id=$1 AND is_active', [payload.uid]);
    if (!rows[0]) throw new Error('gone');
    req.user = rows[0];
    next();
  } catch {
    res.status(401).json({ error: 'unauthorized' });
  }
}
const adminOnly = (req, res, next) => (req.user.role === 'admin' ? next() : res.status(403).json({ error: 'forbidden' }));

/* ---------- auth ---------- */

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const email = String(req.body.email || '').toLowerCase().trim();
  const password = String(req.body.password || '');
  const generic = () => res.status(401).json({ error: 'פרטי ההתחברות שגויים' });

  const { rows } = await pool.query('SELECT * FROM users WHERE email=$1 AND is_active', [email]);
  const user = rows[0];
  if (!user) return generic();
  if (user.locked_until && new Date(user.locked_until) > new Date()) {
    return res.status(429).json({ error: 'החשבון ננעל זמנית עקב ניסיונות כושלים. נסה שוב בעוד רבע שעה.' });
  }
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) {
    const fails = user.failed_attempts + 1;
    const lock = fails >= MAX_LOGIN_FAILURES ? `now() + interval '${LOCK_MINUTES} minutes'` : 'NULL';
    await pool.query(`UPDATE users SET failed_attempts=$1, locked_until=${lock} WHERE id=$2`, [fails % MAX_LOGIN_FAILURES, user.id]);
    return generic();
  }
  await pool.query('UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=$1', [user.id]);

  if (process.env.TWOFA_ENABLED === 'false') {
    setSessionCookie(res, user);
    await log(user.id, 'login.success', '2fa disabled by config');
    return res.json({ ok: true, user: publicUser(user) });
  }

  const code = String(crypto.randomInt(100000, 1000000));
  await pool.query('UPDATE login_codes SET used=true WHERE user_id=$1 AND NOT used', [user.id]);
  await pool.query(
    `INSERT INTO login_codes (user_id, code_hash, expires_at) VALUES ($1,$2, now() + interval '${CODE_TTL_MIN} minutes')`,
    [user.id, sha256(code)]
  );
  const tpl = mail.codeEmail(code);
  const result = await mail.send({ to: user.email, ...tpl });
  const pre = jwt.sign({ uid: user.id, typ: 'pre2fa' }, JWT_SECRET, { expiresIn: '10m' });
  await log(user.id, 'login.password_ok', mail.configured ? '' : 'smtp not configured — code in logs');
  res.json({ pending2fa: true, pre, emailSent: result.sent });
});

app.post('/api/auth/verify', authLimiter, async (req, res) => {
  let payload;
  try {
    payload = jwt.verify(String(req.body.pre || ''), JWT_SECRET);
    if (payload.typ !== 'pre2fa') throw new Error();
  } catch { return res.status(401).json({ error: 'פג תוקף ההתחברות, התחל מחדש' }); }

  const code = String(req.body.code || '').trim();
  const { rows } = await pool.query(
    'SELECT * FROM login_codes WHERE user_id=$1 AND NOT used ORDER BY id DESC LIMIT 1', [payload.uid]);
  const rec = rows[0];
  if (!rec || new Date(rec.expires_at) < new Date()) return res.status(401).json({ error: 'הקוד פג תוקף, התחל מחדש' });
  if (rec.attempts >= MAX_CODE_ATTEMPTS) return res.status(429).json({ error: 'יותר מדי ניסיונות. התחל התחברות מחדש.' });
  if (sha256(code) !== rec.code_hash) {
    await pool.query('UPDATE login_codes SET attempts=attempts+1 WHERE id=$1', [rec.id]);
    return res.status(401).json({ error: 'קוד שגוי' });
  }
  await pool.query('UPDATE login_codes SET used=true WHERE id=$1', [rec.id]);
  const { rows: urows } = await pool.query('SELECT * FROM users WHERE id=$1 AND is_active', [payload.uid]);
  if (!urows[0]) return res.status(401).json({ error: 'unauthorized' });
  setSessionCookie(res, urows[0]);
  await log(urows[0].id, 'login.success');
  res.json({ ok: true, user: publicUser(urows[0]) });
});

app.post('/api/auth/logout', (req, res) => { res.clearCookie('mls_session', { path: '/' }); res.json({ ok: true }); });
app.get('/api/auth/me', auth, (req, res) => res.json({ user: publicUser(req.user) }));

app.post('/api/auth/change-password', auth, async (req, res) => {
  const current = String(req.body.current || '');
  const next = String(req.body.next || '');
  if (next.length < 10) return res.status(400).json({ error: 'סיסמה חדשה חייבת להיות באורך 10 תווים לפחות' });
  if (!(await bcrypt.compare(current, req.user.password_hash))) return res.status(401).json({ error: 'הסיסמה הנוכחית שגויה' });
  const hash = await bcrypt.hash(next, 12);
  await pool.query('UPDATE users SET password_hash=$1, must_change_password=false WHERE id=$2', [hash, req.user.id]);
  await log(req.user.id, 'password.changed');
  res.json({ ok: true });
});

/* ---------- users (admin) ---------- */

app.get('/api/users', auth, adminOnly, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM users ORDER BY id');
  res.json({ users: rows.map(publicUser) });
});

app.post('/api/users', auth, adminOnly, async (req, res) => {
  const email = String(req.body.email || '').toLowerCase().trim();
  const firstName = String(req.body.first_name || '').trim();
  const lastName = String(req.body.last_name || '').trim();
  const phone = String(req.body.phone || '').trim();
  const name = `${firstName} ${lastName}`.trim();
  const role = req.body.role === 'admin' ? 'admin' : 'agent';
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: 'כתובת מייל לא תקינה' });
  const temp = crypto.randomBytes(9).toString('base64url');
  const hash = await bcrypt.hash(temp, 12);
  try {
    const { rows } = await pool.query(
      `INSERT INTO users (email, name, first_name, last_name, phone, password_hash, role, must_change_password) VALUES ($1,$2,$3,$4,$5,$6,$7,true) RETURNING *`,
      [email, name, firstName, lastName, phone, hash, role]);
    await mail.send({
      to: email,
      subject: 'הוזמנת למערכת הניהול של MLS ישראל',
      text: `שלום ${name},\nנוצר עבורך משתמש במערכת הניהול: https://led-mls.co.il/admin\nשם משתמש: ${email}\nסיסמה זמנית: ${temp}\nתתבקש להחליף אותה בכניסה הראשונה.`,
    });
    await log(req.user.id, 'user.created', email);
    res.json({ user: publicUser(rows[0]), tempPassword: temp });
  } catch (e) {
    if (String(e.message).includes('duplicate')) return res.status(409).json({ error: 'משתמש עם המייל הזה כבר קיים' });
    throw e;
  }
});

app.patch('/api/users/:id', auth, adminOnly, async (req, res) => {
  const id = Number(req.params.id);
  const target = (await pool.query('SELECT * FROM users WHERE id=$1', [id])).rows[0];
  if (!target) return res.status(404).json({ error: 'not found' });
  const firstName = req.body.first_name !== undefined ? String(req.body.first_name).trim() : target.first_name;
  const lastName = req.body.last_name !== undefined ? String(req.body.last_name).trim() : target.last_name;
  const phone = req.body.phone !== undefined ? String(req.body.phone).trim() : target.phone;
  const name = `${firstName} ${lastName}`.trim() || target.name;
  const role = req.body.role !== undefined ? (req.body.role === 'admin' ? 'admin' : 'agent') : target.role;
  const active = req.body.is_active !== undefined ? !!req.body.is_active : target.is_active;
  if (id === req.user.id && (!active || role !== 'admin')) {
    return res.status(400).json({ error: 'לא ניתן להשבית או להוריד הרשאות לעצמך' });
  }
  let resetInfo = {};
  if (req.body.reset_password) {
    const temp = crypto.randomBytes(9).toString('base64url');
    const hash = await bcrypt.hash(temp, 12);
    await pool.query('UPDATE users SET password_hash=$1, must_change_password=true WHERE id=$2', [hash, id]);
    await mail.send({ to: target.email, subject: 'איפוס סיסמה — מערכת הניהול MLS ישראל', text: `סיסמה זמנית חדשה: ${temp}` });
    resetInfo = { tempPassword: temp };
  }
  const { rows } = await pool.query(
    'UPDATE users SET name=$1, first_name=$2, last_name=$3, phone=$4, role=$5, is_active=$6 WHERE id=$7 RETURNING *',
    [name, firstName, lastName, phone, role, active, id]);
  await log(req.user.id, 'user.updated', target.email);
  res.json({ user: publicUser(rows[0]), ...resetInfo });
});

app.delete('/api/users/:id', auth, adminOnly, async (req, res) => {
  const id = Number(req.params.id);
  if (id === req.user.id) return res.status(400).json({ error: 'לא ניתן למחוק את עצמך' });
  const target = (await pool.query('SELECT email FROM users WHERE id=$1', [id])).rows[0];
  if (!target) return res.status(404).json({ error: 'not found' });
  await pool.query('DELETE FROM users WHERE id=$1', [id]);
  await log(req.user.id, 'user.deleted', target.email);
  res.json({ ok: true });
});

/* ---------- leads ---------- */

// public: submitted by the website contact form
app.post('/api/leads', leadLimiter, async (req, res) => {
  if (String(req.body.company || '') !== '') return res.json({ ok: true }); // honeypot
  const name = String(req.body.name || '').trim().slice(0, 120);
  const phone = String(req.body.phone || '').trim().slice(0, 40);
  const email = String(req.body.email || '').trim().slice(0, 160);
  const message = String(req.body.message || '').trim().slice(0, 4000);
  const page = String(req.body.page || '').trim().slice(0, 200);
  if (!name || (!phone && !email)) return res.status(400).json({ error: 'missing fields' });
  const { rows } = await pool.query(
    'INSERT INTO leads (name, phone, email, message, page) VALUES ($1,$2,$3,$4,$5) RETURNING id',
    [name, phone, email, message, page]);
  const notify = process.env.LEADS_NOTIFY_EMAIL;
  if (notify) {
    await mail.send({
      to: notify,
      subject: `ליד חדש מהאתר: ${name}`,
      text: `שם: ${name}\nטלפון: ${phone}\nמייל: ${email}\nעמוד: ${page}\n\n${message}\n\nלניהול: https://led-mls.co.il/admin`,
    });
  }
  res.json({ ok: true, id: rows[0].id });
});

app.get('/api/leads', auth, async (req, res) => {
  const status = ['new', 'in_progress', 'won', 'lost'].includes(req.query.status) ? req.query.status : null;
  const q = String(req.query.q || '').trim();
  const params = [];
  const where = [];
  if (status) { params.push(status); where.push(`l.status=$${params.length}`); }
  if (q) { params.push(`%${q}%`); where.push(`(l.name ILIKE $${params.length} OR l.phone ILIKE $${params.length} OR l.email ILIKE $${params.length} OR l.message ILIKE $${params.length})`); }
  const { rows } = await pool.query(
    `SELECT l.*, u.name AS assigned_name FROM leads l LEFT JOIN users u ON u.id=l.assigned_to
     ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY l.created_at DESC LIMIT 500`, params);
  res.json({ leads: rows });
});

app.get('/api/leads/:id', auth, async (req, res) => {
  const id = Number(req.params.id);
  const lead = (await pool.query('SELECT l.*, u.name AS assigned_name FROM leads l LEFT JOIN users u ON u.id=l.assigned_to WHERE l.id=$1', [id])).rows[0];
  if (!lead) return res.status(404).json({ error: 'not found' });
  const notes = (await pool.query('SELECT n.*, u.name AS user_name FROM lead_notes n LEFT JOIN users u ON u.id=n.user_id WHERE n.lead_id=$1 ORDER BY n.id', [id])).rows;
  const messages = (await pool.query('SELECT m.*, u.name AS user_name FROM lead_messages m LEFT JOIN users u ON u.id=m.user_id WHERE m.lead_id=$1 ORDER BY m.id', [id])).rows;
  res.json({ lead, notes, messages });
});

app.patch('/api/leads/:id', auth, async (req, res) => {
  const id = Number(req.params.id);
  const lead = (await pool.query('SELECT * FROM leads WHERE id=$1', [id])).rows[0];
  if (!lead) return res.status(404).json({ error: 'not found' });
  const status = ['new', 'in_progress', 'won', 'lost'].includes(req.body.status) ? req.body.status : lead.status;
  const assigned = req.body.assigned_to === null ? null : (req.body.assigned_to !== undefined ? Number(req.body.assigned_to) : lead.assigned_to);
  const { rows } = await pool.query('UPDATE leads SET status=$1, assigned_to=$2 WHERE id=$3 RETURNING *', [status, assigned, id]);
  await log(req.user.id, 'lead.updated', `#${id} → ${status}`);
  res.json({ lead: rows[0] });
});

app.post('/api/leads/:id/notes', auth, async (req, res) => {
  const id = Number(req.params.id);
  const body = String(req.body.body || '').trim();
  if (!body) return res.status(400).json({ error: 'empty' });
  const { rows } = await pool.query(
    'INSERT INTO lead_notes (lead_id, user_id, body) VALUES ($1,$2,$3) RETURNING *', [id, req.user.id, body]);
  res.json({ note: rows[0] });
});

app.post('/api/leads/:id/email', auth, async (req, res) => {
  const id = Number(req.params.id);
  const lead = (await pool.query('SELECT * FROM leads WHERE id=$1', [id])).rows[0];
  if (!lead) return res.status(404).json({ error: 'not found' });
  if (!lead.email) return res.status(400).json({ error: 'ללקוח הזה אין כתובת מייל' });
  const subject = String(req.body.subject || '').trim().slice(0, 200);
  const body = String(req.body.body || '').trim().slice(0, 8000);
  if (!subject || !body) return res.status(400).json({ error: 'נדרשים נושא ותוכן' });
  const result = await mail.send({ to: lead.email, subject, text: body });
  if (!result.sent) return res.status(502).json({ error: 'שליחת המייל נכשלה — בדוק את הגדרות ה-SMTP' });
  await pool.query(
    'INSERT INTO lead_messages (lead_id, user_id, direction, channel, subject, body, delivered) VALUES ($1,$2,\'out\',\'email\',$3,$4,true)',
    [id, req.user.id, subject, body]);
  await log(req.user.id, 'lead.emailed', `#${id} → ${lead.email}`);
  res.json({ ok: true });
});

/* ---------- stats + ui ---------- */

app.get('/api/stats', auth, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT status, COUNT(*)::int AS n FROM leads GROUP BY status`);
  const total = (await pool.query('SELECT COUNT(*)::int AS n FROM leads')).rows[0].n;
  const week = (await pool.query(`SELECT COUNT(*)::int AS n FROM leads WHERE created_at > now() - interval '7 days'`)).rows[0].n;
  res.json({ total, week, byStatus: Object.fromEntries(rows.map(r => [r.status, r.n])) });
});

app.use('/admin', express.static(path.join(__dirname, 'public'), { index: 'index.html' }));
app.get('/api/health', (req, res) => res.json({ ok: true }));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'internal error' });
});

init().then(() => {
  app.listen(PORT, () => console.log(`MLS admin API listening on :${PORT} (smtp configured: ${mail.configured})`));
}).catch((e) => { console.error('DB init failed:', e); process.exit(1); });
