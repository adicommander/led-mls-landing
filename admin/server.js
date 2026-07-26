const express = require('express');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const { pool, init, log, nextSerial } = require('./src/db');
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

const STAGES = ['new', 'contacted', 'quoted', 'negotiation', 'won', 'lost'];
const OPEN_STAGES = ['new', 'contacted', 'quoted', 'negotiation'];
// probability weights per open stage, for a weighted revenue forecast
const STAGE_WEIGHT = { new: 0.1, contacted: 0.25, quoted: 0.5, negotiation: 0.75, won: 1, lost: 0 };

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
  await log(null, 'lead.created', 'התקבל ליד חדש מהאתר', rows[0].id);
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

function leadFilters(req, params) {
  const where = [];
  const status = STAGES.includes(req.query.status) ? req.query.status : null;
  const q = String(req.query.q || '').trim();
  const tag = String(req.query.tag || '').trim();
  const assigned = req.query.assigned ? Number(req.query.assigned) : null;
  if (status) { params.push(status); where.push(`l.status=$${params.length}`); }
  if (assigned) { params.push(assigned); where.push(`l.assigned_to=$${params.length}`); }
  if (tag) { params.push(`%${tag}%`); where.push(`l.tags ILIKE $${params.length}`); }
  if (q) { params.push(`%${q}%`); where.push(`(l.name ILIKE $${params.length} OR l.phone ILIKE $${params.length} OR l.email ILIKE $${params.length} OR l.message ILIKE $${params.length} OR l.tags ILIKE $${params.length})`); }
  return where.length ? 'WHERE ' + where.join(' AND ') : '';
}

app.get('/api/leads', auth, async (req, res) => {
  const params = [];
  const whereSql = leadFilters(req, params);
  const { rows } = await pool.query(
    `SELECT l.*, u.name AS assigned_name FROM leads l LEFT JOIN users u ON u.id=l.assigned_to
     ${whereSql} ORDER BY l.created_at DESC LIMIT 1000`, params);
  res.json({ leads: rows });
});

// CSV export of all leads (respects the same filters)
app.get('/api/leads/export.csv', auth, async (req, res) => {
  const params = [];
  const whereSql = leadFilters(req, params);
  const { rows } = await pool.query(
    `SELECT l.id, l.name, l.phone, l.email, l.status, l.value, l.expected_close, l.tags, l.page, l.created_at, u.name AS assigned_name, l.message
     FROM leads l LEFT JOIN users u ON u.id=l.assigned_to ${whereSql} ORDER BY l.created_at DESC`, params);
  const cols = ['id', 'name', 'phone', 'email', 'status', 'value', 'expected_close', 'tags', 'assigned_name', 'page', 'created_at', 'message'];
  const esc = (v) => { const s = v == null ? '' : String(v); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
  const csv = '﻿' + [cols.join(',')].concat(rows.map(r => cols.map(c => esc(r[c])).join(','))).join('\n');
  res.set('Content-Type', 'text/csv; charset=utf-8');
  res.set('Content-Disposition', 'attachment; filename="leads.csv"');
  res.send(csv);
});

app.get('/api/leads/:id', auth, async (req, res) => {
  const id = Number(req.params.id);
  const lead = (await pool.query('SELECT l.*, u.name AS assigned_name FROM leads l LEFT JOIN users u ON u.id=l.assigned_to WHERE l.id=$1', [id])).rows[0];
  if (!lead) return res.status(404).json({ error: 'not found' });
  const notes = (await pool.query('SELECT n.*, u.name AS user_name FROM lead_notes n LEFT JOIN users u ON u.id=n.user_id WHERE n.lead_id=$1 ORDER BY n.id', [id])).rows;
  const messages = (await pool.query('SELECT m.*, u.name AS user_name FROM lead_messages m LEFT JOIN users u ON u.id=m.user_id WHERE m.lead_id=$1 ORDER BY m.id', [id])).rows;
  const activity = (await pool.query('SELECT a.*, u.name AS user_name FROM activity_log a LEFT JOIN users u ON u.id=a.user_id WHERE a.lead_id=$1 ORDER BY a.id DESC LIMIT 100', [id])).rows;
  const tasks = (await pool.query('SELECT t.*, u.name AS user_name FROM tasks t LEFT JOIN users u ON u.id=t.user_id WHERE t.lead_id=$1 ORDER BY t.done, t.due_date NULLS LAST', [id])).rows;
  res.json({ lead, notes, messages, activity, tasks });
});

app.patch('/api/leads/:id', auth, async (req, res) => {
  const id = Number(req.params.id);
  const lead = (await pool.query('SELECT * FROM leads WHERE id=$1', [id])).rows[0];
  if (!lead) return res.status(404).json({ error: 'not found' });
  const status = STAGES.includes(req.body.status) ? req.body.status : lead.status;
  const assigned = req.body.assigned_to === null ? null : (req.body.assigned_to !== undefined ? Number(req.body.assigned_to) : lead.assigned_to);
  const value = req.body.value !== undefined ? Math.max(0, Number(req.body.value) || 0) : lead.value;
  const expected = req.body.expected_close !== undefined ? (req.body.expected_close || null) : lead.expected_close;
  const tags = req.body.tags !== undefined ? String(req.body.tags).trim().slice(0, 300) : lead.tags;
  const { rows } = await pool.query(
    'UPDATE leads SET status=$1, assigned_to=$2, value=$3, expected_close=$4, tags=$5 WHERE id=$6 RETURNING *',
    [status, assigned, value, expected, tags, id]);
  if (status !== lead.status) await log(req.user.id, 'lead.stage', `שלב שונה ל: ${status}`, id);
  else await log(req.user.id, 'lead.updated', 'פרטי ליד עודכנו', id);
  res.json({ lead: rows[0] });
});

app.post('/api/leads/:id/notes', auth, async (req, res) => {
  const id = Number(req.params.id);
  const body = String(req.body.body || '').trim();
  if (!body) return res.status(400).json({ error: 'empty' });
  const { rows } = await pool.query(
    'INSERT INTO lead_notes (lead_id, user_id, body) VALUES ($1,$2,$3) RETURNING *', [id, req.user.id, body]);
  await log(req.user.id, 'lead.note', 'נוספה הערה', id);
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
  const filled = fillTemplate(body, lead);
  const html = isHtml(filled) ? filled : undefined;
  const result = await mail.send({ to: lead.email, subject, text: html ? filled.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim() : filled, html });
  if (!result.sent) return res.status(502).json({ error: 'שליחת המייל נכשלה — ודא שמפתח OneSignal/SMTP מוגדר' });
  await pool.query(
    'INSERT INTO lead_messages (lead_id, user_id, direction, channel, subject, body, delivered) VALUES ($1,$2,\'out\',\'email\',$3,$4,true)',
    [id, req.user.id, subject, body]);
  await log(req.user.id, 'lead.emailed', `מייל נשלח ל-${lead.email}`, id);
  res.json({ ok: true });
});

/* ---------- tasks ---------- */

const TASK_STATUSES = ['open', 'in_progress', 'follow_up', 'done'];

app.get('/api/tasks', auth, async (req, res) => {
  const scope = req.query.scope; // today | overdue | upcoming | open | all
  let cond = 'WHERE NOT t.done';
  if (scope === 'today') cond = `WHERE NOT t.done AND t.due_date::date = now()::date`;
  else if (scope === 'overdue') cond = `WHERE NOT t.done AND t.due_date < now()`;
  else if (scope === 'upcoming') cond = `WHERE NOT t.done AND t.due_date >= now()`;
  else if (scope === 'all') cond = '';
  const { rows } = await pool.query(
    `SELECT t.*, l.name AS lead_name, u.name AS user_name, cu.name AS creator_name
     FROM tasks t
     LEFT JOIN leads l ON l.id=t.lead_id
     LEFT JOIN users u ON u.id=t.user_id
     LEFT JOIN users cu ON cu.id=t.created_by
     ${cond} ORDER BY t.done, t.due_date NULLS LAST LIMIT 500`);
  res.json({ tasks: rows });
});

app.post('/api/tasks', auth, async (req, res) => {
  const title = String(req.body.title || '').trim().slice(0, 300);
  if (!title) return res.status(400).json({ error: 'נדרשת כותרת למשימה' });
  const leadId = req.body.lead_id ? Number(req.body.lead_id) : null;
  const due = req.body.due_date || null;
  const remind = req.body.remind_at || null;
  const status = TASK_STATUSES.includes(req.body.status) ? req.body.status : 'open';
  const assignee = req.body.user_id ? Number(req.body.user_id) : req.user.id;
  const { rows } = await pool.query(
    'INSERT INTO tasks (lead_id, user_id, created_by, title, status, due_date, remind_at) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
    [leadId, assignee, req.user.id, title, status, due, remind]);
  if (leadId) await log(req.user.id, 'task.created', title, leadId);
  res.json({ task: rows[0] });
});

app.patch('/api/tasks/:id', auth, async (req, res) => {
  const id = Number(req.params.id);
  const t = (await pool.query('SELECT * FROM tasks WHERE id=$1', [id])).rows[0];
  if (!t) return res.status(404).json({ error: 'not found' });
  // legacy toggle {done:true} still works; status is the source of truth
  let status = TASK_STATUSES.includes(req.body.status) ? req.body.status
    : (req.body.done !== undefined ? (req.body.done ? 'done' : 'open') : t.status);
  const done = status === 'done';
  const title = req.body.title !== undefined ? String(req.body.title).trim().slice(0, 300) : t.title;
  const due = req.body.due_date !== undefined ? (req.body.due_date || null) : t.due_date;
  const assignee = req.body.user_id !== undefined ? (req.body.user_id ? Number(req.body.user_id) : null) : t.user_id;
  const remind = req.body.remind_at !== undefined ? (req.body.remind_at || null) : t.remind_at;
  // a new/changed reminder time re-arms the reminder
  const reminded = (String(remind) !== String(t.remind_at)) ? false : t.reminded;
  const { rows } = await pool.query(
    `UPDATE tasks SET status=$1, done=$2, done_at=CASE WHEN $2 AND NOT done THEN now() WHEN NOT $2 THEN NULL ELSE done_at END,
       title=$3, due_date=$4, user_id=$5, remind_at=$6, reminded=$7 WHERE id=$8 RETURNING *`,
    [status, done, title, due, assignee, remind, reminded, id]);
  if (assignee !== t.user_id && t.lead_id) await log(req.user.id, 'task.reassigned', title, t.lead_id);
  res.json({ task: rows[0] });
});

app.delete('/api/tasks/:id', auth, async (req, res) => {
  await pool.query('DELETE FROM tasks WHERE id=$1', [Number(req.params.id)]);
  res.json({ ok: true });
});

// reminder poller — every minute, email the assignee for any task whose remind_at has passed
async function processReminders() {
  try {
    const { rows } = await pool.query(
      `SELECT t.*, u.email AS assignee_email, u.name AS assignee_name, l.name AS lead_name
       FROM tasks t LEFT JOIN users u ON u.id=t.user_id LEFT JOIN leads l ON l.id=t.lead_id
       WHERE t.remind_at IS NOT NULL AND NOT t.reminded AND NOT t.done AND t.remind_at <= now() LIMIT 50`);
    for (const t of rows) {
      if (t.assignee_email) {
        await mail.send({
          to: t.assignee_email,
          subject: `תזכורת משימה: ${t.title}`,
          text: `שלום ${t.assignee_name || ''},\nתזכורת למשימה: ${t.title}${t.lead_name ? `\nלקוח: ${t.lead_name}` : ''}${t.due_date ? `\nיעד: ${new Date(t.due_date).toLocaleString('he-IL')}` : ''}\n\nלמערכת: https://led-mls.co.il/admin`,
        });
      }
      await pool.query('UPDATE tasks SET reminded=true WHERE id=$1', [t.id]);
    }
  } catch (e) { console.error('reminder poller failed:', e.message); }
}

/* ---------- email templates + bulk ---------- */

const isHtml = (s) => /<[a-z][\s\S]*>/i.test(String(s || ''));

// {{name}} {{first_name}} — filled from a lead record
function fillTemplate(text, lead) {
  const first = (lead.name || '').split(' ')[0];
  return String(text || '')
    .replace(/\{\{\s*name\s*\}\}/g, lead.name || '')
    .replace(/\{\{\s*first_name\s*\}\}/g, first)
    .replace(/\{\{\s*email\s*\}\}/g, lead.email || '')
    .replace(/\{\{\s*phone\s*\}\}/g, lead.phone || '');
}

app.get('/api/templates', auth, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM email_templates ORDER BY id DESC');
  res.json({ templates: rows });
});

app.post('/api/templates', auth, async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 120);
  const subject = String(req.body.subject || '').trim().slice(0, 200);
  const body = String(req.body.body || '').trim().slice(0, 8000);
  if (!name) return res.status(400).json({ error: 'נדרש שם לתבנית' });
  const { rows } = await pool.query('INSERT INTO email_templates (name, subject, body) VALUES ($1,$2,$3) RETURNING *', [name, subject, body]);
  res.json({ template: rows[0] });
});

app.patch('/api/templates/:id', auth, async (req, res) => {
  const id = Number(req.params.id);
  const t = (await pool.query('SELECT * FROM email_templates WHERE id=$1', [id])).rows[0];
  if (!t) return res.status(404).json({ error: 'not found' });
  const name = req.body.name !== undefined ? String(req.body.name).trim().slice(0, 120) : t.name;
  const subject = req.body.subject !== undefined ? String(req.body.subject).trim().slice(0, 200) : t.subject;
  const body = req.body.body !== undefined ? String(req.body.body).trim().slice(0, 8000) : t.body;
  const { rows } = await pool.query('UPDATE email_templates SET name=$1, subject=$2, body=$3 WHERE id=$4 RETURNING *', [name, subject, body, id]);
  res.json({ template: rows[0] });
});

app.delete('/api/templates/:id', auth, async (req, res) => {
  await pool.query('DELETE FROM email_templates WHERE id=$1', [Number(req.params.id)]);
  res.json({ ok: true });
});

// send one template (or ad-hoc subject/body) to many leads at once
app.post('/api/leads/bulk-email', auth, async (req, res) => {
  const ids = Array.isArray(req.body.lead_ids) ? req.body.lead_ids.map(Number).filter(Boolean) : [];
  let subject = String(req.body.subject || '').trim();
  let body = String(req.body.body || '').trim();
  if (req.body.template_id) {
    const t = (await pool.query('SELECT * FROM email_templates WHERE id=$1', [Number(req.body.template_id)])).rows[0];
    if (t) { subject = subject || t.subject; body = body || t.body; }
  }
  if (!ids.length) return res.status(400).json({ error: 'לא נבחרו לידים' });
  if (!subject || !body) return res.status(400).json({ error: 'נדרשים נושא ותוכן' });
  const { rows: leads } = await pool.query('SELECT * FROM leads WHERE id = ANY($1) AND email <> \'\'', [ids]);
  let sent = 0, failed = 0, skipped = ids.length - leads.length;
  for (const lead of leads) {
    const filled = fillTemplate(body, lead);
    const html = isHtml(filled) ? filled : undefined;
    const r = await mail.send({ to: lead.email, subject: fillTemplate(subject, lead), text: html ? filled.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim() : filled, html });
    if (r.sent) {
      sent++;
      await pool.query('INSERT INTO lead_messages (lead_id, user_id, direction, channel, subject, body, delivered) VALUES ($1,$2,\'out\',\'email\',$3,$4,true)',
        [lead.id, req.user.id, fillTemplate(subject, lead), fillTemplate(body, lead)]);
      await log(req.user.id, 'lead.emailed', 'דיוור המוני', lead.id);
    } else failed++;
  }
  res.json({ ok: true, sent, failed, skipped });
});

/* ---------- quotes → work orders ---------- */

const QUOTE_STATUSES = ['draft', 'sent', 'accepted', 'rejected', 'ordered'];
const nis = (n) => '₪' + Number(n || 0).toLocaleString('he-IL', { maximumFractionDigits: 2 });

const clampPct = (n) => Math.min(100, Math.max(0, Number(n) || 0));
// subtotal = sum of line nets (after per-line discount); discount = global discount amount
function quoteTotals(items, vatRate, discType, discVal) {
  const list = Array.isArray(items) ? items : [];
  const subtotal = list.reduce((s, it) => {
    const line = (Number(it.qty) || 0) * (Number(it.price) || 0);
    return s + line * (1 - clampPct(it.disc) / 100);
  }, 0);
  let discount = discType === 'percent' ? subtotal * clampPct(discVal) / 100 : Math.max(0, Number(discVal) || 0);
  discount = Math.min(discount, subtotal);
  const afterDisc = subtotal - discount;
  const vat = afterDisc * (Number(vatRate) || 0) / 100;
  return { subtotal, discount, vat, total: afterDisc + vat };
}
function cleanItems(items) {
  // `cost` is kept for internal margin analysis only — quoteDocHtml never renders it to the client
  return (Array.isArray(items) ? items : []).slice(0, 50)
    .map(it => ({ desc: String(it.desc || '').slice(0, 300), qty: Number(it.qty) || 0, price: Number(it.price) || 0, cost: Number(it.cost) || 0, disc: clampPct(it.disc) }))
    .filter(it => it.desc || it.qty || it.price);
}

// full RTL HTML document — used both for the printable page and the emailed quote
function quoteDocHtml(q, forPrint) {
  const isOrder = q.status === 'ordered' && q.order_number;
  const docTitle = isOrder ? `הזמנת עבודה מס׳ ${q.order_number}` : `הצעת מחיר מס׳ ${q.number}`;
  const items = Array.isArray(q.items) ? q.items : [];
  const anyDisc = items.some(it => (Number(it.disc) || 0) > 0);
  const rows = items.map(it => {
    const line = (Number(it.qty) || 0) * (Number(it.price) || 0);
    const disc = Number(it.disc) || 0;
    const net = line * (1 - disc / 100);
    return `<tr>
      <td style="padding:12px 14px;border-top:1px solid #eee">${(it.desc || '').replace(/</g, '&lt;')}</td>
      <td style="padding:12px 14px;border-top:1px solid #eee;text-align:center">${it.qty || 0}</td>
      <td style="padding:12px 14px;border-top:1px solid #eee">${nis(it.price)}</td>
      ${anyDisc ? `<td style="padding:12px 14px;border-top:1px solid #eee;text-align:center">${disc > 0 ? disc + '%' : '—'}</td>` : ''}
      <td style="padding:12px 14px;border-top:1px solid #eee;font-weight:600">${nis(net)}</td></tr>`;
  }).join('');
  const dt = (d) => d ? new Date(d).toLocaleDateString('he-IL') : '';
  return `<!doctype html><html dir="rtl" lang="he"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${docTitle} — MLS ישראל</title>
<style>
  body{margin:0;background:#f4f4f6;font-family:'Segoe UI',Arial,sans-serif;color:#1d1d1f}
  .doc{max-width:720px;margin:24px auto;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 6px 24px rgba(0,0,0,.06)}
  .doc-head{background:#0a0603;padding:24px 30px;display:flex;align-items:center;justify-content:space-between}
  .doc-head img{height:46px}
  .doc-head .num{color:#fff;text-align:end}
  .doc-head .num b{color:#FF6A1A;font-size:1.1rem;display:block}
  .doc-body{padding:30px}
  h1{font-size:1.6rem;margin:0 0 4px}
  .meta{color:#666;font-size:.9rem;margin-bottom:22px}
  .party{background:#faf7f4;border-radius:12px;padding:14px 16px;margin-bottom:22px;font-size:.92rem}
  table{width:100%;border-collapse:collapse;font-size:.92rem;border:1px solid #eee;border-radius:12px;overflow:hidden}
  th{background:#faf7f4;padding:12px 14px;text-align:start;font-size:.8rem;color:#666}
  .totals{margin-top:18px;margin-inline-start:auto;width:280px;font-size:.95rem}
  .totals div{display:flex;justify-content:space-between;padding:6px 0}
  .totals .grand{border-top:2px solid #FF6A1A;margin-top:6px;padding-top:10px;font-weight:800;font-size:1.15rem;color:#FF6A1A}
  .notes{margin-top:22px;font-size:.88rem;color:#555;line-height:1.6;white-space:pre-wrap}
  .doc-foot{background:#faf7f4;padding:18px 30px;text-align:center;color:#8a8a8f;font-size:.82rem;border-top:1px solid #eee}
  .printbtn{display:block;width:max-content;margin:16px auto;background:#FF6A1A;color:#fff;border:none;border-radius:980px;padding:10px 26px;font-size:.95rem;cursor:pointer;text-decoration:none}
  @media print{body{background:#fff}.doc{box-shadow:none;margin:0;max-width:100%}.printbtn{display:none}}
</style></head><body>
<div class="doc">
  <div class="doc-head"><img src="https://led-mls.co.il/assets/images/logo.png" alt="MLS ישראל"><div class="num"><span>${isOrder ? 'הזמנת עבודה' : 'הצעת מחיר'}</span><b>מס׳ ${isOrder ? q.order_number : q.number}</b></div></div>
  <div class="doc-body">
    <h1>${(q.title || docTitle).replace(/</g, '&lt;')}</h1>
    <div class="meta">תאריך: ${dt(q.created_at)}${q.valid_until && !isOrder ? ` · בתוקף עד: ${dt(q.valid_until)}` : ''}${isOrder ? ` · אושרה: ${dt(q.ordered_at)} · הצעה מקורית מס׳ ${q.number}` : ''}</div>
    <div class="party"><b>לכבוד:</b> ${(q.lead_name || '').replace(/</g, '&lt;')}${q.lead_phone ? ' · ' + q.lead_phone : ''}${q.lead_email ? ' · ' + q.lead_email : ''}</div>
    <table><thead><tr><th>פריט</th><th style="text-align:center">כמות</th><th>מחיר יח׳</th>${anyDisc ? '<th style="text-align:center">הנחה</th>' : ''}<th>סה״כ</th></tr></thead>
    <tbody>${rows || `<tr><td colspan="${anyDisc ? 5 : 4}" style="padding:14px;color:#999">אין פריטים</td></tr>`}</tbody></table>
    <div class="totals">
      <div><span>סכום ביניים (לפני מע״מ)</span><span>${nis(q.subtotal)}</span></div>
      ${Number(q.discount) > 0 ? `<div style="color:#217A3B"><span>הנחה${q.discount_type === 'percent' ? ` (${Number(q.discount_value)}%)` : ''}</span><span>-${nis(q.discount)}</span></div>` : ''}
      <div><span>מע״מ (${Number(q.vat_rate)}%)</span><span>${nis(q.vat)}</span></div>
      <div class="grand"><span>סה״כ לתשלום</span><span>${nis(q.total)}</span></div>
    </div>
    ${q.notes ? `<div class="notes">${String(q.notes).replace(/</g, '&lt;')}</div>` : ''}
  </div>
  <div class="doc-foot">MLS ישראל · מסכי LED מקצועיים · 058-500-8500 · led-mls.co.il</div>
</div>
${forPrint ? '<a class="printbtn" href="#" onclick="window.print();return false">🖨️ הדפסה / שמירה כ-PDF</a>' : ''}
</body></html>`;
}

app.get('/api/quotes', auth, async (req, res) => {
  const status = QUOTE_STATUSES.includes(req.query.status) ? req.query.status : null;
  const params = []; let where = '';
  if (status) { params.push(status); where = 'WHERE q.status=$1'; }
  const { rows } = await pool.query(
    `SELECT q.*, l.name AS lead_name FROM quotes q LEFT JOIN leads l ON l.id=q.lead_id ${where} ORDER BY q.created_at DESC LIMIT 500`, params);
  res.json({ quotes: rows });
});

app.get('/api/quotes/:id', auth, async (req, res) => {
  const q = (await pool.query('SELECT q.*, l.name AS lead_name, l.email AS lead_email, l.phone AS lead_phone FROM quotes q LEFT JOIN leads l ON l.id=q.lead_id WHERE q.id=$1', [Number(req.params.id)])).rows[0];
  if (!q) return res.status(404).json({ error: 'not found' });
  res.json({ quote: q });
});

app.post('/api/quotes', auth, async (req, res) => {
  const leadId = req.body.lead_id ? Number(req.body.lead_id) : null;
  const title = String(req.body.title || '').trim().slice(0, 200);
  const items = cleanItems(req.body.items);
  const vatRate = req.body.vat_rate !== undefined ? (Number(req.body.vat_rate) || 0) : 18;
  const notes = String(req.body.notes || '').slice(0, 2000);
  const valid = req.body.valid_until || null;
  const discType = req.body.discount_type === 'percent' ? 'percent' : 'amount';
  const discVal = Math.max(0, Number(req.body.discount_value) || 0);
  const { subtotal, discount, vat, total } = quoteTotals(items, vatRate, discType, discVal);
  const number = await nextSerial('quote');
  const { rows } = await pool.query(
    `INSERT INTO quotes (number, lead_id, created_by, title, items, vat_rate, discount_type, discount_value, discount, subtotal, vat, total, notes, valid_until)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *`,
    [number, leadId, req.user.id, title, JSON.stringify(items), vatRate, discType, discVal, discount, subtotal, vat, total, notes, valid]);
  if (leadId) await log(req.user.id, 'quote.created', `הצעת מחיר נוצרה (מס׳ ${number})`, leadId);
  res.json({ quote: rows[0] });
});

app.patch('/api/quotes/:id', auth, async (req, res) => {
  const id = Number(req.params.id);
  const q = (await pool.query('SELECT * FROM quotes WHERE id=$1', [id])).rows[0];
  if (!q) return res.status(404).json({ error: 'not found' });
  const title = req.body.title !== undefined ? String(req.body.title).slice(0, 200) : q.title;
  const items = req.body.items !== undefined ? cleanItems(req.body.items) : q.items;
  const vatRate = req.body.vat_rate !== undefined ? (Number(req.body.vat_rate) || 0) : Number(q.vat_rate);
  const notes = req.body.notes !== undefined ? String(req.body.notes).slice(0, 2000) : q.notes;
  const valid = req.body.valid_until !== undefined ? (req.body.valid_until || null) : q.valid_until;
  const status = QUOTE_STATUSES.includes(req.body.status) ? req.body.status : q.status;
  const discType = req.body.discount_type !== undefined ? (req.body.discount_type === 'percent' ? 'percent' : 'amount') : q.discount_type;
  const discVal = req.body.discount_value !== undefined ? Math.max(0, Number(req.body.discount_value) || 0) : Number(q.discount_value);
  const { subtotal, discount, vat, total } = quoteTotals(items, vatRate, discType, discVal);
  const { rows } = await pool.query(
    `UPDATE quotes SET title=$1, items=$2, vat_rate=$3, discount_type=$4, discount_value=$5, discount=$6, subtotal=$7, vat=$8, total=$9, notes=$10, valid_until=$11, status=$12 WHERE id=$13 RETURNING *`,
    [title, JSON.stringify(items), vatRate, discType, discVal, discount, subtotal, vat, total, notes, valid, status, id]);
  res.json({ quote: rows[0] });
});

app.delete('/api/quotes/:id', auth, async (req, res) => {
  await pool.query('DELETE FROM quotes WHERE id=$1', [Number(req.params.id)]);
  res.json({ ok: true });
});

app.post('/api/quotes/:id/send', auth, async (req, res) => {
  const id = Number(req.params.id);
  const q = (await pool.query('SELECT q.*, l.name AS lead_name, l.email AS lead_email, l.phone AS lead_phone FROM quotes q LEFT JOIN leads l ON l.id=q.lead_id WHERE q.id=$1', [id])).rows[0];
  if (!q) return res.status(404).json({ error: 'not found' });
  if (!q.lead_email) return res.status(400).json({ error: 'ללקוח אין כתובת מייל' });
  const result = await mail.send({ to: q.lead_email, subject: `הצעת מחיר מס׳ ${q.number} — MLS ישראל`, text: `הצעת מחיר מס׳ ${q.number}. סה״כ לתשלום: ${nis(q.total)}.`, html: quoteDocHtml(q, false) });
  if (!result.sent) return res.status(502).json({ error: 'שליחת המייל נכשלה — ודא שמפתח OneSignal מוגדר' });
  await pool.query(`UPDATE quotes SET status=CASE WHEN status='draft' THEN 'sent' ELSE status END, sent_at=now() WHERE id=$1`, [id]);
  if (q.lead_id) {
    await pool.query('INSERT INTO lead_messages (lead_id,user_id,direction,channel,subject,body,delivered) VALUES ($1,$2,\'out\',\'email\',$3,$4,true)', [q.lead_id, req.user.id, `הצעת מחיר ${q.number}`, `הצעת מחיר על סך ${nis(q.total)} נשלחה`]);
    await log(req.user.id, 'quote.sent', `הצעת מחיר ${q.number} נשלחה ל-${q.lead_email}`, q.lead_id);
    await pool.query(`UPDATE leads SET status='quoted' WHERE id=$1 AND status IN ('new','contacted')`, [q.lead_id]);
  }
  res.json({ ok: true });
});

app.post('/api/quotes/:id/convert', auth, async (req, res) => {
  const id = Number(req.params.id);
  const q = (await pool.query('SELECT * FROM quotes WHERE id=$1', [id])).rows[0];
  if (!q) return res.status(404).json({ error: 'not found' });
  if (q.order_number) return res.status(400).json({ error: 'ההצעה כבר הומרה להזמנת עבודה מס׳ ' + q.order_number });
  const orderNum = await nextSerial('order');
  const { rows } = await pool.query(`UPDATE quotes SET status='ordered', order_number=$1, ordered_at=now() WHERE id=$2 RETURNING *`, [orderNum, id]);
  if (q.lead_id) {
    await log(req.user.id, 'quote.ordered', `הצעה ${q.number} הומרה להזמנת עבודה מס׳ ${orderNum}`, q.lead_id);
    await pool.query(`UPDATE leads SET status='won' WHERE id=$1`, [q.lead_id]);
  }
  res.json({ quote: rows[0] });
});

app.get('/api/quotes/:id/print', auth, async (req, res) => {
  const q = (await pool.query('SELECT q.*, l.name AS lead_name, l.email AS lead_email, l.phone AS lead_phone FROM quotes q LEFT JOIN leads l ON l.id=q.lead_id WHERE q.id=$1', [Number(req.params.id)])).rows[0];
  if (!q) return res.status(404).send('not found');
  res.set('Content-Type', 'text/html; charset=utf-8');
  res.send(quoteDocHtml(q, true));
});

/* ---------- price catalog: departments + items ---------- */

app.get('/api/departments', auth, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM departments ORDER BY name');
  res.json({ departments: rows });
});
app.post('/api/departments', auth, async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 120);
  if (!name) return res.status(400).json({ error: 'נדרש שם מחלקה' });
  const { rows } = await pool.query('INSERT INTO departments (name) VALUES ($1) RETURNING *', [name]);
  res.json({ department: rows[0] });
});
app.patch('/api/departments/:id', auth, async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 120);
  const { rows } = await pool.query('UPDATE departments SET name=$1 WHERE id=$2 RETURNING *', [name, Number(req.params.id)]);
  if (!rows[0]) return res.status(404).json({ error: 'not found' });
  res.json({ department: rows[0] });
});
app.delete('/api/departments/:id', auth, async (req, res) => {
  await pool.query('DELETE FROM departments WHERE id=$1', [Number(req.params.id)]);
  res.json({ ok: true });
});

app.get('/api/catalog', auth, async (req, res) => {
  const params = []; let where = '';
  if (req.query.department_id) { params.push(Number(req.query.department_id)); where = 'WHERE c.department_id=$1'; }
  const { rows } = await pool.query(
    `SELECT c.*, d.name AS department_name FROM catalog_items c LEFT JOIN departments d ON d.id=c.department_id ${where} ORDER BY d.name NULLS LAST, c.name`, params);
  res.json({ items: rows });
});
app.post('/api/catalog', auth, async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 200);
  if (!name) return res.status(400).json({ error: 'נדרש שם פריט' });
  const dept = req.body.department_id ? Number(req.body.department_id) : null;
  const sku = String(req.body.sku || '').slice(0, 60);
  const unit = String(req.body.unit || '').slice(0, 40);
  const cost = Math.max(0, Number(req.body.cost_price) || 0);
  const sale = Math.max(0, Number(req.body.sale_price) || 0);
  const { rows } = await pool.query(
    'INSERT INTO catalog_items (department_id, name, sku, unit, cost_price, sale_price) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
    [dept, name, sku, unit, cost, sale]);
  res.json({ item: rows[0] });
});
app.patch('/api/catalog/:id', auth, async (req, res) => {
  const id = Number(req.params.id);
  const c = (await pool.query('SELECT * FROM catalog_items WHERE id=$1', [id])).rows[0];
  if (!c) return res.status(404).json({ error: 'not found' });
  const name = req.body.name !== undefined ? String(req.body.name).trim().slice(0, 200) : c.name;
  const dept = req.body.department_id !== undefined ? (req.body.department_id ? Number(req.body.department_id) : null) : c.department_id;
  const sku = req.body.sku !== undefined ? String(req.body.sku).slice(0, 60) : c.sku;
  const unit = req.body.unit !== undefined ? String(req.body.unit).slice(0, 40) : c.unit;
  const cost = req.body.cost_price !== undefined ? Math.max(0, Number(req.body.cost_price) || 0) : c.cost_price;
  const sale = req.body.sale_price !== undefined ? Math.max(0, Number(req.body.sale_price) || 0) : c.sale_price;
  const active = req.body.is_active !== undefined ? !!req.body.is_active : c.is_active;
  const { rows } = await pool.query(
    'UPDATE catalog_items SET department_id=$1, name=$2, sku=$3, unit=$4, cost_price=$5, sale_price=$6, is_active=$7 WHERE id=$8 RETURNING *',
    [dept, name, sku, unit, cost, sale, active, id]);
  res.json({ item: rows[0] });
});
app.delete('/api/catalog/:id', auth, async (req, res) => {
  await pool.query('DELETE FROM catalog_items WHERE id=$1', [Number(req.params.id)]);
  res.json({ ok: true });
});

/* ---------- dashboard stats + ui ---------- */

app.get('/api/stats', auth, async (req, res) => {
  const byStatusRows = (await pool.query(`SELECT status, COUNT(*)::int AS n FROM leads GROUP BY status`)).rows;
  const byStatus = Object.fromEntries(byStatusRows.map(r => [r.status, r.n]));
  const total = (await pool.query('SELECT COUNT(*)::int AS n FROM leads')).rows[0].n;
  const week = (await pool.query(`SELECT COUNT(*)::int AS n FROM leads WHERE created_at > now() - interval '7 days'`)).rows[0].n;
  const valRow = (await pool.query(
    `SELECT
       COALESCE(SUM(value) FILTER (WHERE status = ANY($1)),0)::float AS pipeline_value,
       COALESCE(SUM(value) FILTER (WHERE status='won'),0)::float AS won_value
     FROM leads`, [OPEN_STAGES])).rows[0];
  // weighted forecast across open stages
  const openRows = (await pool.query(`SELECT status, COALESCE(SUM(value),0)::float AS v FROM leads WHERE status = ANY($1) GROUP BY status`, [OPEN_STAGES])).rows;
  const forecast = openRows.reduce((s, r) => s + r.v * (STAGE_WEIGHT[r.status] || 0), 0);
  const tasksToday = (await pool.query(`SELECT COUNT(*)::int AS n FROM tasks WHERE NOT done AND due_date::date = now()::date`)).rows[0].n;
  const tasksOverdue = (await pool.query(`SELECT COUNT(*)::int AS n FROM tasks WHERE NOT done AND due_date < now()`)).rows[0].n;
  // last 14 days of new leads for a trend sparkline
  const trend = (await pool.query(
    `SELECT to_char(d::date,'YYYY-MM-DD') AS day, COUNT(l.id)::int AS n
     FROM generate_series(now()::date - interval '13 days', now()::date, interval '1 day') d
     LEFT JOIN leads l ON l.created_at::date = d::date
     GROUP BY d ORDER BY d`)).rows;
  const wonCount = byStatus.won || 0;
  const lostCount = byStatus.lost || 0;
  const winRate = (wonCount + lostCount) ? Math.round(wonCount * 100 / (wonCount + lostCount)) : 0;
  const quotesOpen = (await pool.query(`SELECT COUNT(*)::int AS n FROM quotes WHERE status IN ('draft','sent','accepted')`)).rows[0].n;
  const ordersRow = (await pool.query(`SELECT COUNT(*)::int AS n, COALESCE(SUM(total),0)::float AS v FROM quotes WHERE status='ordered'`)).rows[0];
  res.json({ total, week, byStatus, pipelineValue: valRow.pipeline_value, wonValue: valRow.won_value, forecast, tasksToday, tasksOverdue, winRate, trend, quotesOpen, ordersCount: ordersRow.n, ordersValue: ordersRow.v });
});

app.use('/admin', express.static(path.join(__dirname, 'public'), { index: 'index.html' }));
app.get('/api/health', (req, res) => res.json({ ok: true }));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'internal error' });
});

init().then(() => {
  app.listen(PORT, () => console.log(`MLS admin API listening on :${PORT} (smtp configured: ${mail.configured})`));
  setInterval(processReminders, 60 * 1000); // task reminders
}).catch((e) => { console.error('DB init failed:', e); process.exit(1); });
