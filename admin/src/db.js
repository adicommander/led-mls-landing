const { Pool, Client } = require('pg');
const bcrypt = require('bcryptjs');

// Strip sslmode from the URL so our explicit ssl config below always wins
// (pg >= 8.12 lets a URL sslmode override the config object).
const rawUrl = process.env.DATABASE_URL || '';
const connectionString = rawUrl.replace(/([?&])sslmode=[^&]*&?/, '$1').replace(/[?&]$/, '');
const ssl = rawUrl.includes('localhost')
  ? false
  : process.env.DB_CA_CERT
    ? { ca: process.env.DB_CA_CERT }
    : { rejectUnauthorized: false };

// PG 15+ blocks CREATE in schema public for non-owner users, and DO dev
// databases restrict CREATE SCHEMA too — so at boot we probe for a schema the
// app user can actually write to, and route every connection there.
let appSchema = 'public';
const pool = new Pool({ connectionString, ssl });
pool.on('connect', (client) => {
  client.query(`SET search_path TO "${appSchema}", public`).catch(() => {});
});

async function resolveSchema() {
  const probe = new Client({ connectionString, ssl });
  await probe.connect();
  try {
    const who = await probe.query('SELECT current_user, current_database()');
    console.log('DB user/database:', JSON.stringify(who.rows[0]));
    const { rows } = await probe.query(`
      SELECT nspname FROM pg_namespace
      WHERE has_schema_privilege(current_user, oid, 'CREATE')
        AND nspname NOT LIKE 'pg\\_%' AND nspname <> 'information_schema'
      ORDER BY (nspname = 'app') DESC, (nspname = current_user) DESC, (nspname = 'public') DESC`);
    console.log('Writable schemas:', rows.map(r => r.nspname).join(', ') || '(none)');
    if (rows.length) return rows[0].nspname;
    await probe.query('CREATE SCHEMA IF NOT EXISTS app');
    return 'app';
  } finally {
    await probe.end();
  }
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL DEFAULT '',
  first_name TEXT NOT NULL DEFAULT '',
  last_name TEXT NOT NULL DEFAULT '',
  phone TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'agent' CHECK (role IN ('admin','agent')),
  is_active BOOLEAN NOT NULL DEFAULT true,
  must_change_password BOOLEAN NOT NULL DEFAULT false,
  failed_attempts INT NOT NULL DEFAULT 0,
  locked_until TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS login_codes (
  id SERIAL PRIMARY KEY,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  attempts INT NOT NULL DEFAULT 0,
  expires_at TIMESTAMPTZ NOT NULL,
  used BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS leads (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  phone TEXT NOT NULL DEFAULT '',
  email TEXT NOT NULL DEFAULT '',
  message TEXT NOT NULL DEFAULT '',
  page TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new','contacted','quoted','negotiation','won','lost')),
  value NUMERIC NOT NULL DEFAULT 0,
  expected_close DATE,
  city TEXT NOT NULL DEFAULT '',
  tags TEXT NOT NULL DEFAULT '',
  inquiries INT NOT NULL DEFAULT 1,
  assigned_to INT REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS lead_notes (
  id SERIAL PRIMARY KEY,
  lead_id INT NOT NULL REFERENCES leads(id) ON DELETE CASCADE,
  user_id INT REFERENCES users(id) ON DELETE SET NULL,
  body TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS lead_inquiries (
  id SERIAL PRIMARY KEY,
  lead_id INT NOT NULL REFERENCES leads(id) ON DELETE CASCADE,
  message TEXT NOT NULL DEFAULT '',
  city TEXT NOT NULL DEFAULT '',
  tags TEXT NOT NULL DEFAULT '',
  page TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_inq_lead ON lead_inquiries(lead_id);
CREATE TABLE IF NOT EXISTS lead_messages (
  id SERIAL PRIMARY KEY,
  lead_id INT NOT NULL REFERENCES leads(id) ON DELETE CASCADE,
  user_id INT REFERENCES users(id) ON DELETE SET NULL,
  direction TEXT NOT NULL DEFAULT 'out' CHECK (direction IN ('out','in')),
  channel TEXT NOT NULL DEFAULT 'email',
  subject TEXT NOT NULL DEFAULT '',
  body TEXT NOT NULL,
  delivered BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS activity_log (
  id SERIAL PRIMARY KEY,
  user_id INT REFERENCES users(id) ON DELETE SET NULL,
  lead_id INT REFERENCES leads(id) ON DELETE CASCADE,
  action TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS tasks (
  id SERIAL PRIMARY KEY,
  lead_id INT REFERENCES leads(id) ON DELETE CASCADE,
  user_id INT REFERENCES users(id) ON DELETE SET NULL,
  created_by INT REFERENCES users(id) ON DELETE SET NULL,
  title TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','in_progress','follow_up','done')),
  due_date TIMESTAMPTZ,
  remind_at TIMESTAMPTZ,
  reminded BOOLEAN NOT NULL DEFAULT false,
  done BOOLEAN NOT NULL DEFAULT false,
  done_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS email_templates (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  subject TEXT NOT NULL DEFAULT '',
  body TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS counters (
  key TEXT PRIMARY KEY,
  val INT NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS quotes (
  id SERIAL PRIMARY KEY,
  number TEXT UNIQUE NOT NULL,
  lead_id INT REFERENCES leads(id) ON DELETE SET NULL,
  created_by INT REFERENCES users(id) ON DELETE SET NULL,
  title TEXT NOT NULL DEFAULT '',
  items JSONB NOT NULL DEFAULT '[]',
  vat_rate NUMERIC NOT NULL DEFAULT 18,
  discount_type TEXT NOT NULL DEFAULT 'amount',
  discount_value NUMERIC NOT NULL DEFAULT 0,
  discount NUMERIC NOT NULL DEFAULT 0,
  subtotal NUMERIC NOT NULL DEFAULT 0,
  vat NUMERIC NOT NULL DEFAULT 0,
  total NUMERIC NOT NULL DEFAULT 0,
  notes TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','sent','accepted','rejected','ordered')),
  valid_until DATE,
  order_number TEXT,
  ordered_at TIMESTAMPTZ,
  sent_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_quotes_lead ON quotes(lead_id);
CREATE INDEX IF NOT EXISTS idx_quotes_created ON quotes(created_at DESC);
CREATE TABLE IF NOT EXISTS departments (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS catalog_items (
  id SERIAL PRIMARY KEY,
  department_id INT REFERENCES departments(id) ON DELETE SET NULL,
  name TEXT NOT NULL,
  sku TEXT NOT NULL DEFAULT '',
  unit TEXT NOT NULL DEFAULT '',
  cost_price NUMERIC NOT NULL DEFAULT 0,
  sale_price NUMERIC NOT NULL DEFAULT 0,
  is_active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_catalog_dept ON catalog_items(department_id);
CREATE INDEX IF NOT EXISTS idx_leads_status ON leads(status);
CREATE INDEX IF NOT EXISTS idx_leads_created ON leads(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_tasks_due ON tasks(due_date) WHERE NOT done;
CREATE INDEX IF NOT EXISTS idx_tasks_lead ON tasks(lead_id);
`;

async function init() {
  appSchema = await resolveSchema();
  console.log(`Using schema "${appSchema}" for app tables.`);
  await pool.query(SCHEMA);
  // migrations for databases created before these columns existed
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS first_name TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_name TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT NOT NULL DEFAULT ''`);
  await pool.query(`
    UPDATE users SET
      first_name = split_part(name, ' ', 1),
      last_name = ltrim(substr(name, length(split_part(name, ' ', 1)) + 1))
    WHERE first_name = '' AND last_name = '' AND name <> ''`);
  // CRM migrations for databases created before the pipeline expansion
  await pool.query(`ALTER TABLE leads ADD COLUMN IF NOT EXISTS value NUMERIC NOT NULL DEFAULT 0`);
  await pool.query(`ALTER TABLE leads ADD COLUMN IF NOT EXISTS expected_close DATE`);
  await pool.query(`ALTER TABLE leads ADD COLUMN IF NOT EXISTS tags TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE leads ADD COLUMN IF NOT EXISTS city TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE leads ADD COLUMN IF NOT EXISTS inquiries INT NOT NULL DEFAULT 1`);
  // backfill one inquiry row per existing lead (from its own submission) so the tree always shows the original
  await pool.query(`INSERT INTO lead_inquiries (lead_id, message, city, tags, page, created_at)
    SELECT id, message, city, tags, page, created_at FROM leads l
    WHERE NOT EXISTS (SELECT 1 FROM lead_inquiries i WHERE i.lead_id = l.id)`);
  await pool.query(`ALTER TABLE activity_log ADD COLUMN IF NOT EXISTS lead_id INT`);
  // expand the pipeline stages: map legacy 'in_progress' -> 'contacted', then widen the CHECK
  await pool.query(`ALTER TABLE leads DROP CONSTRAINT IF EXISTS leads_status_check`);
  await pool.query(`UPDATE leads SET status='contacted' WHERE status='in_progress'`);
  await pool.query(`ALTER TABLE leads ADD CONSTRAINT leads_status_check CHECK (status IN ('new','contacted','quoted','negotiation','won','lost'))`);
  // task workflow migrations: creator, status, reminders
  await pool.query(`ALTER TABLE tasks ADD COLUMN IF NOT EXISTS created_by INT`);
  await pool.query(`ALTER TABLE tasks ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'open'`);
  await pool.query(`ALTER TABLE tasks ADD COLUMN IF NOT EXISTS remind_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE tasks ADD COLUMN IF NOT EXISTS reminded BOOLEAN NOT NULL DEFAULT false`);
  await pool.query(`UPDATE tasks SET status = CASE WHEN done THEN 'done' ELSE 'open' END WHERE status IS NULL OR status=''`);
  await pool.query(`ALTER TABLE tasks DROP CONSTRAINT IF EXISTS tasks_status_check`);
  await pool.query(`ALTER TABLE tasks ADD CONSTRAINT tasks_status_check CHECK (status IN ('open','in_progress','follow_up','done'))`);
  await pool.query(`ALTER TABLE quotes ADD COLUMN IF NOT EXISTS discount_type TEXT NOT NULL DEFAULT 'amount'`);
  await pool.query(`ALTER TABLE quotes ADD COLUMN IF NOT EXISTS discount_value NUMERIC NOT NULL DEFAULT 0`);
  await pool.query(`ALTER TABLE quotes ADD COLUMN IF NOT EXISTS discount NUMERIC NOT NULL DEFAULT 0`);
  await seedTemplates();
  const { rows } = await pool.query('SELECT COUNT(*)::int AS n FROM users');
  if (rows[0].n === 0) {
    const email = (process.env.SEED_ADMIN_EMAIL || '').toLowerCase().trim();
    const password = process.env.SEED_ADMIN_PASSWORD || '';
    if (!email || !password) {
      console.warn('No users exist and SEED_ADMIN_EMAIL/SEED_ADMIN_PASSWORD are not set — admin cannot log in.');
      return;
    }
    const hash = await bcrypt.hash(password, 12);
    await pool.query(
      `INSERT INTO users (email, name, password_hash, role, must_change_password)
       VALUES ($1, $2, $3, 'admin', true)`,
      [email, 'מנהל ראשי', hash]
    );
    console.log(`Seeded initial admin user ${email} (must change password on first login).`);
  }
}

// ---- seeded, professionally designed RTL HTML email templates ----
const LOGO = 'https://led-mls.co.il/assets/images/logo.png';
const SITE = 'https://led-mls.co.il';
const ORANGE = '#FF6A1A';
const shell = (inner) => `<div dir="rtl" style="margin:0;background:#f4f4f6;padding:24px 0;font-family:'Segoe UI',Arial,sans-serif;color:#1d1d1f">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="width:600px;max-width:94%;background:#ffffff;border-radius:18px;overflow:hidden;box-shadow:0 6px 24px rgba(0,0,0,.06)">
<tr><td style="background:#0a0603;padding:22px 28px" align="center">
<img src="${LOGO}" alt="MLS ישראל" width="120" style="display:block;height:auto">
</td></tr>
${inner}
<tr><td style="background:#faf7f4;padding:20px 28px;border-top:1px solid #eee" align="center">
<p style="margin:0;font-size:13px;color:#8a8a8f">MLS ישראל · מסכי LED מקצועיים · <a href="tel:+972549494948" style="color:${ORANGE};text-decoration:none">054-949-4948</a> · <a href="${SITE}" style="color:${ORANGE};text-decoration:none">led-mls.co.il</a></p>
</td></tr>
</table></td></tr></table></div>`;

const TEMPLATES_SEED = [
  {
    name: 'הצעת מחיר',
    subject: 'הצעת מחיר למסך LED — MLS ישראל',
    body: shell(`<tr><td style="padding:32px 28px 8px">
<p style="margin:0 0 6px;font-size:15px">שלום {{first_name}},</p>
<h1 style="margin:0 0 8px;font-size:26px;font-weight:800;letter-spacing:-.5px">הצעת מחיר</h1>
<p style="margin:0 0 20px;font-size:15px;color:#555;line-height:1.6">תודה על פנייתך. להלן הצעת מחיר מותאמת לצרכים שסיכמנו:</p>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #eee;border-radius:12px;overflow:hidden;font-size:14px">
<tr style="background:#faf7f4"><td style="padding:12px 14px;font-weight:700">פריט</td><td style="padding:12px 14px;font-weight:700;width:90px">כמות</td><td style="padding:12px 14px;font-weight:700;width:120px">מחיר</td></tr>
<tr><td style="padding:12px 14px;border-top:1px solid #f0f0f0">[תיאור המסך — לדוגמה: מסך חוץ P4, 3×2 מ׳]</td><td style="padding:12px 14px;border-top:1px solid #f0f0f0">1</td><td style="padding:12px 14px;border-top:1px solid #f0f0f0">[₪ ___]</td></tr>
<tr><td style="padding:12px 14px;border-top:1px solid #f0f0f0">[התקנה ואספקה]</td><td style="padding:12px 14px;border-top:1px solid #f0f0f0">1</td><td style="padding:12px 14px;border-top:1px solid #f0f0f0">[₪ ___]</td></tr>
<tr style="background:#fff6f0"><td style="padding:14px;font-weight:800" colspan="2">סה״כ לתשלום (לפני מע״מ)</td><td style="padding:14px;font-weight:800;color:${ORANGE}">[₪ ___]</td></tr>
</table>
<p style="margin:18px 0 0;font-size:13px;color:#777;line-height:1.6">ההצעה בתוקף ל-14 יום. אחריות יצרן מלאה, כולל התקנה מקצועית וכיול צבע באתר.</p>
<p style="margin:22px 0 0;font-size:15px">בברכה,<br><b>צוות MLS ישראל</b></p>
</td></tr>`),
  },
  {
    name: 'קידום מכירות / מבצע',
    subject: '🔥 מבצע מיוחד על מסכי LED — MLS ישראל',
    body: shell(`<tr><td style="padding:0">
<div style="background:linear-gradient(135deg,${ORANGE},#ff9243);padding:38px 28px;text-align:center">
<p style="margin:0 0 6px;font-size:13px;letter-spacing:2px;color:#fff8f2;text-transform:uppercase">מבצע לזמן מוגבל</p>
<h1 style="margin:0;font-size:30px;font-weight:800;color:#fff;letter-spacing:-.5px">מסך LED לעסק שלך</h1>
<p style="margin:10px 0 0;font-size:16px;color:#fff">במחיר שלא תראו בשוק</p>
</div>
<div style="padding:30px 28px">
<p style="margin:0 0 16px;font-size:15px;line-height:1.7">שלום {{first_name}}, זו ההזדמנות לשדרג את החזות של העסק עם מסך LED מקצועי — בהיר, חד, ועמיד. מלאי זמין להתקנה מהירה.</p>
<ul style="margin:0 0 22px;padding-inline-start:20px;font-size:14px;color:#444;line-height:1.9">
<li>מסכי חוץ ופנים בכל גודל</li>
<li>ליווי מלא מהתכנון ועד ההפעלה</li>
<li>אחריות ושירות מקומי בישראל</li>
</ul>
<div align="center"><a href="${SITE}/contact.html" style="display:inline-block;background:${ORANGE};color:#fff;font-size:16px;font-weight:700;text-decoration:none;padding:14px 34px;border-radius:980px">קבלו הצעת מחיר ←</a></div>
</div>
</td></tr>`),
  },
  {
    name: 'מעקב לקוח',
    subject: 'רצינו לחזור אליך — MLS ישראל',
    body: shell(`<tr><td style="padding:32px 28px">
<p style="margin:0 0 14px;font-size:15px;line-height:1.7">שלום {{first_name}},</p>
<p style="margin:0 0 14px;font-size:15px;line-height:1.7">רצינו לוודא שקיבלת את כל המידע שחיפשת לגבי מסכי ה-LED שלנו, ולראות אם נוכל לעזור בשלב הבא. נשמח לענות על כל שאלה או להכין הצעה מותאמת.</p>
<p style="margin:0 0 22px;font-size:15px;line-height:1.7">אפשר פשוט להשיב למייל הזה, או לחייג אלינו: <a href="tel:+972549494948" style="color:${ORANGE};font-weight:700;text-decoration:none">054-949-4948</a>.</p>
<p style="margin:0;font-size:15px">בברכה,<br><b>צוות MLS ישראל</b></p>
</td></tr>`),
  },
];

async function seedTemplates() {
  const { rows } = await pool.query('SELECT COUNT(*)::int AS n FROM email_templates');
  if (rows[0].n > 0) return;
  for (const t of TEMPLATES_SEED) {
    await pool.query('INSERT INTO email_templates (name, subject, body) VALUES ($1,$2,$3)', [t.name, t.subject, t.body]);
  }
  console.log(`Seeded ${TEMPLATES_SEED.length} email templates.`);
}

async function log(userId, action, detail = '', leadId = null) {
  try {
    await pool.query('INSERT INTO activity_log (user_id, action, detail, lead_id) VALUES ($1,$2,$3,$4)', [userId, action, detail, leadId]);
  } catch (e) {
    console.error('activity_log failed:', e.message);
  }
}

// atomic per-year serial numbers, e.g. nextSerial('quote') -> "2026-0007"
async function nextSerial(kind) {
  const year = new Date().getFullYear();
  const key = `${kind}-${year}`;
  const { rows } = await pool.query(
    `INSERT INTO counters(key,val) VALUES($1,1) ON CONFLICT(key) DO UPDATE SET val=counters.val+1 RETURNING val`, [key]);
  return `${year}-${String(rows[0].val).padStart(4, '0')}`;
}

module.exports = { pool, init, log, nextSerial };
