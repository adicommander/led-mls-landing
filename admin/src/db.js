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
  tags TEXT NOT NULL DEFAULT '',
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
  title TEXT NOT NULL,
  due_date TIMESTAMPTZ,
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
  await pool.query(`ALTER TABLE activity_log ADD COLUMN IF NOT EXISTS lead_id INT`);
  // expand the pipeline stages: map legacy 'in_progress' -> 'contacted', then widen the CHECK
  await pool.query(`ALTER TABLE leads DROP CONSTRAINT IF EXISTS leads_status_check`);
  await pool.query(`UPDATE leads SET status='contacted' WHERE status='in_progress'`);
  await pool.query(`ALTER TABLE leads ADD CONSTRAINT leads_status_check CHECK (status IN ('new','contacted','quoted','negotiation','won','lost'))`);
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

async function log(userId, action, detail = '', leadId = null) {
  try {
    await pool.query('INSERT INTO activity_log (user_id, action, detail, lead_id) VALUES ($1,$2,$3,$4)', [userId, action, detail, leadId]);
  } catch (e) {
    console.error('activity_log failed:', e.message);
  }
}

module.exports = { pool, init, log };
