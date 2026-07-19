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
  status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new','in_progress','won','lost')),
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
  action TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_leads_status ON leads(status);
CREATE INDEX IF NOT EXISTS idx_leads_created ON leads(created_at DESC);
`;

async function init() {
  appSchema = await resolveSchema();
  console.log(`Using schema "${appSchema}" for app tables.`);
  await pool.query(SCHEMA);
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

async function log(userId, action, detail = '') {
  try {
    await pool.query('INSERT INTO activity_log (user_id, action, detail) VALUES ($1,$2,$3)', [userId, action, detail]);
  } catch (e) {
    console.error('activity_log failed:', e.message);
  }
}

module.exports = { pool, init, log };
