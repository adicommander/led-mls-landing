const nodemailer = require('nodemailer');

const osConfigured = !!(process.env.ONESIGNAL_APP_ID && process.env.ONESIGNAL_API_KEY);
const smtpConfigured = !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
const configured = osConfigured || smtpConfigured;

const transporter = smtpConfigured
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: Number(process.env.SMTP_PORT) === 465,
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    })
  : null;

const FROM = process.env.SMTP_FROM || process.env.SMTP_USER || 'noreply@led-mls.co.il';
const OS_FROM_NAME = process.env.EMAIL_FROM_NAME || 'MLS ישראל';
const OS_FROM_ADDRESS = process.env.EMAIL_FROM_ADDRESS || 'noreply@mail.led-mls.co.il';

async function sendViaOneSignal({ to, subject, text, html }) {
  const key = process.env.ONESIGNAL_API_KEY;
  const auth = key.startsWith('os_v2_') ? `Key ${key}` : `Basic ${key}`;
  const r = await fetch('https://api.onesignal.com/notifications', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: auth },
    body: JSON.stringify({
      app_id: process.env.ONESIGNAL_APP_ID,
      email_subject: subject,
      email_body: html || `<div dir="rtl" style="font-family:Arial,sans-serif;white-space:pre-wrap">${String(text || '')}</div>`,
      include_email_tokens: [to],
      email_from_name: OS_FROM_NAME,
      email_from_address: OS_FROM_ADDRESS,
    }),
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok || (d.errors && d.errors.length)) {
    throw new Error(`OneSignal ${r.status}: ${JSON.stringify(d.errors || d)}`);
  }
  return { sent: true, id: d.id };
}

// Returns {sent:boolean}. Prefers OneSignal (verified mail.led-mls.co.il domain),
// falls back to SMTP, and finally logs to stdout so 2FA codes stay reachable
// through the platform runtime logs.
async function send({ to, subject, text, html }) {
  if (osConfigured) {
    try {
      return await sendViaOneSignal({ to, subject, text, html });
    } catch (e) {
      console.error('OneSignal send failed:', e.message);
    }
  }
  if (transporter) {
    try {
      await transporter.sendMail({ from: FROM, to, subject, text, html });
      return { sent: true };
    } catch (e) {
      console.error('SMTP send failed:', e.message);
    }
  }
  console.log(`[MAIL not delivered] to=${to} subject="${subject}"\n${text}`);
  return { sent: false };
}

function codeEmail(code) {
  return {
    subject: `${code} — קוד הכניסה שלך למערכת הניהול MLS ישראל`,
    text: `קוד האימות שלך: ${code}\nהקוד תקף ל-10 דקות. אם לא ניסית להתחבר — התעלם מהודעה זו.`,
    html: `<div dir="rtl" style="font-family:Arial,sans-serif;max-width:420px;margin:auto;padding:24px;border:1px solid #eee;border-radius:12px">
      <h2 style="color:#ff6600;margin:0 0 12px">MLS ישראל — מערכת ניהול</h2>
      <p>קוד האימות שלך:</p>
      <div style="font-size:32px;letter-spacing:8px;font-weight:bold;background:#fff7f0;border:1px solid #ffd9b3;border-radius:8px;padding:12px;text-align:center">${code}</div>
      <p style="color:#888;font-size:13px">הקוד תקף ל-10 דקות. אם לא ניסית להתחבר — התעלם מהודעה זו.</p>
    </div>`,
  };
}

module.exports = { send, codeEmail, configured };
