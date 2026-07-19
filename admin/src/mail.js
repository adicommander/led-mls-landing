const nodemailer = require('nodemailer');

const configured = !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);

const transporter = configured
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: Number(process.env.SMTP_PORT) === 465,
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    })
  : null;

const FROM = process.env.SMTP_FROM || process.env.SMTP_USER || 'noreply@led-mls.co.il';

// Returns {sent:boolean}. When SMTP is not configured the message is logged to
// stdout so 2FA codes remain reachable through the platform runtime logs.
async function send({ to, subject, text, html }) {
  if (!transporter) {
    console.log(`[MAIL not configured] to=${to} subject="${subject}"\n${text}`);
    return { sent: false };
  }
  try {
    await transporter.sendMail({ from: FROM, to, subject, text, html });
    return { sent: true };
  } catch (e) {
    console.error('sendMail failed:', e.message);
    return { sent: false, error: e.message };
  }
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
