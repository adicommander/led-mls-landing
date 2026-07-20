# LED-MLS Israel — Project Handoff

מסמך זה מסכם את מצב הפרויקט כדי שסוכן AI אחר (או מפתח) יוכל להמשיך. נכתב 2026-07-20.

---

## מה זה
אתר תדמית + מערכת ניהול (CRM) עבור **MLS ישראל** — הנציגות הרשמית בישראל של [led-mls.com](https://www.led-mls.com), יצרנית מסכי LED בינלאומית. האתר בעברית (RTL).

- **אתר חי:** https://led-mls.co.il (וגם www)
- **מערכת ניהול:** https://led-mls.co.il/admin
- **ריפו GitHub:** `adicommander/led-mls-landing` (public, branch `main`)
- **אחסון:** DigitalOcean App Platform, app id `bce64917-12b3-4489-8974-9cf3dc03e403`, region `fra`

---

## ארכיטקטורה

אפליקציה אחת ב-DigitalOcean App Platform עם 3 רכיבים:

| רכיב | סוג | תיאור |
|---|---|---|
| `site` | Static Site | האתר עצמו (HTML/CSS/JS בשורש הריפו) |
| `api` | Service (Node, basic-xxs) | מערכת הניהול, בתיקייה `/admin` |
| `maindb` | Dev PostgreSQL | מסד הלידים והמשתמשים |

**ניתוב (ingress):** `/api` ו-`/admin` → `api` (עם `preserve_path_prefix: true` — קריטי!). כל השאר → `site`.

מקור האמת למפרט האפליקציה: `deploy/app-spec.json` (מסמך זה; ראה גם קובץ נפרד בתיקיית `deploy/`). הסודות (JWT_SECRET, סיסמאות, מפתח OneSignal) **לא** בריפו — הם ב-DigitalOcean console כ-SECRET envs.

---

## מבנה הקבצים

```
/
├── index.html          דף הבית (hero carousel + video tour + timeline)
├── products.html       קטלוג מוצרים + טבלת מפרטים
├── solutions.html      פתרונות לפי תחום
├── place.html          כלי אינטראקטיבי: מיקום מסך וירטואלי (three.js)
├── about.html          אודות
├── contact.html        טופס יצירת קשר → POST /api/leads
├── assets/             images, video (showcase-tour.mp4 + mobile)
├── robots.txt          מזמין זחלני AI, חוסם /admin /api
├── sitemap.xml
├── llms.txt            סיכום לחברה עבור סוכני AI (GEO)
├── OneSignalSDKWorker.js   service worker לפוש
└── admin/              מערכת הניהול (Node/Express)
    ├── server.js       כל ה-API routes
    ├── src/db.js       schema + חיבור PostgreSQL
    ├── src/mail.js     שליחת מיילים (OneSignal → SMTP → log)
    ├── public/index.html   ה-SPA של הניהול (וניל JS)
    └── package.json
```

---

## עיצוב

- **שפה עיצובית:** בהשראת אפל — רקע לבן/אפור (#F5F5F7), טקסט כהה (#1D1D1F), כתום מותג יחיד `#FF6A1A`. הפתיח (hero carousel) וסיור הווידאו נשארים כהים בכוונה.
- **מנגנון:** משתני CSS ב-`:root` של כל עמוד + בלוק override בשם `<style id="ive-light">` שמוזרק לפני `</body>`. **כל כוונון עיצוב לתמה הבהירה צריך להיכנס לבלוק `ive-light`.**
- הוסרו: דמויות (mascots), כפתורים צפים, גריד פיקסלים, טקסטורת רעש.
- CTA "קבל הצעת מחיר" מופיע **רק בהדר** (השאר הוסתרו ב-CSS).
- פונטים: Rubik (כותרות), Assistant (גוף), JetBrains Mono (מספרים).

---

## מערכת הניהול (admin)

**התחברות:** אימייל + סיסמה. יש 2FA אופציונלי במייל (דגל `TWOFA_ENABLED`, כרגע `false` לבקשת הלקוח). בכניסה ראשונה המשתמש מחויב להחליף סיסמה.

**API עיקרי (server.js):**
- `POST /api/auth/login` → אם 2FA כבוי, מחזיר session; אחרת שולח קוד ומחזיר `pre` token
- `POST /api/auth/verify` → אימות קוד 2FA
- `POST /api/auth/change-password`
- `GET/POST/PATCH/DELETE /api/users` (admin only) — משתמשים עם first_name/last_name/phone/role
- `POST /api/leads` (public) — טופס האתר; honeypot `company`
- `GET/PATCH /api/leads`, `GET /api/leads/:id`, `POST /api/leads/:id/notes`, `POST /api/leads/:id/email`
- `GET /api/stats`

**מסד (db.js):** טבלאות `users, login_codes, leads, lead_notes, lead_messages, activity_log`. הסכימה נוצרת אוטומטית ב-boot. שים לב: הקוד מזהה סכימה כתיבה (`resolveSchema`) כי DO dev DB חוסם CREATE ב-public.

**מיילים (mail.js):** מנסה OneSignal → SMTP → log. כרגע OneSignal מוגדר אבל **חסר `ONESIGNAL_API_KEY`** (ראה "משימות פתוחות").

---

## DNS (מנוהל ב-DigitalOcean, דומיין רשום ב-LiveDNS)

הדומיין `led-mls.co.il` רשום ב-LiveDNS אבל שרתי השמות מצביעים ל-DigitalOcean (`ns1/2/3.digitalocean.com`), כך ש-DNS מנוהל בקונסולת DO.

**רשומות קריטיות שאסור לשבור:**
- דואר Microsoft 365: `MX @ → ledmls-co-il0i.mail.protection.outlook.com`, `TXT @ MS=ms44680477`, `TXT @ v=spf1 include:spf.protection.outlook.com -all`, `CNAME autodiscover → autodiscover.outlook.com`
- OneSignal email (על תת-דומיין `mail.led-mls.co.il` בלבד, מאומת): TXT `_osauth.mail`, TXT SPF `mail`, CNAME `os1/os2._domainkey.mail`, TXT `_dmarc`, MX `mail → mxa/mxb.onesignal.email`, CNAME `email.mail → click.tr.onesignal.email`

---

## SEO / GEO

- `robots.txt` — מזמין במפורש זחלני AI (GPTBot, ClaudeBot, PerplexityBot, Google-Extended…), חוסם /admin, /api
- `sitemap.xml` — 6 עמודים
- `llms.txt` — סיכום החברה לסוכני AI
- JSON-LD בכל עמוד: Organization+LocalBusiness, WebSite (בית), Product ItemList (מוצרים), BreadcrumbList (פנימיים). מסומן `<!-- seo-structured-data -->`
- canonical + og:url נכונים לכל עמוד + geo meta

---

## פריסה (deploy)

הפריסה **לא אוטומטית** (מקור git רגיל, לא GitHub App). לאחר `git push`:
```
POST https://api.digitalocean.com/v2/apps/{APP_ID}/deployments  {"force_build":true}
```
ואז לעקוב אחר `phase` עד `ACTIVE`. הבנייה של השרת דורשת `admin/package-lock.json` (buildpack). זמן פריסה טיפוסי: 2–4 דקות.

---

## פרטי קשר / מותג
- טלפון/וואטסאפ: 058-500-8500 / +972585008500
- אימייל: sales@led-mls.co.il
- אינסטגרם: @mls_israel
- צבע מותג: כתום #FF6A1A (מ-`--mainColor` של led-mls.com)

---

## ⚠️ משימות פתוחות (למי שממשיך)

1. **`ONESIGNAL_API_KEY` חסר** — בלי זה אין שליחת מיילים (קודי 2FA, התראות לידים, מיילים ללקוחות). יש להשיג REST API Key מ-OneSignal dashboard ולהוסיף כ-SECRET env בשם `ONESIGNAL_API_KEY` + לוודא `ONESIGNAL_APP_ID`. הדומיין `mail.led-mls.co.il` כבר מאומת ב-OneSignal.
2. **2FA כבוי** — `TWOFA_ENABLED=false`. להחזרה: שנה ל-`true` ב-envs (אחרי שהמיילים עובדים).
3. **טוקן DigitalOcean נחשף** בצ'אט המקורי — יש להחליף אותו בקונסולה.
4. **לוודא ש-`sales@led-mls.co.il` קיימת** ב-Microsoft 365 (תיבה או alias) — לשם מגיעות פניות מהאתר.
5. **מומלץ:** Google Search Console + הגשת sitemap; שקילת עמוד FAQ עם FAQPage schema (מחזק GEO).

## סביבה (env vars ב-DigitalOcean)
```
JWT_SECRET=<secret>
DATABASE_URL=${maindb.DATABASE_URL}
DB_CA_CERT=${maindb.CA_CERT}
SEED_ADMIN_EMAIL=adi@led-mls.co.il
SEED_ADMIN_PASSWORD=<secret, החלף בכניסה ראשונה>
LEADS_NOTIFY_EMAIL=sales@led-mls.co.il
TWOFA_ENABLED=false
ONESIGNAL_APP_ID=<app id>
ONESIGNAL_API_KEY=<secret — חסר!>
EMAIL_FROM_ADDRESS=noreply@mail.led-mls.co.il
EMAIL_FROM_NAME=MLS ישראל
SMTP_* (fallback, ריק)
```
