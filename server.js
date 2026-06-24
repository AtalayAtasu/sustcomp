'use strict';
const express  = require('express');
const session  = require('express-session');
const { Pool } = require('pg');
const bcrypt   = require('bcryptjs');
// nodemailer removed — using Resend HTTP API instead (SMTP blocked on Render)
const path     = require('path');
const fs       = require('fs');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── DATABASE ───────────────────────────────────────────────────────────────

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS cohorts (
      id         SERIAL PRIMARY KEY,
      name       VARCHAR(255) NOT NULL UNIQUE,
      api_key    TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id            SERIAL PRIMARY KEY,
      username      VARCHAR(255) NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      cohort_id     INTEGER REFERENCES cohorts(id) ON DELETE SET NULL,
      expires_at    TIMESTAMPTZ NOT NULL,
      last_login    TIMESTAMPTZ,
      created_at    TIMESTAMPTZ DEFAULT NOW()
    )`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS submissions (
      id             SERIAL PRIMARY KEY,
      user_id        INTEGER REFERENCES users(id) ON DELETE SET NULL,
      username       TEXT NOT NULL,
      cohort_name    TEXT DEFAULT '',
      group_name     TEXT DEFAULT '',
      industry       TEXT DEFAULT '',
      challenge_name TEXT DEFAULT '',
      challenge_desc TEXT DEFAULT '',
      lever          TEXT DEFAULT '',
      stakeholders   JSONB DEFAULT '[]',
      benefit_lines  JSONB DEFAULT '[]',
      npv5           NUMERIC DEFAULT 0,
      npv10          NUMERIC DEFAULT 0,
      rate           NUMERIC DEFAULT 0,
      currency       TEXT DEFAULT 'EUR',
      report_html    TEXT DEFAULT '',
      submitted_at   TIMESTAMPTZ DEFAULT NOW()
    )`);
  // Add columns introduced after initial deploy (safe to run repeatedly)
  await pool.query(`ALTER TABLE submissions ADD COLUMN IF NOT EXISTS members        TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE submissions ADD COLUMN IF NOT EXISTS lever_detail   TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE submissions ADD COLUMN IF NOT EXISTS market_segment TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE submissions ADD COLUMN IF NOT EXISTS pitch          TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE submissions ADD COLUMN IF NOT EXISTS capex          NUMERIC DEFAULT 0`);
  await pool.query(`ALTER TABLE submissions ADD COLUMN IF NOT EXISTS consultant_html TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE submissions ADD COLUMN IF NOT EXISTS version        TEXT DEFAULT 'basic'`);
  await pool.query(`ALTER TABLE submissions ADD COLUMN IF NOT EXISTS extended_data  JSONB DEFAULT NULL`);
  await pool.query(`ALTER TABLE submissions ADD COLUMN IF NOT EXISTS email_status   TEXT DEFAULT 'pending'`);
  await pool.query(`ALTER TABLE submissions ADD COLUMN IF NOT EXISTS email_error    TEXT DEFAULT ''`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS drafts (
      user_id    INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      state      JSONB,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS drafts_ext (
      user_id    INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      state      JSONB,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )`);
  console.log('Database ready');
}

// ── EXPRESS SETUP ──────────────────────────────────────────────────────────

app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: false }));
app.use(express.json({ limit: '10mb' }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 12 * 60 * 60 * 1000   // 12 hours
  }
}));

// ── MIDDLEWARE ─────────────────────────────────────────────────────────────

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  if (new Date() > new Date(req.session.user.expiresAt))
    return req.session.destroy(() => res.redirect('/login?msg=expired'));
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.isAdmin) return res.redirect('/admin/login');
  next();
}

// ── USER LOGIN / LOGOUT ────────────────────────────────────────────────────

app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/');
  const msg = req.query.msg === 'expired'
    ? 'Your access has expired. Please contact the administrator.'
    : '';
  res.send(loginHTML(msg));
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const r = await pool.query(
      `SELECT u.*, c.name AS cohort_name, c.api_key
       FROM users u
       LEFT JOIN cohorts c ON u.cohort_id = c.id
       WHERE u.username = $1`, [username]);
    const user = r.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash)))
      return res.send(loginHTML('Invalid username or password.'));
    if (new Date() > new Date(user.expires_at))
      return res.send(loginHTML('Your access has expired. Please contact the administrator.'));

    await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);

    req.session.user = {
      id:         user.id,
      username:   user.username,
      cohortId:   user.cohort_id,
      cohortName: user.cohort_name || '',
      expiresAt:  user.expires_at,
      apiKey:     user.api_key || ''
    };
    res.redirect('/');
  } catch (e) {
    console.error(e);
    res.send(loginHTML('An error occurred. Please try again.'));
  }
});

app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));

// ── ADMIN LOGIN / LOGOUT ───────────────────────────────────────────────────

app.get('/admin/login', (req, res) => {
  if (req.session.isAdmin) return res.redirect('/admin');
  res.send(adminLoginHTML());
});

app.post('/admin/login', (req, res) => {
  if (req.body.password === process.env.ADMIN_PASSWORD) {
    req.session.isAdmin = true;
    return res.redirect('/admin');
  }
  res.send(adminLoginHTML('Incorrect password.'));
});

app.get('/admin/logout', (req, res) => {
  req.session.isAdmin = false;
  res.redirect('/admin/login');
});

// ── ADMIN PANEL ────────────────────────────────────────────────────────────

// Test email route — visit /admin/test-email to check credentials work
app.get('/admin/test-email', requireAdmin, async (req, res) => {
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from:    'SustComp <onboarding@resend.dev>',
        to:      ['atalay.atasu@googlemail.com'],
        subject: '[SustComp] Test email — Resend configured OK',
        html:    '<p>If you received this, Resend is working correctly for SustComp.</p>'
      })
    });
    if (!r.ok) { const e = await r.json(); throw new Error(e.message || `Resend error ${r.status}`); }
    res.send('<p style="font-family:sans-serif;padding:2rem">✅ Test email sent to atalay.atasu@googlemail.com — check your inbox (and spam).<br><br><a href="/admin">← Back to admin</a></p>');
  } catch (e) {
    res.status(500).send(`<p style="font-family:sans-serif;padding:2rem;color:red">❌ Email failed:<br><br><code>${e.message}</code><br><br><a href="/admin">← Back to admin</a></p>`);
  }
});

app.get('/admin', requireAdmin, async (req, res) => {
  try {
    const [cohortsR, usersR, subsR] = await Promise.all([
      pool.query(`
        SELECT c.*, COUNT(u.id)::int AS user_count
        FROM cohorts c
        LEFT JOIN users u ON u.cohort_id = c.id
        GROUP BY c.id ORDER BY c.created_at DESC`),
      pool.query(`
        SELECT u.*, c.name AS cohort_name
        FROM users u
        LEFT JOIN cohorts c ON u.cohort_id = c.id
        ORDER BY u.created_at DESC`),
      pool.query(`
        SELECT id, username, cohort_name, group_name, challenge_name, submitted_at, version, email_status, email_error
        FROM submissions ORDER BY submitted_at DESC LIMIT 100`)
    ]);
    res.send(adminHTML(cohortsR.rows, usersR.rows, subsR.rows, req.query.msg));
  } catch (e) {
    console.error(e);
    res.status(500).send('Error: ' + e.message);
  }
});

// Cohorts — create
app.post('/admin/cohorts', requireAdmin, async (req, res) => {
  const { name, api_key } = req.body;
  if (!name.trim()) return res.redirect('/admin?msg=Name+is+required');
  try {
    await pool.query('INSERT INTO cohorts (name, api_key) VALUES ($1, $2)',
      [name.trim(), (api_key || '').trim()]);
    res.redirect('/admin?msg=Cohort+created+successfully');
  } catch (e) {
    res.redirect('/admin?msg=' + encodeURIComponent('Error: ' + e.message));
  }
});

// Cohorts — delete
app.post('/admin/cohorts/:id/delete', requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM cohorts WHERE id = $1', [req.params.id]);
  res.redirect('/admin?msg=Cohort+deleted');
});

// Users — create
app.post('/admin/users', requireAdmin, async (req, res) => {
  const { username, password, cohort_id, expires_at } = req.body;
  if (!username.trim() || !password || !expires_at)
    return res.redirect('/admin?msg=Username,+password+and+expiry+are+required');
  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      `INSERT INTO users (username, password_hash, cohort_id, expires_at)
       VALUES ($1, $2, $3, $4)`,
      [username.trim(), hash, cohort_id || null, expires_at]);
    res.redirect('/admin?msg=User+created+successfully');
  } catch (e) {
    res.redirect('/admin?msg=' + encodeURIComponent('Error: ' + e.message));
  }
});

// Users — delete
app.post('/admin/users/:id/delete', requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
  res.redirect('/admin?msg=User+deleted');
});

// Users — reset progress (clears draft, leaves account + submissions intact)
app.post('/admin/users/:id/reset', requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM drafts WHERE user_id=$1', [req.params.id]);
  res.redirect('/admin?msg=User+progress+reset');
});

// Submissions — view CFO report only
app.get('/admin/submissions/:id/report', requireAdmin, async (req, res) => {
  const r = await pool.query(
    'SELECT report_html, username, challenge_name, group_name, industry, cohort_name FROM submissions WHERE id = $1',
    [req.params.id]);
  if (!r.rows[0]) return res.status(404).send('Not found');
  const row = r.rows[0];
  res.type('html').send(buildReportDoc({
    reportHtml:    row.report_html,
    username:      row.username,
    challengeName: row.challenge_name,
    groupName:     row.group_name,
    industry:      row.industry,
    cohortName:    row.cohort_name
  }));
});

// Submissions — view complete submission
app.get('/admin/submissions/:id/complete', requireAdmin, async (req, res) => {
  const r = await pool.query('SELECT * FROM submissions WHERE id = $1', [req.params.id]);
  if (!r.rows[0]) return res.status(404).send('Not found');
  const row = r.rows[0];
  res.type('html').send(buildCompleteDoc({
    reportHtml:      row.report_html,
    consultantHtml:  row.consultant_html,
    username:        row.username,
    challengeName:   row.challenge_name,
    challengeDesc:   row.challenge_desc,
    groupName:       row.group_name,
    members:         row.members,
    industry:        row.industry,
    cohortName:      row.cohort_name,
    lever:           row.lever,
    leverDetail:     row.lever_detail,
    marketSegment:   row.market_segment,
    stakeholders:    row.stakeholders,
    benefitLines:    row.benefit_lines,
    npv5:            row.npv5,
    npv10:           row.npv10,
    capex:           row.capex,
    rate:            row.rate,
    currency:        row.currency,
    pitch:           row.pitch
  }));
});

// Submissions — view complete (extended version)
app.get('/admin/submissions/:id/complete-ext', requireAdmin, async (req, res) => {
  const r = await pool.query('SELECT * FROM submissions WHERE id = $1', [req.params.id]);
  if (!r.rows[0]) return res.status(404).send('Not found');
  const row = r.rows[0];
  const d = row.extended_data || {};
  res.type('html').send(buildCompleteDoc({
    reportHtml:     row.report_html,
    consultantHtml: row.consultant_html,
    username:       row.username,
    challengeName:  row.challenge_name,
    challengeDesc:  row.challenge_desc,
    groupName:      row.group_name,
    members:        row.members,
    industry:       row.industry,
    cohortName:     row.cohort_name,
    lever:          d.lever || '',
    leverDetail:    d.vision || '',
    marketSegment:  d.wtpData?.segment || d.mktExData?.segment || '',
    stakeholders:   row.stakeholders,
    benefitLines:   row.benefit_lines,
    npv5:           row.npv5,
    npv10:          row.npv10,
    capex:          row.capex,
    rate:           row.rate,
    currency:       row.currency,
    pitch:          row.pitch
  }));
});

app.post('/admin/submissions/:id/delete', requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM submissions WHERE id=$1', [req.params.id]);
    res.redirect('/admin?msg=Submission+deleted');
  } catch (e) {
    res.redirect('/admin?msg=Delete+failed:+' + encodeURIComponent(e.message));
  }
});

// ── MAIN APP ───────────────────────────────────────────────────────────────

function serveApp(file, req, res) {
  const html = fs.readFileSync(path.join(__dirname, file), 'utf8');
  const script = `<script>
    window.__API_KEY__   = ${JSON.stringify(req.session.user.apiKey)};
    window.__USERNAME__  = ${JSON.stringify(req.session.user.username)};
    window.__COHORT__    = ${JSON.stringify(req.session.user.cohortName)};
    window.__EXPIRES__   = ${JSON.stringify(req.session.user.expiresAt)};
  </script>`;
  res.send(html.replace('</head>', script + '</head>'));
}

app.get('/',        requireLogin, (req, res) => res.send(landingHTML(req.session.user.username)));
app.get('/basic',   requireLogin, (req, res) => serveApp('app.html',          req, res));
app.get('/extended',requireLogin, (req, res) => serveApp('app-extended.html', req, res));

// ── SUBMIT API ─────────────────────────────────────────────────────────────

// ── DRAFT (auto-save) ──────────────────────────────────────────────────────

app.get('/api/draft', requireLogin, async (req, res) => {
  try {
    const r = await pool.query('SELECT state FROM drafts WHERE user_id=$1', [req.session.user.id]);
    res.json(r.rows[0] ? { state: r.rows[0].state } : {});
  } catch (e) { res.json({}); }
});

app.put('/api/draft', requireLogin, async (req, res) => {
  try {
    await pool.query(
      `INSERT INTO drafts(user_id, state, updated_at) VALUES($1,$2,NOW())
       ON CONFLICT(user_id) DO UPDATE SET state=$2, updated_at=NOW()`,
      [req.session.user.id, JSON.stringify(req.body)]
    );
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false }); }
});

// Extended version — separate draft slot
app.get('/api/draft/ext', requireLogin, async (req, res) => {
  try {
    const r = await pool.query('SELECT state FROM drafts_ext WHERE user_id=$1', [req.session.user.id]);
    res.json(r.rows[0] ? { state: r.rows[0].state } : {});
  } catch (e) { res.json({}); }
});

app.put('/api/draft/ext', requireLogin, async (req, res) => {
  try {
    await pool.query(
      `INSERT INTO drafts_ext(user_id, state, updated_at) VALUES($1,$2,NOW())
       ON CONFLICT(user_id) DO UPDATE SET state=$2, updated_at=NOW()`,
      [req.session.user.id, JSON.stringify(req.body)]
    );
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false }); }
});

// Submissions — resend email
app.post('/admin/submissions/:id/resend-email', requireAdmin, async (req, res) => {
  const r = await pool.query('SELECT * FROM submissions WHERE id=$1', [req.params.id]);
  if (!r.rows[0]) return res.redirect('/admin?msg=Submission+not+found');
  const sub = r.rows[0];
  await pool.query(`UPDATE submissions SET email_status='pending', email_error='' WHERE id=$1`, [sub.id]);
  try {
    const parseJ = v => { try { return typeof v === 'string' ? JSON.parse(v) : (v || []); } catch { return []; } };
    await sendEmail({
      ...sub,
      groupName:      sub.group_name,
      challengeName:  sub.challenge_name,
      challengeDesc:  sub.challenge_desc,
      consultantHtml: sub.consultant_html,
      reportHtml:     sub.report_html,
      stakeholders:   parseJ(sub.stakeholders),
      benefitLines:   parseJ(sub.benefit_lines),
      cohortName:     sub.cohort_name,
    });
    await pool.query(`UPDATE submissions SET email_status='sent', email_error='' WHERE id=$1`, [sub.id]);
    res.redirect('/admin?msg=Email+resent+successfully');
  } catch (e) {
    await pool.query(`UPDATE submissions SET email_status='failed', email_error=$1 WHERE id=$2`, [e.message, sub.id]);
    res.redirect('/admin?msg=' + encodeURIComponent('Email failed: ' + e.message));
  }
});

// ── SUBMIT ─────────────────────────────────────────────────────────────────

app.post('/api/submit', requireLogin, async (req, res) => {
  const u = req.session.user;
  const d = req.body;
  try {
    let subId;
    if (d.version === 'extended') {
      // Extended submission — store common fields + full payload in extended_data
      const ins = await pool.query(`
        INSERT INTO submissions
          (user_id, username, cohort_name, group_name, members, industry,
           challenge_name, challenge_desc, npv5, npv10, capex, rate, currency,
           pitch, consultant_html, report_html, version, extended_data)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
        RETURNING id`,
        [u.id, u.username, u.cohortName,
         d.groupName||'', d.members||'', d.industry||'',
         d.challengeName||'', d.challengeDesc||'',
         d.npv5||0, d.npv10||0, d.capex||0, d.rate||0,
         d.currency||'EUR', d.pitch||'',
         d.consultantHtml||'', d.reportHtml||'',
         'extended', JSON.stringify(d)]);
      subId = ins.rows[0].id;
      await pool.query('DELETE FROM drafts_ext WHERE user_id=$1', [u.id]);
    } else {
      // Basic submission
      const ins = await pool.query(`
        INSERT INTO submissions
          (user_id, username, cohort_name, group_name, members, industry,
           challenge_name, challenge_desc, lever, lever_detail, market_segment,
           stakeholders, benefit_lines, npv5, npv10, capex, rate, currency,
           pitch, consultant_html, report_html, version)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
        RETURNING id`,
        [u.id, u.username, u.cohortName,
         d.groupName||'', d.members||'', d.industry||'',
         d.challengeName||'', d.challengeDesc||'',
         d.lever||'', d.leverDetail||'', d.marketSegment||'',
         JSON.stringify(d.stakeholders||[]),
         JSON.stringify(d.benefitLines||[]),
         d.npv5||0, d.npv10||0, d.capex||0, d.rate||0,
         d.currency||'EUR', d.pitch||'',
         d.consultantHtml||'', d.reportHtml||'', 'basic']);
      subId = ins.rows[0].id;
      await pool.query('DELETE FROM drafts WHERE user_id=$1', [u.id]);
    }

    let emailError = null;
    try {
      await sendEmail({ ...d, username: u.username, cohortName: u.cohortName });
      console.log(`Email sent for ${u.username}`);
      await pool.query(`UPDATE submissions SET email_status='sent', email_error='' WHERE id=$1`, [subId]);
    } catch (emailErr) {
      emailError = emailErr.message;
      console.error('Email failed for', u.username, ':', emailErr.message);
      await pool.query(`UPDATE submissions SET email_status='failed', email_error=$1 WHERE id=$2`, [emailErr.message, subId]);
    }

    res.json({ success: true, emailSent: !emailError, emailError });

  } catch (e) {
    console.error('Submit error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ── EMAIL ──────────────────────────────────────────────────────────────────

if (!process.env.RESEND_API_KEY) {
  console.warn('WARNING: RESEND_API_KEY not set — submission emails will fail');
} else {
  console.log('Email configured via Resend');
}

const LEVER_LABELS = {
  cost:  'Cost Reduction',
  wtp:   'WTP Creation',
  mkt:   'Market Creation',
  combo: 'Combination'
};

const STH_LABELS = {
  soc: 'Nature & Society',
  eco: 'Business Ecosystem',
  reg: 'Regulators',
  inv: 'Financial Institutions & Investors'
};

function fmtMoney(n, cur) {
  const sym = { USD:'$', GBP:'£', CHF:'CHF ', SGD:'S$', JPY:'¥', CNY:'¥', BRL:'R$', INR:'₹' }[cur] || '€';
  return sym + Number(n || 0).toLocaleString('en', { maximumFractionDigits: 0 });
}

// Wraps raw CFO report inner HTML in a full styled standalone document
function buildReportDoc(d) {
  const date = new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
  const esc = s => (s || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>CFO Report — ${esc(d.challengeName)}</title>
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@600;700&family=DM+Sans:ital,wght@0,400;0,500;0,600;1,400&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'DM Sans',system-ui,sans-serif;font-size:10.5pt;line-height:1.75;color:#1A1A1A;background:#F0F4F8}
.page{max-width:820px;margin:2rem auto;background:white;border-radius:12px;overflow:hidden;box-shadow:0 4px 32px rgba(0,42,92,0.12)}
.cover{background:#002A5C;color:white;padding:2.5rem 3rem 2.2rem}
.cover-eyebrow{font-size:8pt;font-weight:600;letter-spacing:0.18em;text-transform:uppercase;color:rgba(255,255,255,0.4);margin-bottom:0.5rem}
.cover-title{font-family:'Playfair Display',Georgia,serif;font-size:20pt;font-weight:700;line-height:1.2;color:#fff;margin-bottom:0.2rem}
.cover-subtitle{font-family:'Playfair Display',Georgia,serif;font-size:11pt;color:rgba(255,255,255,0.5);font-weight:600;margin-bottom:1rem}
.cover-rule{height:3px;background:#C9A84C;width:56px;margin:1rem 0 1.1rem;border-radius:2px}
.cover-meta{font-size:8.5pt;color:rgba(255,255,255,0.55);line-height:2}
.cover-meta strong{color:rgba(255,255,255,0.85);font-weight:600}
.body-wrap{padding:2.5rem 3rem}
h3{font-family:'Playfair Display',Georgia,serif;font-size:11.5pt;color:#002A5C;margin:2rem 0 0.6rem;padding-bottom:0.35rem;border-bottom:2px solid #4AABE8;font-weight:700}
h3:first-child{margin-top:0}
p{margin-bottom:0.8rem}
ul,ol{padding-left:1.5rem;margin-bottom:0.8rem}
li{margin-bottom:0.3rem}
strong{color:#002A5C;font-weight:600}
.highlight-box{background:#EEF6FB;border-left:4px solid #4AABE8;padding:1rem 1.25rem;margin:0.5rem 0 1.25rem;border-radius:0 6px 6px 0}
table{width:100%;border-collapse:collapse;margin:0.75rem 0;font-size:9.5pt}
th{background:#002A5C;color:white;padding:0.5rem 0.75rem;text-align:left;font-weight:600;font-size:8.5pt}
td{padding:0.45rem 0.75rem;border-bottom:1px solid #D5E6F5}
tr:nth-child(even) td{background:#F3F8FC}
.doc-footer{margin-top:2.5rem;padding:1rem 3rem;background:#F8FAFC;border-top:1px solid #D5E6F5;display:flex;justify-content:space-between;align-items:center;font-size:8pt;color:#aaa}
.doc-footer-brand{color:#002A5C;font-weight:600}
@media print{body{background:white}.page{box-shadow:none;border-radius:0;margin:0}}
</style></head><body>
<div class="page">
  <div class="cover">
    <div class="cover-eyebrow">Sustainability Strategy Compass · Executive Report</div>
    <div class="cover-title">${esc(d.challengeName) || 'Sustainability Strategy Opportunity'}</div>
    <div class="cover-subtitle">CFO-Ready Investment Memo</div>
    <div class="cover-rule"></div>
    <div class="cover-meta">
      <strong>Group:</strong> ${esc(d.groupName)}<br>
      ${d.industry ? `<strong>Industry:</strong> ${esc(d.industry)}<br>` : ''}
      <strong>Cohort:</strong> ${esc(d.cohortName)}&nbsp;·&nbsp;<strong>Submitted by:</strong> ${esc(d.username)}<br>
      <strong>Date:</strong> ${date}
    </div>
  </div>
  <div class="body-wrap">
    ${d.reportHtml || '<p style="color:#aaa;font-style:italic">CFO report was not generated before submission.</p>'}
    <div class="doc-footer">
      <span class="doc-footer-brand">© AcpitConsulting · Sustainability Strategy Compass</span>
      <span>${date}</span>
    </div>
  </div>
</div>
</body></html>`;
}

// Builds the complete summary document matching the S4 Summary & Report page
function buildCompleteDoc(d) {
  const date = new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
  const esc = s => (s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const cur = d.currency || 'EUR';
  const af = (r, n) => r > 0 ? (1 - Math.pow(1 + r/100, -n)) / (r/100) : n;
  const capex = parseFloat(d.capex) || 0;
  const lines = (d.benefitLines || []).map(l => ({ ...l, ann: parseFloat(l.ann) || 0 }));
  const npv5  = d.npv5  || (-capex + lines.reduce((a,l) => a + l.ann * af(d.rate,5),  0));
  const npv10 = d.npv10 || (-capex + lines.reduce((a,l) => a + l.ann * af(d.rate,10), 0));
  const totAnn = lines.reduce((a,l) => a + l.ann, 0);

  const LEVER_LABELS_LOCAL = { cost:'Cost Reduction', wtp:'WTP Creation', mkt:'Market Creation', combo:'Combination' };

  const activeSth = (d.stakeholders || []).filter(s => s.on);
  const sthRows = activeSth.length
    ? activeSth.map(s => `
      <tr>
        <td>${esc(STH_LABELS[s.id] || s.id)}</td>
        <td>${esc(s.who)}</td><td>${esc(s.pressure)}</td>
        <td>${esc(s.impact)}</td><td>${esc(s.opp)}</td>
      </tr>`).join('')
    : `<tr><td colspan="5" style="color:#aaa;font-style:italic">No stakeholders entered</td></tr>`;

  const benRows = lines.length
    ? lines.map(l => `
      <tr>
        <td>${esc(l.blabel || l.opp)}</td>
        <td style="text-align:right;font-weight:600">${fmtMoney(l.ann, cur)}/yr</td>
        <td style="text-align:right;color:#1B6B3A">${fmtMoney(l.ann * af(d.rate, 5), cur)}</td>
        <td style="text-align:right;color:#1B6B3A">${fmtMoney(l.ann * af(d.rate, 10), cur)}</td>
      </tr>`).join('')
    : `<tr><td colspan="4" style="color:#aaa;font-style:italic">No benefit lines entered</td></tr>`;

  const css = `
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'DM Sans',system-ui,sans-serif;font-size:10.5pt;line-height:1.75;color:#1A1A1A;background:#F0F4F8}
.page{max-width:900px;margin:2rem auto;background:white;border-radius:12px;overflow:hidden;box-shadow:0 4px 32px rgba(0,42,92,0.12)}
.cover{background:#002A5C;color:white;padding:2.5rem 3rem 2.2rem}
.cover-eyebrow{font-size:8pt;font-weight:600;letter-spacing:0.18em;text-transform:uppercase;color:rgba(255,255,255,0.4);margin-bottom:0.5rem}
.cover-title{font-family:'Playfair Display',Georgia,serif;font-size:20pt;font-weight:700;line-height:1.2;color:#fff;margin-bottom:0.2rem}
.cover-subtitle{font-family:'Playfair Display',Georgia,serif;font-size:11pt;color:rgba(255,255,255,0.5);font-weight:600;margin-bottom:1rem}
.cover-rule{height:3px;background:#C9A84C;width:56px;margin:1rem 0 1.1rem;border-radius:2px}
.cover-meta{font-size:8.5pt;color:rgba(255,255,255,0.55);line-height:2}
.cover-meta strong{color:rgba(255,255,255,0.85);font-weight:600}
.body-wrap{padding:0}
.sec{padding:2rem 3rem;border-bottom:1px solid #E8EFF8}
.sec:last-child{border-bottom:none}
.sec-eyebrow{font-size:7.5pt;font-weight:700;letter-spacing:0.14em;text-transform:uppercase;color:#4AABE8;margin-bottom:0.35rem}
.sec-title{font-family:'Playfair Display',Georgia,serif;font-size:13pt;font-weight:700;color:#002A5C;margin-bottom:1rem}
.meta-grid{display:grid;grid-template-columns:140px 1fr;gap:0.3rem 1rem;font-size:9.5pt;margin-bottom:1rem}
.meta-label{color:#999;padding:0.2rem 0}
.meta-val{color:#1A1A1A;padding:0.2rem 0;font-weight:500}
.kpi-row{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin:1rem 0}
.kpi{background:#F0F4F8;border-radius:8px;padding:1rem;text-align:center}
.kpi-label{font-size:7.5pt;color:#999;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:0.3rem}
.kpi-val{font-family:'Playfair Display',Georgia,serif;font-size:14pt;font-weight:700}
.kpi-val.pos{color:#1B6B3A}.kpi-val.neg{color:#C0392B}
table{width:100%;border-collapse:collapse;font-size:9pt;margin:0.5rem 0}
th{background:#002A5C;color:white;padding:0.5rem 0.75rem;text-align:left;font-weight:600;font-size:8pt}
td{padding:0.45rem 0.75rem;border-bottom:1px solid #E8EFF8}
tr:nth-child(even) td{background:#F8FAFC}
.ai-sec{background:#F8FAFC;border-top:2px solid #4AABE8}
.ai-inner{padding:2rem 3rem}
.ai-inner h3{font-family:'Playfair Display',Georgia,serif;font-size:11pt;color:#002A5C;margin:1.5rem 0 0.5rem;padding-bottom:0.3rem;border-bottom:1px solid #D5E6F5;font-weight:700}
.ai-inner h3:first-child{margin-top:0}
.ai-inner p{margin-bottom:0.75rem;font-size:10pt}
.ai-inner ul,.ai-inner ol{padding-left:1.4rem;margin-bottom:0.75rem}
.ai-inner li{margin-bottom:0.28rem}
.ai-inner strong{color:#002A5C;font-weight:600}
.ai-inner .highlight-box{background:#EEF6FB;border-left:4px solid #4AABE8;padding:0.9rem 1.1rem;margin:0.5rem 0 1.2rem;border-radius:0 6px 6px 0}
.doc-footer{padding:1rem 3rem;background:#F8FAFC;border-top:1px solid #D5E6F5;display:flex;justify-content:space-between;align-items:center;font-size:8pt;color:#aaa}
.doc-footer-brand{color:#002A5C;font-weight:600}
@media print{body{background:white}.page{box-shadow:none;border-radius:0;margin:0}}`;

  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Complete Submission — ${esc(d.challengeName)}</title>
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@600;700&family=DM+Sans:ital,wght@0,400;0,500;0,600;1,400&display=swap" rel="stylesheet">
<style>${css}</style></head><body>
<div class="page">

  <div class="cover">
    <div class="cover-eyebrow">Sustainability Strategy Compass · Complete Submission</div>
    <div class="cover-title">${esc(d.challengeName) || 'Sustainability Strategy'}</div>
    <div class="cover-subtitle">Full Analysis &amp; AI-Generated Reports</div>
    <div class="cover-rule"></div>
    <div class="cover-meta">
      <strong>Group:</strong> ${esc(d.groupName)}${d.members ? ' &nbsp;·&nbsp; ' + esc(d.members) : ''}<br>
      ${d.industry ? `<strong>Industry:</strong> ${esc(d.industry)}<br>` : ''}
      <strong>Cohort:</strong> ${esc(d.cohortName)} &nbsp;·&nbsp; <strong>Submitted by:</strong> ${esc(d.username)}<br>
      <strong>Date:</strong> ${date}
    </div>
  </div>

  <div class="sec">
    <div class="sec-eyebrow">Setup</div>
    <div class="sec-title">Challenge Definition</div>
    <div class="meta-grid">
      <span class="meta-label">Industry</span><span class="meta-val">${esc(d.industry) || '—'}</span>
      <span class="meta-label">Challenge</span><span class="meta-val" style="font-weight:700;color:#002A5C">${esc(d.challengeName) || '—'}</span>
      <span class="meta-label">Description</span><span class="meta-val" style="line-height:1.6">${esc(d.challengeDesc) || '—'}</span>
    </div>
  </div>

  <div class="sec">
    <div class="sec-eyebrow">Question 1</div>
    <div class="sec-title">Stakeholder Analysis</div>
    <table>
      <thead><tr><th>Category</th><th>Who</th><th>Pressure</th><th>Business Impact</th><th>Opportunity</th></tr></thead>
      <tbody>${sthRows}</tbody>
    </table>
  </div>

  <div class="sec">
    <div class="sec-eyebrow">Question 2</div>
    <div class="sec-title">Strategic Lever</div>
    <div class="meta-grid">
      <span class="meta-label">Lever</span><span class="meta-val" style="font-weight:700;color:#002A5C">${esc(LEVER_LABELS_LOCAL[d.lever] || d.lever) || '—'}</span>
      ${d.marketSegment ? `<span class="meta-label">Target segment</span><span class="meta-val">${esc(d.marketSegment)}</span>` : ''}
      <span class="meta-label">Strategic path</span><span class="meta-val" style="line-height:1.6">${esc(d.leverDetail) || '—'}</span>
    </div>
  </div>

  <div class="sec">
    <div class="sec-eyebrow">Question 3</div>
    <div class="sec-title">NPV+ Valuation</div>
    <div class="kpi-row">
      <div class="kpi"><div class="kpi-label">Annual net benefit</div><div class="kpi-val ${totAnn>=0?'pos':'neg'}">${fmtMoney(totAnn,cur)}</div></div>
      <div class="kpi"><div class="kpi-label">NPV+ at 5 years</div><div class="kpi-val ${npv5>=0?'pos':'neg'}">${fmtMoney(npv5,cur)}</div></div>
      <div class="kpi"><div class="kpi-label">NPV+ at 10 years</div><div class="kpi-val ${npv10>=0?'pos':'neg'}">${fmtMoney(npv10,cur)}</div></div>
    </div>
    <table>
      <thead><tr><th>Benefit line</th><th style="text-align:right">Annual</th><th style="text-align:right">NPV 5yr</th><th style="text-align:right">NPV 10yr</th></tr></thead>
      <tbody>
        ${capex > 0 ? `<tr><td style="color:#C0392B">CAPEX</td><td style="text-align:right;color:#C0392B;font-weight:600">−${fmtMoney(capex,cur)}</td><td style="text-align:right;color:#C0392B">−${fmtMoney(capex,cur)}</td><td style="text-align:right;color:#C0392B">−${fmtMoney(capex,cur)}</td></tr>` : ''}
        ${benRows}
      </tbody>
    </table>
    <div style="margin-top:1rem;padding:0.9rem 1.1rem;background:#EEF6FB;border-left:4px solid #C9A84C;border-radius:0 6px 6px 0"><div style="font-size:7.5pt;font-weight:700;letter-spacing:0.1em;text-transform:uppercase;color:#8B6914;margin-bottom:0.4rem">CFO Pitch</div><div style="font-size:10pt;line-height:1.65">${esc(d.pitch) || '<em style="color:#aaa">—</em>'}</div></div>
  </div>

  ${d.consultantHtml ? `
  <div class="ai-sec">
    <div class="ai-inner">
      <div class="sec-eyebrow" style="padding-top:0.25rem">Strategic Advisor Brief</div>
      <div class="sec-title">Business Model &amp; Implementation Plan</div>
      ${d.consultantHtml}
    </div>
  </div>` : ''}

  ${d.reportHtml ? `
  <div class="ai-sec" style="border-top:2px solid #C9A84C">
    <div class="ai-inner">
      <div class="sec-eyebrow" style="padding-top:0.25rem;color:#8B6914">AI CFO Report</div>
      <div class="sec-title">Investment-Grade Executive Memo</div>
      ${d.reportHtml}
    </div>
  </div>` : ''}

  <div class="doc-footer">
    <span class="doc-footer-brand">© AcpitConsulting · Sustainability Strategy Compass</span>
    <span>${date}</span>
  </div>
</div>
</body></html>`;
}

async function sendEmail(d) {
  const activeSth = (d.stakeholders || []).filter(s => s.on);
  const esc = s => (s || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  const sthRows = activeSth.length
    ? activeSth.map(s => `
        <tr>
          <td style="padding:8px 12px;border-bottom:1px solid #EEF2F8;font-size:0.83rem;color:#555">${STH_LABELS[s.id] || s.id}</td>
          <td style="padding:8px 12px;border-bottom:1px solid #EEF2F8;font-size:0.83rem">${esc(s.who) || '—'}</td>
          <td style="padding:8px 12px;border-bottom:1px solid #EEF2F8;font-size:0.83rem">${esc(s.pressure) || '—'}</td>
          <td style="padding:8px 12px;border-bottom:1px solid #EEF2F8;font-size:0.83rem">${esc(s.opp) || '—'}</td>
        </tr>`).join('')
    : `<tr><td colspan="4" style="padding:10px 12px;color:#bbb;font-style:italic;font-size:0.83rem">No stakeholders entered</td></tr>`;

  const benRows = (d.benefitLines || []).length
    ? (d.benefitLines || []).map(l => `
        <tr>
          <td style="padding:8px 12px;border-bottom:1px solid #EEF2F8;font-size:0.83rem">${esc(l.blabel || l.opp) || '—'}</td>
          <td style="padding:8px 12px;border-bottom:1px solid #EEF2F8;font-size:0.83rem;font-weight:600;color:#002A5C">${fmtMoney(l.ann, d.currency)}/yr</td>
        </tr>`).join('')
    : `<tr><td colspan="2" style="padding:10px 12px;color:#bbb;font-style:italic;font-size:0.83rem">No benefit lines entered</td></tr>`;

  const hd = (label) => `<h3 style="font-family:Georgia,serif;color:#002A5C;font-size:0.95rem;font-weight:700;border-bottom:2px solid #4AABE8;padding-bottom:6px;margin:24px 0 14px">${label}</h3>`;
  const metaRow = (label, val, bold) => `<tr>
    <td style="padding:5px 0;color:#888;font-size:0.82rem;width:140px;vertical-align:top">${label}</td>
    <td style="padding:5px 0;font-size:0.88rem;${bold?'font-weight:600;color:#002A5C':''}">${val || '—'}</td></tr>`;
  const thStyle = 'padding:9px 12px;text-align:left;font-weight:600;font-size:0.78rem;background:#002A5C;color:white';

  const body = `<div style="font-family:'DM Sans',system-ui,sans-serif;max-width:700px;margin:0 auto;background:#F0F4F8;padding:1.5rem">
<div style="background:white;border-radius:12px;overflow:hidden;box-shadow:0 2px 16px rgba(0,42,92,0.1)">

  <!-- HEADER -->
  <div style="background:#002A5C;padding:24px 32px 20px">
    <div style="font-size:8pt;font-weight:600;letter-spacing:0.15em;text-transform:uppercase;color:rgba(255,255,255,0.4);margin-bottom:6px">Sustainability Strategy Compass</div>
    <div style="font-family:Georgia,serif;font-size:17pt;font-weight:700;color:white;line-height:1.2;margin-bottom:4px">${esc(d.challengeName) || 'Submission Report'}</div>
    <div style="height:3px;background:#C9A84C;width:48px;margin:12px 0 10px;border-radius:2px"></div>
    <div style="font-size:8.5pt;color:rgba(255,255,255,0.5);line-height:1.9">
      <strong style="color:rgba(255,255,255,0.8)">${esc(d.groupName) || 'Group'}</strong> &nbsp;·&nbsp;
      ${esc(d.cohortName) || 'No cohort'} &nbsp;·&nbsp;
      ${new Date().toLocaleString('en-GB', { dateStyle: 'long', timeStyle: 'short' })}
    </div>
  </div>

  <!-- BODY -->
  <div style="padding:24px 32px">

    ${hd('Submission Details')}
    <table style="width:100%;border-collapse:collapse;margin-bottom:4px">
      ${metaRow('Username', `<code style="background:#F0F4F8;padding:2px 6px;border-radius:4px;font-size:0.82rem">${esc(d.username)}</code>`)}
      ${metaRow('Industry', esc(d.industry))}
      ${metaRow('Challenge', esc(d.challengeName), true)}
      ${metaRow('Description', `<span style="line-height:1.55">${esc(d.challengeDesc)}</span>`)}
    </table>

    ${hd('Financial Summary')}
    <table style="width:100%;border-collapse:collapse;margin-bottom:4px">
      ${metaRow('Strategic Lever', LEVER_LABELS[d.lever] || d.lever, true)}
      ${metaRow('Discount Rate', `${d.rate || '—'}%`)}
      ${metaRow('NPV+ at 5 years', `<span style="color:#1B6B3A;font-weight:700">${fmtMoney(d.npv5, d.currency)}</span>`)}
      ${metaRow('NPV+ at 10 years', `<span style="color:#1B6B3A;font-weight:700">${fmtMoney(d.npv10, d.currency)}</span>`)}
    </table>

    ${hd('Q1 — Stakeholder Analysis')}
    <table style="width:100%;border-collapse:collapse;margin-bottom:4px">
      <thead><tr>
        <th style="${thStyle}">Category</th>
        <th style="${thStyle}">Who</th>
        <th style="${thStyle}">Pressure</th>
        <th style="${thStyle}">Opportunity</th>
      </tr></thead>
      <tbody>${sthRows}</tbody>
    </table>

    ${hd('Q3 — Benefit Lines')}
    <table style="width:100%;border-collapse:collapse;margin-bottom:4px">
      <thead><tr>
        <th style="${thStyle}">Benefit</th>
        <th style="${thStyle}">Annual Value</th>
      </tr></thead>
      <tbody>${benRows}</tbody>
    </table>

    <div style="margin-top:20px;padding:12px 16px;background:#EEF6FB;border-left:4px solid #4AABE8;border-radius:0 6px 6px 0;font-size:0.8rem;color:#334">
      The full AI-generated CFO Report is attached as an HTML file. Open in any browser, then File → Print → Save as PDF for a formatted copy.
    </div>
  </div>

  <!-- FOOTER -->
  <div style="background:#F8FAFC;border-top:1px solid #D5E6F5;padding:12px 32px;display:flex;justify-content:space-between;font-size:7.5pt;color:#bbb">
    <span style="color:#002A5C;font-weight:600">© AcpitConsulting · Sustainability Strategy Compass</span>
    <span>${new Date().toLocaleDateString('en-GB', { dateStyle: 'long' })}</span>
  </div>

</div></div>`;

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      from:    'SustComp <onboarding@resend.dev>',
      to:      ['atalay.atasu@googlemail.com'],
      subject: `[SustComp] ${d.cohortName || 'No cohort'} — ${d.groupName || d.username} — ${d.challengeName || 'Submission'}`,
      html:    body,
      attachments: [
        {
          filename: `cfo-report-${d.username}-${Date.now()}.html`,
          content:  Buffer.from(buildReportDoc(d)).toString('base64')
        },
        {
          filename: `complete-submission-${d.username}-${Date.now()}.html`,
          content:  Buffer.from(buildCompleteDoc(d)).toString('base64')
        }
      ]
    })
  });
  if (!res.ok) {
    const err = await res.json();
    console.error('Resend rejected email:', res.status, JSON.stringify(err));
    throw new Error(err.message || `Resend ${res.status}: ${JSON.stringify(err)}`);
  }
}

// ── HTML TEMPLATES ─────────────────────────────────────────────────────────

const FONTS = `<link href="https://fonts.googleapis.com/css2?family=DM+Sans:opsz,wght@9..40,400;9..40,500&display=swap" rel="stylesheet">`;

const SHARED_CSS = `
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'DM Sans',system-ui,sans-serif;background:#004080;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1.5rem}
  .card{background:white;border-radius:16px;padding:2.5rem;width:100%;max-width:420px;box-shadow:0 24px 64px rgba(0,0,0,0.35)}
  .brand{text-align:center;margin-bottom:2rem}
  .brand-title{font-family:Georgia,serif;font-weight:700;font-size:1.3rem;color:#002A5C;line-height:1.35}
  .divider{height:1px;background:#eee;margin:0 0 1.75rem}
  label{display:block;font-size:0.78rem;font-weight:500;color:#444;margin-bottom:0.35rem}
  input[type=text],input[type=password],input[type=datetime-local],select,textarea{width:100%;padding:0.62rem 0.9rem;border:1px solid #D0D8E8;border-radius:8px;font-family:inherit;font-size:0.88rem;outline:none;transition:border 0.15s,box-shadow 0.15s;color:#1A1A1A;background:white}
  input:focus,select:focus,textarea:focus{border-color:#004080;box-shadow:0 0 0 3px rgba(0,64,128,0.1)}
  .field{margin-bottom:1rem}
  .btn{width:100%;padding:0.72rem;background:#4AABE8;color:white;border:none;border-radius:8px;font-family:inherit;font-size:0.92rem;font-weight:500;cursor:pointer;margin-top:0.25rem;transition:filter 0.15s}
  .btn:hover{filter:brightness(1.08)}
  .error{background:#FEF2F2;border:1px solid #FCA5A5;color:#B91C1C;border-radius:8px;padding:0.65rem 0.9rem;font-size:0.82rem;margin-bottom:1rem}
  .success{background:#F0F9FF;border:1px solid #BAE6FD;color:#0369A1;border-radius:8px;padding:0.65rem 0.9rem;font-size:0.82rem;margin-bottom:1rem}
  .footer{text-align:center;margin-top:1.5rem;font-size:0.72rem;color:#bbb}
  .footer a{color:#bbb}`;

function loginHTML(error = '') {
  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Sign In — Sustainability Strategy Compass</title>${FONTS}
<style>${SHARED_CSS}</style></head><body>
<div class="card">
  <div class="brand">
    <div class="brand-title">Sustainability Strategy Compass</div>
  </div>
  <div class="divider"></div>
  ${error ? `<div class="error">${error}</div>` : ''}
  <form method="POST" action="/login">
    <div class="field"><label for="u">Username</label>
      <input id="u" type="text" name="username" autocomplete="username" required autofocus></div>
    <div class="field"><label for="p">Password</label>
      <input id="p" type="password" name="password" autocomplete="current-password" required></div>
    <button class="btn" type="submit">Sign in →</button>
  </form>
  <div class="footer">© 2026 AcpitConsulting<br>
    <a href="mailto:atalay.atasu@googlemail.com">atalay.atasu@googlemail.com</a></div>
</div></body></html>`;
}

function adminLoginHTML(error = '') {
  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Admin — SustComp</title>${FONTS}
<style>${SHARED_CSS}</style></head><body>
<div class="card">
  <div class="brand"><div class="brand-title">Admin Panel</div></div>
  <div class="divider"></div>
  ${error ? `<div class="error">${error}</div>` : ''}
  <form method="POST" action="/admin/login">
    <div class="field"><label for="p">Admin Password</label>
      <input id="p" type="password" name="password" required autofocus></div>
    <button class="btn" type="submit">Enter →</button>
  </form>
</div></body></html>`;
}

function statusBadge(expiresAt, lastLogin) {
  const now   = new Date();
  const expDt = new Date(expiresAt);
  if (expDt < now)
    return `<span style="background:#FEE2E2;color:#B91C1C;padding:2px 8px;border-radius:20px;font-size:0.7rem;font-weight:600">Expired</span>`;
  if (!lastLogin)
    return `<span style="background:#FEF9C3;color:#854D0E;padding:2px 8px;border-radius:20px;font-size:0.7rem;font-weight:600">Never logged in</span>`;
  return `<span style="background:#DCFCE7;color:#166534;padding:2px 8px;border-radius:20px;font-size:0.7rem;font-weight:600">Active</span>`;
}

function fmtDt(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleString('en-GB', { dateStyle: 'short', timeStyle: 'short' });
}

function adminHTML(cohorts, users, submissions, msg) {
  const msgBox = msg
    ? `<div class="${msg.startsWith('Error') ? 'msg-error' : 'msg-ok'}">${decodeURIComponent(msg)}</div>`
    : '';

  const defaultExpiry = (() => {
    const d = new Date(); d.setDate(d.getDate() + 7);
    return d.toISOString().slice(0, 16);
  })();

  const cohortOptions = cohorts.map(c =>
    `<option value="${c.id}">${c.name}</option>`).join('');

  const cohortRows = cohorts.map(c => `
    <tr>
      <td>${c.name}</td>
      <td style="font-family:monospace;font-size:0.78rem;color:#888">${c.api_key ? '••••••••' + c.api_key.slice(-4) : '—'}</td>
      <td>${c.user_count} user${c.user_count !== 1 ? 's' : ''}</td>
      <td>${fmtDt(c.created_at)}</td>
      <td>
        <form method="POST" action="/admin/cohorts/${c.id}/delete" style="display:inline"
              onsubmit="return confirm('Delete cohort ${c.name}? Users will lose their cohort assignment.')">
          <button type="submit" class="del-btn">Delete</button>
        </form>
      </td>
    </tr>`).join('') || `<tr><td colspan="5" class="empty">No cohorts yet</td></tr>`;

  const userRows = users.map(u => `
    <tr>
      <td><strong>${u.username}</strong></td>
      <td>${u.cohort_name || '<span style="color:#ccc">—</span>'}</td>
      <td>${fmtDt(u.expires_at)}</td>
      <td>${fmtDt(u.last_login)}</td>
      <td>${statusBadge(u.expires_at, u.last_login)}</td>
      <td style="display:flex;gap:6px;flex-wrap:wrap">
        <form method="POST" action="/admin/users/${u.id}/reset" style="display:inline"
              onsubmit="return confirm('Reset progress for ${u.username}? This clears their draft so they start from scratch. Their submitted reports are kept.')">
          <button type="submit" class="del-btn" style="background:#E67E22;border-color:#E67E22">↺ Reset</button>
        </form>
        <form method="POST" action="/admin/users/${u.id}/delete" style="display:inline"
              onsubmit="return confirm('Delete user ${u.username}? Their submitted reports will be kept but the account will be removed.')">
          <button type="submit" class="del-btn">Delete</button>
        </form>
      </td>
    </tr>`).join('') || `<tr><td colspan="6" class="empty">No users yet</td></tr>`;

  const subRows = submissions.map(s => {
    const isExt = s.version === 'extended';
    const vBadge = isExt
      ? `<span style="background:#7C3AED;color:white;border-radius:10px;font-size:0.65rem;padding:1px 7px;font-weight:600;margin-left:5px">Extended</span>`
      : `<span style="background:#0070CC;color:white;border-radius:10px;font-size:0.65rem;padding:1px 7px;font-weight:600;margin-left:5px">Basic</span>`;
    const completeLink = isExt
      ? `<a href="/admin/submissions/${s.id}/complete-ext" target="_blank" class="view-link" style="background:#F3E8FF;color:#7C3AED;border:1px solid #C4B5FD;border-radius:4px;padding:2px 8px;text-decoration:none;font-size:0.75rem">Complete →</a>`
      : `<a href="/admin/submissions/${s.id}/complete" target="_blank" class="view-link" style="background:#E8F5E9;color:#2E7D32;border:1px solid #A5D6A7;border-radius:4px;padding:2px 8px;text-decoration:none;font-size:0.75rem">Complete →</a>`;
    const emailStatus = s.email_status || 'pending';
    const emailBadge = emailStatus === 'sent'
      ? `<span title="Email delivered" style="color:#16a34a;font-size:0.85rem">✓ sent</span>`
      : emailStatus === 'failed'
      ? `<span title="${(s.email_error||'').replace(/"/g,'&quot;')}" style="color:#dc2626;font-size:0.85rem;cursor:help">✗ failed</span>`
      : `<span style="color:#9ca3af;font-size:0.85rem">⏳ pending</span>`;
    const retryBtn = emailStatus !== 'sent'
      ? `<form method="POST" action="/admin/submissions/${s.id}/resend-email" style="margin:0">
           <button type="submit" style="background:none;border:1px solid #93c5fd;color:#1d4ed8;border-radius:4px;padding:2px 8px;cursor:pointer;font-size:0.7rem;font-family:inherit">Retry</button>
         </form>`
      : '';
    return `
    <tr>
      <td><strong>${s.username}</strong>${vBadge}</td>
      <td>${s.cohort_name || '—'}</td>
      <td>${s.group_name || '—'}</td>
      <td>${s.challenge_name || '—'}</td>
      <td>${fmtDt(s.submitted_at)}</td>
      <td style="white-space:nowrap">${emailBadge}${retryBtn}</td>
      <td style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap">
        <a href="/admin/submissions/${s.id}/report" target="_blank" class="view-link" style="background:#EBF5FF;color:#004080;border:1px solid #BAD4F0;border-radius:4px;padding:2px 8px;text-decoration:none;font-size:0.75rem">CFO Report →</a>
        ${completeLink}
        <form method="POST" action="/admin/submissions/${s.id}/delete" style="margin:0" onsubmit="return confirm('Delete this submission? This cannot be undone.')">
          <button type="submit" style="background:none;border:1px solid #e88;color:#c33;border-radius:4px;padding:2px 8px;cursor:pointer;font-size:0.75rem;font-family:inherit">Delete</button>
        </form>
      </td>
    </tr>`;
  }).join('') || `<tr><td colspan="7" class="empty">No submissions yet</td></tr>`;

  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Admin Panel — SustComp</title>${FONTS}
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'DM Sans',system-ui,sans-serif;background:#EAF2FA;min-height:100vh;padding:0 0 3rem}
  .hdr{background:#004080;color:white;padding:0 2rem;height:60px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:10}
  .hdr-title{font-family:Georgia,serif;font-size:1.05rem;font-weight:700}
  .hdr-sub{font-size:0.72rem;opacity:0.55;margin-top:2px}
  .logout{color:rgba(255,255,255,0.5);font-size:0.78rem;text-decoration:none}
  .logout:hover{color:white}
  .wrap{max-width:1000px;margin:2rem auto;padding:0 1.5rem}
  .msg-ok{background:#F0F9FF;border:1px solid #BAE6FD;color:#0369A1;border-radius:8px;padding:0.7rem 1rem;font-size:0.85rem;margin-bottom:1.5rem}
  .msg-error{background:#FEF2F2;border:1px solid #FCA5A5;color:#B91C1C;border-radius:8px;padding:0.7rem 1rem;font-size:0.85rem;margin-bottom:1.5rem}
  .panel{background:white;border-radius:12px;padding:1.75rem;margin-bottom:1.5rem;border:1px solid rgba(0,0,0,0.07)}
  .panel-title{font-family:Georgia,serif;font-size:1rem;font-weight:700;color:#002A5C;margin-bottom:1.25rem;padding-bottom:0.75rem;border-bottom:1px solid #eee;display:flex;align-items:center;gap:0.5rem}
  .badge{background:#004080;color:white;border-radius:20px;font-size:0.68rem;font-family:'DM Sans',sans-serif;font-weight:500;padding:2px 8px}
  .form-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:0.75rem;align-items:end}
  .form-grid .full{grid-column:1/-1}
  label{display:block;font-size:0.76rem;font-weight:500;color:#555;margin-bottom:0.3rem}
  input,select{width:100%;padding:0.55rem 0.8rem;border:1px solid #D0D8E8;border-radius:7px;font-family:inherit;font-size:0.85rem;outline:none;color:#1A1A1A;background:white}
  input:focus,select:focus{border-color:#004080;box-shadow:0 0 0 3px rgba(0,64,128,0.08)}
  .sub-btn{padding:0.55rem 1.25rem;background:#4AABE8;color:white;border:none;border-radius:7px;font-family:inherit;font-size:0.85rem;font-weight:500;cursor:pointer;white-space:nowrap;height:fit-content}
  .sub-btn:hover{filter:brightness(1.08)}
  table{width:100%;border-collapse:collapse;font-size:0.85rem}
  th{text-align:left;padding:0.5rem 0.75rem;font-size:0.72rem;color:#888;font-weight:500;text-transform:uppercase;letter-spacing:0.05em;border-bottom:1px solid #eee}
  td{padding:0.6rem 0.75rem;border-bottom:1px solid #f5f5f5;vertical-align:middle}
  tr:last-child td{border-bottom:none}
  .empty{text-align:center;color:#ccc;padding:1.5rem;font-style:italic}
  .del-btn{background:none;border:1px solid #FCA5A5;color:#EF4444;border-radius:5px;padding:2px 8px;font-size:0.75rem;cursor:pointer;font-family:inherit}
  .del-btn:hover{background:#FEF2F2}
  .view-link{color:#004080;font-size:0.82rem;font-weight:500}
  .section-title{font-size:0.72rem;font-weight:600;color:#888;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:0.75rem}
</style>
</head><body>

<div class="hdr">
  <div>
    <div class="hdr-title">Admin Panel</div>
    <div class="hdr-sub">SustComp · AcpitConsulting</div>
  </div>
  <div style="display:flex;align-items:center;gap:1.5rem">
    <a href="/admin/test-email" style="color:rgba(255,255,255,0.55);font-size:0.78rem;text-decoration:none" title="Send a test email to verify Resend is working">Test email</a>
    <a class="logout" href="/admin/logout">Sign out</a>
  </div>
</div>

<div class="wrap">
  ${msgBox}

  <!-- COHORTS -->
  <div class="panel">
    <div class="panel-title">Cohorts <span class="badge">${cohorts.length}</span></div>
    <div class="section-title">Create new cohort</div>
    <form method="POST" action="/admin/cohorts" style="margin-bottom:1.5rem">
      <div class="form-grid">
        <div>
          <label>Cohort name *</label>
          <input type="text" name="name" placeholder="e.g. MBA May 2026" required>
        </div>
        <div>
          <label>Anthropic API key *</label>
          <input type="text" name="api_key" placeholder="sk-ant-api03-…" required>
        </div>
        <div style="display:flex;align-items:flex-end">
          <button type="submit" class="sub-btn">Create cohort</button>
        </div>
      </div>
    </form>
    <div class="section-title">Existing cohorts</div>
    <table>
      <thead><tr>
        <th>Name</th><th>API Key</th><th>Users</th><th>Created</th><th></th>
      </tr></thead>
      <tbody>${cohortRows}</tbody>
    </table>
  </div>

  <!-- USERS -->
  <div class="panel">
    <div class="panel-title">Users <span class="badge">${users.length}</span></div>
    <div class="section-title">Create new user</div>
    <form method="POST" action="/admin/users" style="margin-bottom:1.5rem">
      <div class="form-grid">
        <div>
          <label>Username *</label>
          <input type="text" name="username" placeholder="e.g. team_alpha" required>
        </div>
        <div>
          <label>Password *</label>
          <input type="text" name="password" placeholder="Set a password" required>
        </div>
        <div>
          <label>Cohort</label>
          <select name="cohort_id">
            <option value="">— no cohort —</option>
            ${cohortOptions}
          </select>
        </div>
        <div>
          <label>Access expires *</label>
          <input type="datetime-local" name="expires_at" value="${defaultExpiry}" required>
        </div>
        <div style="display:flex;align-items:flex-end">
          <button type="submit" class="sub-btn">Create user</button>
        </div>
      </div>
    </form>
    <div class="section-title">All users</div>
    <table>
      <thead><tr>
        <th>Username</th><th>Cohort</th><th>Expires</th><th>Last login</th><th>Status</th><th></th>
      </tr></thead>
      <tbody>${userRows}</tbody>
    </table>
  </div>

  <!-- SUBMISSIONS -->
  <div class="panel">
    <div class="panel-title">Submissions <span class="badge">${submissions.length}</span></div>
    <table>
      <thead><tr>
        <th>Username</th><th>Cohort</th><th>Group</th><th>Challenge</th><th>Submitted</th><th>Email</th><th>Actions</th>
      </tr></thead>
      <tbody>${subRows}</tbody>
    </table>
  </div>

</div></body></html>`;
}

// ── LANDING PAGE ───────────────────────────────────────────────────────────

function landingHTML(username) {
  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Sustainability Strategy Compass</title>${FONTS}
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'DM Sans',system-ui,sans-serif;background:#EAF2FA;min-height:100vh;display:flex;flex-direction:column}
.hdr{background:#004080;padding:0 2rem;height:60px;display:flex;align-items:center;justify-content:space-between}
.hdr-brand{display:flex;align-items:center;gap:10px}
.hdr-title{font-family:'Playfair Display',Georgia,serif;font-size:1rem;color:white;font-weight:700}
.hdr-right{font-size:0.78rem;color:rgba(255,255,255,0.5)}
.hdr-right a{color:rgba(255,255,255,0.5);text-decoration:none} .hdr-right a:hover{color:white}
.main{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:3rem 1.5rem}
.eyebrow{font-size:0.72rem;font-weight:600;letter-spacing:0.14em;text-transform:uppercase;color:#0070CC;margin-bottom:0.5rem}
h1{font-family:'Playfair Display',Georgia,serif;font-size:1.75rem;font-weight:700;color:#002A5C;text-align:center;margin-bottom:0.4rem}
.sub{font-size:0.9rem;color:#888;margin-bottom:2.5rem;text-align:center}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1.5rem;max-width:700px;width:100%}
.card{background:white;border-radius:14px;padding:2rem 1.75rem;border:2px solid #E0EAF4;text-decoration:none;color:inherit;transition:all 0.18s;display:flex;flex-direction:column;gap:0.75rem}
.card:hover{border-color:#004080;box-shadow:0 8px 32px rgba(0,64,128,0.12);transform:translateY(-2px)}
.card-tag{font-size:0.65rem;font-weight:700;letter-spacing:0.12em;text-transform:uppercase;padding:3px 10px;border-radius:20px;align-self:flex-start}
.tag-basic{background:#DBEAFE;color:#1565C0}
.tag-ext{background:#EDE9FE;color:#6D28D9}
.card-title{font-family:'Playfair Display',Georgia,serif;font-size:1.15rem;font-weight:700;color:#002A5C}
.card-desc{font-size:0.85rem;color:#666;line-height:1.6}
.card-steps{margin-top:0.25rem}
.card-step{font-size:0.78rem;color:#888;padding:0.18rem 0;display:flex;align-items:center;gap:0.4rem}
.card-step::before{content:'›';color:#0070CC;font-weight:600}
.card-arrow{margin-top:0.75rem;font-size:0.82rem;font-weight:600;color:#004080;align-self:flex-end}
.card.ext{border-color:#E9D5FF} .card.ext:hover{border-color:#7C3AED;box-shadow:0 8px 32px rgba(124,58,237,0.12)}
.card.ext .card-arrow{color:#6D28D9}
</style></head><body>
<div class="hdr">
  <div class="hdr-brand">
    <svg width="32" height="32" viewBox="0 0 44 44" fill="none"><circle cx="22" cy="22" r="19.5" stroke="white" stroke-width="2"/><ellipse cx="22" cy="22" rx="19.5" ry="8" stroke="white" stroke-width="1.3"/><ellipse cx="22" cy="22" rx="10.5" ry="19.5" stroke="white" stroke-width="1.3"/><line x1="2.5" y1="22" x2="41.5" y2="22" stroke="white" stroke-width="1.3"/><line x1="22" y1="2.5" x2="22" y2="41.5" stroke="white" stroke-width="1.3"/></svg>
    <div class="hdr-title">Sustainability Strategy Compass</div>
  </div>
  <div class="hdr-right">Welcome, ${username} &nbsp;·&nbsp; <a href="/logout">Sign out</a></div>
</div>
<div class="main">
  <div class="eyebrow">AcpitConsulting · Executive Education</div>
  <h1>Choose your programme version</h1>
  <p class="sub">Select the version assigned by your instructor.</p>
  <div class="cards">
    <a class="card" href="/basic">
      <span class="card-tag tag-basic">Standard</span>
      <div class="card-title">Sustainability Strategy Compass</div>
      <div class="card-desc">A focused four-stage analysis from stakeholder mapping through NPV+ valuation to AI-generated executive reports.</div>
      <div class="card-steps">
        <div class="card-step">Q1 · Stakeholder analysis</div>
        <div class="card-step">Q2 · Strategic lever selection</div>
        <div class="card-step">Q3 · NPV+ financial model</div>
        <div class="card-step">AI Strategic Advisor &amp; CFO Report</div>
      </div>
      <div class="card-arrow">Start Standard →</div>
    </a>
    <a class="card ext" href="/extended">
      <span class="card-tag tag-ext">Extended</span>
      <div class="card-title">Deep Strategy Analysis</div>
      <div class="card-desc">An extended deep-dive adding market context, industry sustainability track record, and a detailed triple-win strategic opportunity analysis.</div>
      <div class="card-steps">
        <div class="card-step">Market context &amp; industry track record</div>
        <div class="card-step">Q1 · Stakeholder analysis</div>
        <div class="card-step">Q2 · Triple-win strategic opportunity</div>
        <div class="card-step">Q3 · NPV+ financial model</div>
        <div class="card-step">AI Strategic Advisor &amp; CFO Report</div>
      </div>
      <div class="card-arrow">Start Extended →</div>
    </a>
  </div>
</div>
</body></html>`;
}

// ── START ──────────────────────────────────────────────────────────────────

initDB().then(() => {
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}).catch(e => {
  console.error('DB init failed:', e);
  process.exit(1);
});
