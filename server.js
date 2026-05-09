'use strict';
const express  = require('express');
const session  = require('express-session');
const { Pool } = require('pg');
const bcrypt   = require('bcryptjs');
const nodemailer = require('nodemailer');
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
    await mailer.sendMail({
      from: `"SustComp Test" <${process.env.GMAIL_USER}>`,
      to:   'atalay.atasu@gmail.com',
      subject: '[SustComp] Test email — credentials OK',
      text: 'If you received this, your Gmail credentials are working correctly.'
    });
    res.send('<p style="font-family:sans-serif;padding:2rem">✅ Test email sent successfully to atalay.atasu@gmail.com — check your inbox (and spam).<br><br><a href="/admin">← Back to admin</a></p>');
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
        SELECT id, username, cohort_name, group_name, challenge_name, submitted_at
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

// Submissions — view report
app.get('/admin/submissions/:id/report', requireAdmin, async (req, res) => {
  const r = await pool.query(
    'SELECT report_html, username, challenge_name FROM submissions WHERE id = $1',
    [req.params.id]);
  if (!r.rows[0]) return res.status(404).send('Not found');
  res.type('html').send(r.rows[0].report_html || '<p>No report content saved.</p>');
});

// ── MAIN APP ───────────────────────────────────────────────────────────────

app.get('/', requireLogin, (req, res) => {
  const html = fs.readFileSync(path.join(__dirname, 'app.html'), 'utf8');
  const script = `<script>
    window.__API_KEY__   = ${JSON.stringify(req.session.user.apiKey)};
    window.__USERNAME__  = ${JSON.stringify(req.session.user.username)};
    window.__COHORT__    = ${JSON.stringify(req.session.user.cohortName)};
    window.__EXPIRES__   = ${JSON.stringify(req.session.user.expiresAt)};
  </script>`;
  res.send(html.replace('</head>', script + '</head>'));
});

// ── SUBMIT API ─────────────────────────────────────────────────────────────

app.post('/api/submit', requireLogin, async (req, res) => {
  const u = req.session.user;
  const d = req.body;
  try {
    await pool.query(`
      INSERT INTO submissions
        (user_id, username, cohort_name, group_name, industry,
         challenge_name, challenge_desc, lever, stakeholders,
         benefit_lines, npv5, npv10, rate, currency, report_html)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
      [u.id, u.username, u.cohortName,
       d.groupName||'', d.industry||'', d.challengeName||'',
       d.challengeDesc||'', d.lever||'',
       JSON.stringify(d.stakeholders||[]),
       JSON.stringify(d.benefitLines||[]),
       d.npv5||0, d.npv10||0, d.rate||0,
       d.currency||'EUR', d.reportHtml||'']);

    res.json({ success: true });

    // Send email in background — don't let email failure block the submission
    sendEmail({ ...d, username: u.username, cohortName: u.cohortName })
      .then(() => console.log(`Email sent for ${u.username}`))
      .catch(e => console.error('Email failed for', u.username, ':', e.message));

  } catch (e) {
    console.error('Submit error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ── EMAIL ──────────────────────────────────────────────────────────────────

if (!process.env.GMAIL_USER || !process.env.GMAIL_PASS) {
  console.warn('WARNING: GMAIL_USER or GMAIL_PASS not set — submission emails will fail');
} else {
  console.log('Email configured for:', process.env.GMAIL_USER);
}
const mailer = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 465,
  secure: true,
  auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_PASS }
});

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
  const sym = cur === 'USD' ? '$' : cur === 'GBP' ? '£' : '€';
  return sym + Number(n || 0).toLocaleString('en', { maximumFractionDigits: 0 });
}

async function sendEmail(d) {
  const activeSth = (d.stakeholders || []).filter(s => s.on);

  const sthRows = activeSth.length
    ? activeSth.map(s => `
        <tr>
          <td style="padding:7px 10px;border-bottom:1px solid #eee;font-size:0.85rem">${STH_LABELS[s.id] || s.id}</td>
          <td style="padding:7px 10px;border-bottom:1px solid #eee;font-size:0.85rem">${s.who || '—'}</td>
          <td style="padding:7px 10px;border-bottom:1px solid #eee;font-size:0.85rem">${s.pressure || '—'}</td>
          <td style="padding:7px 10px;border-bottom:1px solid #eee;font-size:0.85rem">${s.opp || '—'}</td>
        </tr>`).join('')
    : `<tr><td colspan="4" style="padding:10px;color:#aaa;font-style:italic">No stakeholders entered</td></tr>`;

  const benRows = (d.benefitLines || []).length
    ? (d.benefitLines || []).map(l => `
        <tr>
          <td style="padding:7px 10px;border-bottom:1px solid #eee;font-size:0.85rem">${l.blabel || l.opp || '—'}</td>
          <td style="padding:7px 10px;border-bottom:1px solid #eee;font-size:0.85rem;font-weight:600">${fmtMoney(l.ann, d.currency)}/yr</td>
        </tr>`).join('')
    : `<tr><td colspan="2" style="padding:10px;color:#aaa;font-style:italic">No benefit lines entered</td></tr>`;

  const body = `
<div style="font-family:Georgia,serif;max-width:680px;margin:0 auto;color:#1A1A1A;border:1px solid #ddd;border-radius:10px;overflow:hidden">

  <div style="background:#004080;color:white;padding:24px 32px">
    <h2 style="margin:0;font-size:1.25rem;font-weight:700">SustComp — Submission Report</h2>
    <p style="margin:6px 0 0;opacity:0.65;font-size:0.82rem">
      ${new Date().toLocaleString('en-GB', { dateStyle: 'full', timeStyle: 'short' })}
    </p>
  </div>

  <div style="padding:24px 32px;background:#f7f9fc">

    <table style="width:100%;border-collapse:collapse;margin-bottom:20px">
      <tr><td style="padding:4px 0;color:#666;font-size:0.85rem;width:150px">Cohort / Session</td>
          <td style="padding:4px 0;font-weight:700">${d.cohortName || '—'}</td></tr>
      <tr><td style="padding:4px 0;color:#666;font-size:0.85rem">Username</td>
          <td style="padding:4px 0;font-weight:700">${d.username}</td></tr>
      <tr><td style="padding:4px 0;color:#666;font-size:0.85rem">Group Name</td>
          <td style="padding:4px 0">${d.groupName || '—'}</td></tr>
    </table>

    <h3 style="color:#004080;border-bottom:2px solid #4AABE8;padding-bottom:6px;margin:20px 0 12px;font-size:1rem">Problem Definition</h3>
    <table style="width:100%;border-collapse:collapse;margin-bottom:20px">
      <tr><td style="padding:4px 0;color:#666;font-size:0.85rem;width:150px">Industry</td>
          <td style="padding:4px 0">${d.industry || '—'}</td></tr>
      <tr><td style="padding:4px 0;color:#666;font-size:0.85rem;vertical-align:top">Challenge</td>
          <td style="padding:4px 0;font-weight:700">${d.challengeName || '—'}</td></tr>
      <tr><td style="padding:4px 0;color:#666;font-size:0.85rem;vertical-align:top">Description</td>
          <td style="padding:4px 0;line-height:1.5;font-size:0.9rem">${d.challengeDesc || '—'}</td></tr>
    </table>

    <h3 style="color:#004080;border-bottom:2px solid #4AABE8;padding-bottom:6px;margin:20px 0 12px;font-size:1rem">Solutions Summary</h3>
    <table style="width:100%;border-collapse:collapse;margin-bottom:20px">
      <tr><td style="padding:4px 0;color:#666;font-size:0.85rem;width:150px">Strategic Lever</td>
          <td style="padding:4px 0;font-weight:700">${LEVER_LABELS[d.lever] || d.lever || '—'}</td></tr>
      <tr><td style="padding:4px 0;color:#666;font-size:0.85rem">Discount Rate</td>
          <td style="padding:4px 0">${d.rate || '—'}%</td></tr>
      <tr><td style="padding:4px 0;color:#666;font-size:0.85rem">NPV+ at 5 years</td>
          <td style="padding:4px 0;font-weight:700;color:#004080">${fmtMoney(d.npv5, d.currency)}</td></tr>
      <tr><td style="padding:4px 0;color:#666;font-size:0.85rem">NPV+ at 10 years</td>
          <td style="padding:4px 0;font-weight:700;color:#004080">${fmtMoney(d.npv10, d.currency)}</td></tr>
    </table>

    <h3 style="color:#004080;border-bottom:2px solid #4AABE8;padding-bottom:6px;margin:20px 0 12px;font-size:1rem">Q1 — Stakeholder Analysis</h3>
    <table style="width:100%;border-collapse:collapse;margin-bottom:20px">
      <thead>
        <tr style="background:#004080;color:white">
          <th style="padding:8px 10px;text-align:left;font-weight:500;font-size:0.78rem">Category</th>
          <th style="padding:8px 10px;text-align:left;font-weight:500;font-size:0.78rem">Who</th>
          <th style="padding:8px 10px;text-align:left;font-weight:500;font-size:0.78rem">Pressure</th>
          <th style="padding:8px 10px;text-align:left;font-weight:500;font-size:0.78rem">Opportunity</th>
        </tr>
      </thead>
      <tbody>${sthRows}</tbody>
    </table>

    <h3 style="color:#004080;border-bottom:2px solid #4AABE8;padding-bottom:6px;margin:20px 0 12px;font-size:1rem">Q3 — Benefit Lines</h3>
    <table style="width:100%;border-collapse:collapse;margin-bottom:20px">
      <thead>
        <tr style="background:#004080;color:white">
          <th style="padding:8px 10px;text-align:left;font-weight:500;font-size:0.78rem">Benefit</th>
          <th style="padding:8px 10px;text-align:left;font-weight:500;font-size:0.78rem">Annual Value</th>
        </tr>
      </thead>
      <tbody>${benRows}</tbody>
    </table>

    <p style="font-size:0.78rem;color:#999;font-style:italic;margin-top:8px">
      Full CFO report attached as HTML file. Open in any browser → File → Print → Save as PDF.
    </p>
  </div>

  <div style="background:#002A5C;color:rgba(255,255,255,0.4);padding:12px 32px;font-size:0.73rem">
    © 2026 AcpitConsulting · SustComp
  </div>
</div>`;

  await mailer.sendMail({
    from:    `"SustComp" <${process.env.GMAIL_USER}>`,
    to:      'atalay.atasu@gmail.com',
    subject: `[SustComp] ${d.cohortName || 'No cohort'} — ${d.username} — ${d.challengeName || 'Submission'}`,
    html:    body,
    attachments: [{
      filename:    `sustcomp-${d.username}-${Date.now()}.html`,
      content:     d.reportHtml || '<p>No report generated.</p>',
      contentType: 'text/html'
    }]
  });
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
    <a href="mailto:atalay.atasu@gmail.com">atalay.atasu@gmail.com</a></div>
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
      <td>
        <form method="POST" action="/admin/users/${u.id}/delete" style="display:inline"
              onsubmit="return confirm('Delete user ${u.username}?')">
          <button type="submit" class="del-btn">Delete</button>
        </form>
      </td>
    </tr>`).join('') || `<tr><td colspan="6" class="empty">No users yet</td></tr>`;

  const subRows = submissions.map(s => `
    <tr>
      <td><strong>${s.username}</strong></td>
      <td>${s.cohort_name || '—'}</td>
      <td>${s.group_name || '—'}</td>
      <td>${s.challenge_name || '—'}</td>
      <td>${fmtDt(s.submitted_at)}</td>
      <td><a href="/admin/submissions/${s.id}/report" target="_blank" class="view-link">View →</a></td>
    </tr>`).join('') || `<tr><td colspan="6" class="empty">No submissions yet</td></tr>`;

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
  <a class="logout" href="/admin/logout">Sign out</a>
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
        <th>Username</th><th>Cohort</th><th>Group</th><th>Challenge</th><th>Submitted</th><th>Report</th>
      </tr></thead>
      <tbody>${subRows}</tbody>
    </table>
  </div>

</div></body></html>`;
}

// ── START ──────────────────────────────────────────────────────────────────

initDB().then(() => {
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}).catch(e => {
  console.error('DB init failed:', e);
  process.exit(1);
});
