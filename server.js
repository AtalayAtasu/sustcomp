const express = require('express');
const session = require('express-session');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: false }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 8 * 60 * 60 * 1000
  }
}));

function getUsers() {
  try { return JSON.parse(process.env.USERS || '[]'); }
  catch { return []; }
}

function requireLogin(req, res, next) {
  if (req.session.user) return next();
  res.redirect('/login');
}

function requireAdmin(req, res, next) {
  if (req.session.isAdmin) return next();
  res.redirect('/admin/login');
}

// ── USER LOGIN ─────────────────────────────────────────────────────────────

app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/');
  res.send(loginHTML());
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const users = getUsers();
  if (users.find(u => u.username === username && u.password === password)) {
    req.session.user = username;
    return res.redirect('/');
  }
  res.send(loginHTML('Invalid username or password.'));
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// ── ADMIN ──────────────────────────────────────────────────────────────────

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

app.get('/admin', requireAdmin, (req, res) => {
  res.send(adminHTML(getUsers()));
});

app.get('/admin/logout', (req, res) => {
  req.session.isAdmin = false;
  res.redirect('/admin/login');
});

// ── APP ────────────────────────────────────────────────────────────────────

app.get('/', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'app.html'));
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

// ── HTML TEMPLATES ─────────────────────────────────────────────────────────

const SHARED_CSS = `
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'DM Sans',system-ui,sans-serif;background:#004080;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1.5rem}
  .card{background:white;border-radius:16px;padding:2.5rem;width:100%;max-width:420px;box-shadow:0 24px 64px rgba(0,0,0,0.35)}
  .brand{text-align:center;margin-bottom:2rem}
  .brand-title{font-family:Georgia,serif;font-weight:700;font-size:1.3rem;color:#002A5C;letter-spacing:0.02em;line-height:1.35}
  .brand-sub{font-size:0.75rem;color:#aaa;margin-top:0.4rem;letter-spacing:0.08em;text-transform:uppercase}
  .divider{height:1px;background:#eee;margin:0 0 1.75rem}
  label{display:block;font-size:0.78rem;font-weight:500;color:#444;margin-bottom:0.35rem}
  input[type=text],input[type=password]{width:100%;padding:0.65rem 0.9rem;border:1px solid #D0D8E8;border-radius:8px;font-family:inherit;font-size:0.9rem;outline:none;transition:border 0.15s,box-shadow 0.15s;color:#1A1A1A}
  input:focus{border-color:#004080;box-shadow:0 0 0 3px rgba(0,64,128,0.1)}
  .field{margin-bottom:1.1rem}
  .btn{width:100%;padding:0.75rem;background:#C6972F;color:white;border:none;border-radius:8px;font-family:inherit;font-size:0.92rem;font-weight:500;cursor:pointer;margin-top:0.25rem;transition:filter 0.15s;letter-spacing:0.02em}
  .btn:hover{filter:brightness(1.08)}
  .error{background:#FEF2F2;border:1px solid #FCA5A5;color:#B91C1C;border-radius:8px;padding:0.65rem 0.9rem;font-size:0.82rem;margin-bottom:1.1rem}
  .footer{text-align:center;margin-top:1.5rem;font-size:0.72rem;color:#bbb}
  .footer a{color:#bbb}
`;

function loginHTML(error = '') {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Sign In — Sustainability Strategy Compass</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:opsz,wght@9..40,400;9..40,500&display=swap" rel="stylesheet">
<style>${SHARED_CSS}</style>
</head>
<body>
<div class="card">
  <div class="brand">
    <div class="brand-title">Sustainability Strategy Compass</div>
    <div class="brand-sub">AcpitConsulting · 2026</div>
  </div>
  <div class="divider"></div>
  ${error ? `<div class="error">${error}</div>` : ''}
  <form method="POST" action="/login">
    <div class="field"><label for="u">Username</label><input id="u" type="text" name="username" autocomplete="username" required autofocus></div>
    <div class="field"><label for="p">Password</label><input id="p" type="password" name="password" autocomplete="current-password" required></div>
    <button class="btn" type="submit">Sign in →</button>
  </form>
  <div class="footer"><a href="mailto:acpitcons.adm@gmail.com">acpitcons.adm@gmail.com</a></div>
</div>
</body>
</html>`;
}

function adminLoginHTML(error = '') {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Admin — Sustainability Strategy Compass</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:opsz,wght@9..40,400;9..40,500&display=swap" rel="stylesheet">
<style>${SHARED_CSS}</style>
</head>
<body>
<div class="card">
  <div class="brand">
    <div class="brand-title">Admin Panel</div>
    <div class="brand-sub">AcpitConsulting</div>
  </div>
  <div class="divider"></div>
  ${error ? `<div class="error">${error}</div>` : ''}
  <form method="POST" action="/admin/login">
    <div class="field"><label for="p">Admin Password</label><input id="p" type="password" name="password" required autofocus></div>
    <button class="btn" type="submit">Enter →</button>
  </form>
</div>
</body>
</html>`;
}

function adminHTML(users) {
  const userRows = users.length
    ? users.map((u, i) => `<tr><td>${i + 1}</td><td><strong>${u.username}</strong></td><td>••••••••</td></tr>`).join('')
    : `<tr><td colspan="3" style="text-align:center;color:#aaa;padding:1.5rem">No users yet</td></tr>`;

  const exampleJson = JSON.stringify(
    [...users.map(u => ({ username: u.username, password: u.password })), { username: 'newuser', password: 'newpassword' }],
    null, 2
  );

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Admin Panel — Sustainability Strategy Compass</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:opsz,wght@9..40,400;9..40,500&display=swap" rel="stylesheet">
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'DM Sans',system-ui,sans-serif;background:#EAF2FA;min-height:100vh;padding:2rem 1rem;color:#1A1A1A}
  .wrap{max-width:720px;margin:0 auto}
  .hdr{background:#004080;color:white;border-radius:12px;padding:1.25rem 1.75rem;display:flex;align-items:center;justify-content:space-between;margin-bottom:1.5rem}
  .hdr-title{font-family:Georgia,serif;font-size:1.15rem;font-weight:700}
  .hdr-sub{font-size:0.75rem;opacity:0.6;margin-top:2px}
  .logout{background:rgba(255,255,255,0.15);color:white;border:none;padding:0.45rem 1rem;border-radius:6px;font-family:inherit;font-size:0.82rem;cursor:pointer;text-decoration:none}
  .logout:hover{background:rgba(255,255,255,0.25)}
  .card{background:white;border-radius:12px;padding:1.75rem;margin-bottom:1.25rem;border:1px solid rgba(0,0,0,0.07)}
  .card-title{font-family:Georgia,serif;font-size:1rem;font-weight:700;color:#002A5C;margin-bottom:1.25rem;display:flex;align-items:center;gap:0.5rem}
  .badge{background:#004080;color:white;border-radius:20px;font-size:0.7rem;font-family:'DM Sans',sans-serif;font-weight:500;padding:0.15rem 0.6rem}
  table{width:100%;border-collapse:collapse;font-size:0.88rem}
  th{text-align:left;padding:0.5rem 0.75rem;font-size:0.72rem;color:#888;font-weight:500;text-transform:uppercase;letter-spacing:0.05em;border-bottom:1px solid #eee}
  td{padding:0.65rem 0.75rem;border-bottom:1px solid #f5f5f5}
  tr:last-child td{border-bottom:none}
  .step{display:flex;gap:1rem;margin-bottom:1rem;align-items:flex-start}
  .step:last-child{margin-bottom:0}
  .step-num{width:26px;height:26px;background:#004080;color:white;border-radius:50%;font-size:0.78rem;font-weight:600;display:flex;align-items:center;justify-content:center;flex-shrink:0;margin-top:1px}
  .step-body{font-size:0.87rem;color:#444;line-height:1.6}
  .step-body strong{color:#1A1A1A}
  .step-body a{color:#004080}
  pre{background:#F0F4F8;border-radius:8px;padding:1rem;font-size:0.78rem;overflow-x:auto;margin-top:0.75rem;line-height:1.6;border:1px solid #D5E6F5}
  .warn{background:#FEF9E7;border:1px solid #F9E4A0;border-radius:8px;padding:0.75rem 1rem;font-size:0.82rem;color:#7A5B14;margin-top:1rem}
</style>
</head>
<body>
<div class="wrap">
  <div class="hdr">
    <div>
      <div class="hdr-title">Admin Panel</div>
      <div class="hdr-sub">Sustainability Strategy Compass · AcpitConsulting</div>
    </div>
    <a class="logout" href="/admin/logout">Sign out</a>
  </div>

  <div class="card">
    <div class="card-title">Current Users <span class="badge">${users.length}</span></div>
    <table>
      <thead><tr><th>#</th><th>Username</th><th>Password</th></tr></thead>
      <tbody>${userRows}</tbody>
    </table>
  </div>

  <div class="card">
    <div class="card-title">Add or Remove a User</div>
    <div class="step">
      <div class="step-num">1</div>
      <div class="step-body">Go to your <strong><a href="https://dashboard.render.com" target="_blank">Render dashboard</a></strong> and open the <strong>ibsp</strong> service.</div>
    </div>
    <div class="step">
      <div class="step-num">2</div>
      <div class="step-body">Click <strong>Environment</strong> in the left sidebar, then find the <strong>USERS</strong> variable and click the pencil icon to edit it.</div>
    </div>
    <div class="step">
      <div class="step-num">3</div>
      <div class="step-body">
        Replace the value with a JSON array. Each entry needs a <strong>username</strong> and <strong>password</strong>. To add a user, append a new entry; to remove one, delete their entry. Example with a new user added:
        <pre>${exampleJson.replace(/</g, '&lt;')}</pre>
      </div>
    </div>
    <div class="step">
      <div class="step-num">4</div>
      <div class="step-body">Click <strong>Save Changes</strong>. Render will restart the service automatically — takes about 30 seconds. The new user can log in immediately after.</div>
    </div>
    <div class="warn">⚠ Passwords are stored as plain text in the environment variable. Use simple, unique passwords for each participant — not passwords they reuse elsewhere.</div>
  </div>
</div>
</body>
</html>`;
}
