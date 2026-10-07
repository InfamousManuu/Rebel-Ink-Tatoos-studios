require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATABASE_URL = process.env.DATABASE_URL;
let JWT_SECRET = process.env.JWT_SECRET;
let ADMIN_SETUP_TOKEN = process.env.ADMIN_SETUP_TOKEN || '';

if (!DATABASE_URL) {
  console.error('');
  console.error('============================================================');
  console.error(' DATABASE_URL is missing');
  console.error('============================================================');
  console.error(' This app needs a PostgreSQL database.');
  console.error('');
  console.error(' Quick setup on Render (Web Service):');
  console.error('  1. Dashboard → New → PostgreSQL → create a free database.');
  console.error('  2. Open the database → copy the Internal Database URL.');
  console.error('  3. Open your Web Service → Environment → Add:');
  console.error('       DATABASE_URL  =  (paste the Internal Database URL)');
  console.error('       JWT_SECRET    =  (any long random string, 32+ chars)');
  console.error('       ADMIN_SETUP_TOKEN = (any long random string, 24+ chars)');
  console.error('  4. Save → Manual Deploy → Deploy latest commit.');
  console.error('============================================================');
  console.error('');
  process.exit(1);
}

// Auto-generate secrets if not provided (first deploy convenience).
// Prefer setting them permanently in the Render Environment tab.
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  JWT_SECRET = crypto.randomBytes(48).toString('hex');
  console.warn('JWT_SECRET was missing/short — generated a temporary one for this process.');
  console.warn('Set JWT_SECRET in the Render Environment tab so it survives restarts.');
}
if (!ADMIN_SETUP_TOKEN || ADMIN_SETUP_TOKEN.length < 24) {
  ADMIN_SETUP_TOKEN = crypto.randomBytes(24).toString('hex');
  console.warn('ADMIN_SETUP_TOKEN was missing/short — generated a temporary one for this process.');
  console.warn('Set ADMIN_SETUP_TOKEN in the Render Environment tab so the setup link stays stable.');
}

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: false, limit: '20mb' }));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many authentication attempts. Please try again later.' } });
const adminLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false });
const setupLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false });

const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 10 });

function safeUser(u) {
  if (!u) return null;
  return {
    _id: u.id,
    name: u.name,
    phone: u.phone,
    country: u.country,
    state: u.state || '',
    email: u.email,
    role: u.role,
    status: u.status,
    adminNotes: u.admin_notes || '',
    createdAt: u.created_at,
    updatedAt: u.updated_at,
    lastLoginAt: u.last_login_at || null
  };
}
function tokenFor(user) {
  return jwt.sign({ sub: user.id, role: user.role, email: user.email }, JWT_SECRET, { expiresIn: '7d', issuer: 'rebel-ink' });
}
function cleanText(value, max) { return String(value ?? '').trim().slice(0, max); }
function normalizeEmail(email) { return String(email || '').trim().toLowerCase(); }
function validPassword(pw) { return typeof pw === 'string' && pw.length >= 8 && pw.length <= 128 && /[a-zA-Z]/.test(pw) && /[0-9]/.test(pw) && /[^a-zA-Z0-9]/.test(pw); }
function validPhotos(photos) {
  if (!Array.isArray(photos) || photos.length > 5) return false;
  return photos.every(p => p && typeof p.name === 'string' && typeof p.dataUrl === 'string' && /^data:image\/(jpeg|jpg|png|webp|gif);base64,/i.test(p.dataUrl) && p.dataUrl.length <= 3_500_000);
}
function csvEscape(v) { const s = String(v ?? ''); return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; }
function sameSecret(a, b) {
  const aa = Buffer.from(String(a)); const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

const NOTIFY_WEBHOOK_URL = process.env.NOTIFY_WEBHOOK_URL || '';
async function notifyAdmin(title, lines) {
  if (!NOTIFY_WEBHOOK_URL) return;
  const textBody = ['*' + title + '*', ...lines].join('\n');
  try {
    await fetch(NOTIFY_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text: textBody,
        content: textBody,
        username: 'Rebel Ink',
        embeds: [{ title, description: lines.join('\n'), color: 0x1e3a5f }]
      })
    });
  } catch (e) {
    console.warn('Notify webhook failed:', e.message);
  }
}


async function query(text, params) { return pool.query(text, params); }

async function hasAdmin() {
  const r = await query("SELECT 1 FROM users WHERE role='admin' LIMIT 1");
  return r.rowCount > 0;
}

async function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'Authentication required.' });
  try {
    const payload = jwt.verify(token, JWT_SECRET, { issuer: 'rebel-ink' });
    const r = await query('SELECT * FROM users WHERE id=$1 LIMIT 1', [payload.sub]);
    const user = r.rows[0];
    if (!user || user.status === 'suspended') return res.status(401).json({ error: 'Account is unavailable.' });
    req.user = user; next();
  } catch (_) { return res.status(401).json({ error: 'Invalid or expired session.' }); }
}
function adminOnly(req, res, next) { if (!req.user || req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required.' }); next(); }

async function initSchema() {
  await query(`CREATE EXTENSION IF NOT EXISTS pgcrypto;`);
  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT NOT NULL,
      phone TEXT NOT NULL,
      country TEXT NOT NULL,
      state TEXT DEFAULT '',
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('member','admin')),
      status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','suspended')),
      admin_notes TEXT DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_login_at TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS users_status_created_idx ON users(status, created_at DESC);
    CREATE TABLE IF NOT EXISTS bookings (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      service TEXT NOT NULL,
      date DATE,
      problem TEXT NOT NULL,
      photos JSONB NOT NULL DEFAULT '[]'::jsonb,
      status TEXT NOT NULL DEFAULT 'Pending' CHECK (status IN ('Pending','Approved','Rejected','Done','Cancelled')),
      admin_note TEXT DEFAULT '',
      approved_at TIMESTAMPTZ,
      rejected_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS bookings_user_created_idx ON bookings(user_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS bookings_status_created_idx ON bookings(status, created_at DESC);
    CREATE INDEX IF NOT EXISTS bookings_date_idx ON bookings(date);
  `);
}

function setupPage() {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Rebel Ink — First Admin Setup</title><style>body{font-family:Arial,sans-serif;background:#f5f7fb;margin:0;padding:30px;color:#172033}.card{max-width:520px;margin:40px auto;background:#fff;padding:30px;border-radius:16px;box-shadow:0 10px 35px #0001}h1{margin-top:0}.field{margin:15px 0}label{display:block;font-weight:700;margin-bottom:7px}input{width:100%;box-sizing:border-box;padding:12px;border:1px solid #ccd4df;border-radius:8px;font-size:16px}.btn{width:100%;padding:13px;border:0;border-radius:8px;background:#1e3a5f;color:#fff;font-weight:700;font-size:16px;cursor:pointer}.msg{margin:14px 0;padding:12px;border-radius:8px;display:none;white-space:pre-wrap}.ok{background:#ecfdf5;color:#065f46}.err{background:#fef2f2;color:#991b1b}.small{font-size:13px;color:#64748b;line-height:1.5}</style></head><body><div class="card"><h1>Rebel Ink — Admin Setup</h1><p class="small">This page is only for the first administrator. Once an admin account exists, this setup route permanently closes.</p><div id="msg" class="msg"></div><form id="f"><div class="field"><label>Setup token</label><input id="token" required></div><div class="field"><label>Admin name</label><input id="name" required value="Rebel Ink Administrator"></div><div class="field"><label>Admin email</label><input id="email" type="email" required></div><div class="field"><label>Choose admin password</label><input id="password" type="password" required minlength="8"></div><div class="field"><label>Confirm password</label><input id="confirm" type="password" required minlength="8"></div><button class="btn">Create Administrator</button></form></div><script>const q=new URLSearchParams(location.search);document.getElementById('token').value=q.get('token')||'';const msg=document.getElementById('msg');document.getElementById('f').onsubmit=async e=>{e.preventDefault();msg.style.display='none';const p=document.getElementById('password').value,c=document.getElementById('confirm').value;if(p!==c){msg.className='msg err';msg.textContent='Passwords do not match.';msg.style.display='block';return}try{const r=await fetch('/api/admin/setup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:document.getElementById('token').value,name:document.getElementById('name').value,email:document.getElementById('email').value,password:p})});const d=await r.json();if(!r.ok)throw new Error(d.error||'Setup failed');msg.className='msg ok';msg.textContent=d.message+'\n\nYou can now close this page and use the Admin login on the website.';msg.style.display='block';document.getElementById('f').style.display='none'}catch(x){msg.className='msg err';msg.textContent=x.message;msg.style.display='block'}};</script></body></html>`;
}

async function start() {
  await initSchema();
  console.log('Rebel Ink database connected and schema ready.');
  if (NOTIFY_WEBHOOK_URL) console.log('Admin notifications: webhook enabled');
  else console.log('Admin notifications: set NOTIFY_WEBHOOK_URL to receive alerts on new sign-ups/bookings');
  if (!(await hasAdmin())) {
    console.log('FIRST ADMIN SETUP REQUIRED. Open /admin-setup?token=' + ADMIN_SETUP_TOKEN);
    console.log('Choose the admin email and password yourself. The setup route closes after the first admin is created.');
  }

  app.get('/api/health', async (_req, res) => res.json({ ok: true, service: 'rebel-ink', database: 'connected', time: new Date().toISOString() }));
  app.get('/admin-setup', async (_req, res) => {
    if (await hasAdmin()) return res.status(404).send('Admin setup is already completed.');
    res.type('html').send(setupPage());
  });

  app.post('/api/admin/setup', setupLimiter, async (req, res) => {
    try {
      if (await hasAdmin()) return res.status(409).json({ error: 'Admin setup has already been completed.' });
      if (!sameSecret(req.body.token || '', ADMIN_SETUP_TOKEN)) return res.status(403).json({ error: 'Invalid setup token.' });
      const name = cleanText(req.body.name, 120) || 'Rebel Ink Administrator';
      const email = normalizeEmail(req.body.email);
      const password = req.body.password || '';
      if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
      if (!validPassword(password)) return res.status(400).json({ error: 'Password must be at least 8 characters and include letters, numbers and a special character.' });
      const passwordHash = await bcrypt.hash(password, 12);
      const r = await query(`INSERT INTO users(name,phone,country,state,email,password_hash,role,status) VALUES($1,'','United States','',$2,$3,'admin','approved') RETURNING *`, [name, email, passwordHash]);
      res.status(201).json({ message: 'Administrator created successfully.', user: safeUser(r.rows[0]) });
    } catch (e) {
      if (e.code === '23505') return res.status(409).json({ error: 'That email is already registered.' });
      console.error(e); res.status(500).json({ error: 'Admin setup failed.' });
    }
  });

  app.post('/api/register', authLimiter, async (req, res) => {
    try {
      const name=cleanText(req.body.name,120), phone=cleanText(req.body.phone,40), country=cleanText(req.body.country,80), state=cleanText(req.body.state,80), email=normalizeEmail(req.body.email), password=req.body.password;
      if(!name||!phone||!country||!email||!validPassword(password)) return res.status(400).json({error:'Please provide valid registration details and a strong password.'});
      if(country==='United States'&&!state) return res.status(400).json({error:'US state is required.'});
      if(!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({error:'Enter a valid email address.'});
      const passwordHash=await bcrypt.hash(password,12);
      const r=await query(`INSERT INTO users(name,phone,country,state,email,password_hash,role,status) VALUES($1,$2,$3,$4,$5,$6,'member','pending') RETURNING *`,[name,phone,country,state,email,passwordHash]);
      notifyAdmin('New member registration', [
        'Name: ' + name,
        'Email: ' + email,
        'Phone: ' + phone,
        'Location: ' + [state, country].filter(Boolean).join(', '),
        'Status: pending approval'
      ]).catch(() => {});
      res.status(201).json({message:'Account created. Your account is pending admin approval. You will see the approval status in your member portal.',user:safeUser(r.rows[0])});
    }catch(e){if(e.code==='23505')return res.status(409).json({error:'An account with that email already exists.'});console.error(e);res.status(500).json({error:'Registration failed.'});}
  });

  app.post('/api/login', authLimiter, async (req,res)=>{
    const email=normalizeEmail(req.body.email), password=req.body.password||'';
    const r=await query('SELECT * FROM users WHERE email=$1 LIMIT 1',[email]); const user=r.rows[0];
    if(!user||!(await bcrypt.compare(password,user.password_hash)))return res.status(401).json({error:'Invalid email or password.'});
    if(user.status==='suspended')return res.status(403).json({error:'This account is suspended. Contact the administrator.'});
    await query('UPDATE users SET last_login_at=NOW(),updated_at=NOW() WHERE id=$1',[user.id]);
    res.json({token:tokenFor(user),user:safeUser(user)});
  });
  app.post('/api/admin/login', authLimiter, async(req,res)=>{
    const email=normalizeEmail(req.body.email),password=req.body.password||''; const r=await query("SELECT * FROM users WHERE email=$1 AND role='admin' LIMIT 1",[email]); const user=r.rows[0];
    if(!user||!(await bcrypt.compare(password,user.password_hash)))return res.status(401).json({error:'Invalid admin credentials.'});
    await query('UPDATE users SET last_login_at=NOW(),updated_at=NOW() WHERE id=$1',[user.id]); res.json({token:tokenFor(user),user:safeUser(user)});
  });

  app.post('/api/reset-password', authLimiter, async(_req,res)=>res.status(503).json({error:'Password reset is disabled until secure email verification is configured. Contact the administrator.'}));

  app.get('/api/me',auth,async(req,res)=>{const r=await query('SELECT * FROM bookings WHERE user_id=$1 ORDER BY created_at DESC',[req.user.id]);const bs=r.rows.map(b=>({_id:b.id,service:b.service,date:b.date?String(b.date).slice(0,10):'',problem:b.problem,photos:b.photos||[],status:b.status,adminNote:b.admin_note||'',createdAt:b.created_at,updatedAt:b.updated_at}));res.json({user:{...safeUser(req.user),bookings:bs}});});

  app.post('/api/bookings',auth,async(req,res)=>{
    if(req.user.role!=='admin'&&req.user.status!=='approved')return res.status(403).json({error:'Your account must be approved before you can book an appointment.'});
    const service=cleanText(req.body.service,180),date=cleanText(req.body.date,30),problem=cleanText(req.body.problem,5000),photos=req.body.photos||[];
    if(!service||!problem)return res.status(400).json({error:'Service and problem/goals are required.'});
    if(!validPhotos(photos))return res.status(400).json({error:'Photos must be up to 5 supported images. Please use smaller images if the upload is too large.'});
    if(date&&!/^\d{4}-\d{2}-\d{2}$/.test(date))return res.status(400).json({error:'Invalid preferred date.'});
    const r=await query(`INSERT INTO bookings(user_id,service,date,problem,photos) VALUES($1,$2,$3,$4,$5::jsonb) RETURNING *`,[req.user.id,service,date||null,problem,JSON.stringify(photos)]);const b=r.rows[0];
    notifyAdmin('New appointment request', [
      'Member: ' + (req.user.name || '') + ' <' + (req.user.email || '') + '>',
      'Service: ' + service,
      'Preferred date: ' + (date || 'not specified'),
      'Details: ' + problem.slice(0, 200)
    ]).catch(() => {});
    res.status(201).json({message:'Appointment request submitted. Admin review is required.',booking:{_id:b.id,service:b.service,date:b.date?String(b.date).slice(0,10):'',problem:b.problem,photos:b.photos,status:b.status,adminNote:b.admin_note,createdAt:b.created_at,updatedAt:b.updated_at}});
  });

  app.get('/api/admin/members',auth,adminOnly,adminLimiter,async(_req,res)=>{
    const mr=await query("SELECT * FROM users WHERE role='member' ORDER BY created_at DESC"); const br=await query('SELECT * FROM bookings ORDER BY created_at DESC'); const map=new Map();
    for(const b of br){const x={_id:b.id,service:b.service,date:b.date?String(b.date).slice(0,10):'',problem:b.problem,photos:b.photos||[],status:b.status,adminNote:b.admin_note||'',createdAt:b.created_at,updatedAt:b.updated_at};const k=b.user_id;if(!map.has(k))map.set(k,[]);map.get(k).push(x);}
    const members=mr.rows.map(u=>({...safeUser(u),bookings:map.get(u.id)||[]})); const pendingBookings=br.filter(b=>b.status==='Pending').length;
    res.json({members,stats:{total:members.length,withBookings:new Set(br.map(b=>b.user_id)).size,pending:members.filter(m=>m.status==='pending').length,pendingBookings}});
  });

  app.patch('/api/admin/members/:id/status',auth,adminOnly,async(req,res)=>{const status=req.body.status;if(!['approved','suspended','pending'].includes(status))return res.status(400).json({error:'Invalid member status.'});const r=await query("UPDATE users SET status=$1,updated_at=NOW() WHERE id=$2 AND role='member' RETURNING id",[status,req.params.id]);if(!r.rowCount)return res.status(404).json({error:'Member not found.'});res.json({message:`Member ${status}.`});});
  app.patch('/api/admin/members/:id/notes',auth,adminOnly,async(req,res)=>{const r=await query("UPDATE users SET admin_notes=$1,updated_at=NOW() WHERE id=$2 AND role='member' RETURNING id",[cleanText(req.body.notes,5000),req.params.id]);if(!r.rowCount)return res.status(404).json({error:'Member not found.'});res.json({message:'Notes saved.'});});
  app.patch('/api/admin/bookings/:userId/:bookingId/status',auth,adminOnly,async(req,res)=>{const status=req.body.status;if(!['Pending','Approved','Rejected','Done','Cancelled'].includes(status))return res.status(400).json({error:'Invalid appointment status.'});const note=cleanText(req.body.adminNote,3000);let sql='UPDATE bookings SET status=$1,admin_note=$2,updated_at=NOW()';const params=[status,note,req.params.bookingId,req.params.userId];if(status==='Approved')sql+=',approved_at=NOW()';if(status==='Rejected')sql+=',rejected_at=NOW()';sql+=' WHERE id=$3 AND user_id=$4 RETURNING id';const r=await query(sql,params);if(!r.rowCount)return res.status(404).json({error:'Appointment not found.'});res.json({message:`Appointment ${status.toLowerCase()}.`});});

  app.get('/api/admin/export',auth,adminOnly,adminLimiter,async(_req,res)=>{const mr=await query("SELECT * FROM users WHERE role='member' ORDER BY created_at DESC");const br=await query('SELECT * FROM bookings ORDER BY created_at DESC');const rows=[['Member ID','Name','Email','Phone','Country','State','Account Status','Member Since','Appointment ID','Service','Preferred Date','Appointment Status','Problem','Admin Note','Appointment Created']];for(const m of mr.rows){const mine=br.rows.filter(b=>b.user_id===m.id);if(!mine.length)rows.push([m.id,m.name,m.email,m.phone,m.country,m.state,m.status,m.created_at,'','','','','',m.admin_notes||'','']);for(const b of mine)rows.push([m.id,m.name,m.email,m.phone,m.country,m.state,m.status,m.created_at,b.id,b.service,b.date,b.status,b.problem,b.admin_note,b.created_at]);}const csv=rows.map(r=>r.map(csvEscape).join(',')).join('\r\n');res.setHeader('Content-Type','text/csv; charset=utf-8');res.setHeader('Content-Disposition','attachment; filename="rebel-ink-members.csv"');res.send('\ufeff'+csv);});

  const publicDir = path.join(__dirname, 'public');
  app.use(express.static(publicDir));
  app.use((req, res, next) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') return next();
    if (req.path.startsWith('/api')) return next();
    res.sendFile(path.join(publicDir, 'index.html'), (err) => {
      if (err) {
        console.error('sendFile error:', err.message);
        if (!res.headersSent) res.status(500).json({ error: 'Could not load page.' });
      }
    });
  });
  app.use((err, _req, res, _next) => {
    console.error(err);
    if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Request too large.' });
    if (!res.headersSent) res.status(500).json({ error: 'Server error.' });
  });
  app.listen(PORT, () => console.log(`Rebel Ink server listening on port ${PORT}`));
}

start().catch(err => { console.error('Startup failed:', err); process.exit(1); });
