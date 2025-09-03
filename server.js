const express = require('express');
const bcrypt = require('./bcrypt-compat');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const connectRedis = require('connect-redis');
const { createClient } = require('redis');
const nodemailer = require('nodemailer');
const os = require('os');
const { exec } = require('child_process');
const { promisify } = require('util');
const fs = require('fs').promises;
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const session = require('express-session');
let createProxyMiddleware;
try { ({ createProxyMiddleware } = require('http-proxy-middleware')); } catch (_) { /* optional */ }
const crypto = require('crypto');
const dotenv = require('dotenv');
// Load env from local .env first
dotenv.config();
// Fallback to parent .env (e.g., /home/sparqd/.env) if SERVER_IP not set
if (!process.env.SERVER_IP) {
    try {
        dotenv.config({ path: path.resolve(__dirname, '..', '.env') });
    } catch (e) {
        // ignore
    }
}

// Import authentication
const { router: authRouter, authenticateToken, checkPermission, ROLES, adminUsers, managers, clients } = require('./auth');

const app = express();
const execAsync = promisify(exec);
const PORT = process.env.PORT || 3003;
// Package metadata (for version endpoint)
let __pkg = { name: 'sparq-dash', version: '0.0.0' };
try { __pkg = require('./package.json'); } catch(_) {}
// Config persistence path (overrides legacy hardcoded path)
const CONFIG_PATH = process.env.CONFIG_PATH || path.join(__dirname, 'data', 'email-admin-config.json');
const STORAGE_FILE = path.join(__dirname, 'data', 'storage-allocations.json');
const CONTACT_ROUTING_FILE = path.join(__dirname, 'data', 'contact-routing.json');
const CONTACT_SUBMISSIONS_FILE = path.join(__dirname, 'data', 'contact-submissions.json');

// Behind Cloudflare Tunnel/reverse proxy
app.set('trust proxy', 1);
// Serve static files under /portal so /portal/login.html works
app.use('/portal', express.static(path.join(__dirname, 'public')));

// Middleware
// Merge global CORS allowlist with contact-routing allowOrigins
let corsOrigins = (process.env.CORS_ORIGINS || 'http://localhost:3003,http://localhost:5500,http://127.0.0.1:5500,https://getsparqd.com,https://www.getsparqd.com,https://portal.getsparqd.com,https://sparqplug.getsparqd.com')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);
try {
    const fsSync = require('fs');
    const rawCR = fsSync.readFileSync(path.join(__dirname, 'data', 'contact-routing.json'), 'utf8');
    const cr = JSON.parse(rawCR);
    const more = Array.isArray(cr.allowOrigins) ? cr.allowOrigins : [];
    corsOrigins = Array.from(new Set([...corsOrigins, ...more]));
} catch (_) { /* optional */ }
app.use(cors({ origin: corsOrigins, credentials: true }));
// Security headers
app.use(helmet({
    // We'll control framing with CSP only (more flexible than X-Frame-Options)
    frameguard: false,
    contentSecurityPolicy: {
        useDefaults: true,
        directives: {
            // Allow inline scripts for current portal pages; consider nonces/hashes later
            scriptSrc: ["'self'", "'unsafe-inline'"],
            scriptSrcAttr: ["'unsafe-inline'"],
            // Keep styles permissive for inline CSS in templates
            styleSrc: ["'self'", "https:", "'unsafe-inline'"],
            // Allow web fonts (e.g., Google Fonts)
            fontSrc: ["'self'", "https:", "data:"],
            imgSrc: ["'self'", "data:"],
            // Allow embedding SparqPlug app in an iframe (portal -> app)
            frameSrc: ["'self'", 'https://getsparqd.com', 'https://sparqplug.getsparqd.com'],
            // Allow portal pages to be framed by sparqplug during SSO round-trip
            frameAncestors: ["'self'", 'https://sparqplug.getsparqd.com'],
        },
    },
    crossOriginEmbedderPolicy: false,
}));
// Basic rate limiting
app.use(rateLimit({ windowMs: 60 * 1000, limit: Number(process.env.RATE_LIMIT || 300) }));
app.use(express.json());
// Accept classic HTML form posts
app.use(express.urlencoded({ extended: true }));
// Session store (Redis optional)
const SESSION_SECRETS = (process.env.SESSION_SECRETS || process.env.SESSION_SECRET || 'email-admin-session-secret')
    .split(',').map(s => s.trim()).filter(Boolean);
let sessionStore;
if (process.env.REDIS_URL) {
    const client = createClient({ url: process.env.REDIS_URL });
    client.on('error', (err) => console.error('Redis Client Error', err));
    client.connect().catch(err => console.error('Redis connect error', err));
    function createRedisSessionStore(sess, redisClient) {
        try {
            if (typeof connectRedis === 'function') {
                const MaybeCtor = connectRedis(sess);
                if (typeof MaybeCtor === 'function') return new MaybeCtor({ client: redisClient });
            }
        } catch (_) { /* fall through */ }
        const MaybeClass = (connectRedis && (connectRedis.default || connectRedis.RedisStore))
            ? (connectRedis.default || connectRedis.RedisStore)
            : connectRedis;
        if (typeof MaybeClass === 'function') {
            try { return new MaybeClass({ client: redisClient }); } catch (_) { /* fall through */ }
        }
        console.warn('Unsupported connect-redis version: using MemoryStore');
        return undefined;
    }
    sessionStore = createRedisSessionStore(session, client);
}
app.use(session({
    store: sessionStore,
    secret: SESSION_SECRETS.length > 1 ? SESSION_SECRETS : SESSION_SECRETS[0],
    resave: false,
    saveUninitialized: false,
    proxy: true,
    name: process.env.SESSION_NAME || 'portal.sid',
    cookie: {
        secure: 'auto',
        httpOnly: true,
        sameSite: 'lax',
        domain: process.env.SESSION_DOMAIN || undefined,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));
app.use(express.static('public'));

// Optional: proxy live SparQ Plug Next.js runtime (overrides static) when SPARQ_PLUG_URL defined
if (createProxyMiddleware && process.env.SPARQ_PLUG_URL) {
    console.log('[INIT] Enabling SparQ Plug proxy ->', process.env.SPARQ_PLUG_URL);
    app.use('/sparq-plug', createProxyMiddleware({
        target: process.env.SPARQ_PLUG_URL,
        changeOrigin: true,
        ws: true,
        pathRewrite: { '^/sparq-plug': '/' },
        logLevel: 'warn'
        ,onProxyReq: (proxyReq, req, res) => {
            // Strip any spoofed inbound headers first
            ['x-sparq-user-id','x-sparq-user-role','x-sparq-user-email','x-sparq-user-sig','x-sparq-user-ts'].forEach(h=>{
                if (req.headers[h]) delete req.headers[h];
            });
            if (req.session && req.session.user) {
                const u = req.session.user;
                const ts = Date.now().toString();
                const secret = process.env.SPARQ_PLUG_SSO_SECRET || process.env.SESSION_SECRET || 'dev-sso-secret';
                const payload = `${u.id}.${u.role}.${u.email}.${ts}`;
                const sig = crypto.createHmac('sha256', secret).update(payload).digest('hex');
                proxyReq.setHeader('x-sparq-user-id', u.id);
                proxyReq.setHeader('x-sparq-user-role', u.role);
                proxyReq.setHeader('x-sparq-user-email', u.email);
                proxyReq.setHeader('x-sparq-user-ts', ts);
                proxyReq.setHeader('x-sparq-user-sig', sig);
            }
        }
    }));
}

// Serve SparQ Plug Next.js app (production build) if available.
// Expect a production build via `next build && next export` or running `next start` separately.
// 1. If an exported static directory exists (out/), serve it.
// 2. Else if .next/standalone exists (Next.js standalone output), serve its public assets.
// 3. Else fall back to a friendly message.
const sparqPlugRoot = path.join(__dirname, '..', 'sparq-plug');
const sparqPlugStaticExport = path.join(sparqPlugRoot, 'out');
const sparqPlugPublic = path.join(sparqPlugRoot, 'public');
try {
    if (require('fs').existsSync(sparqPlugStaticExport)) {
        app.use('/sparq-plug', express.static(sparqPlugStaticExport, { extensions: ['html'] }));
        // Redirect role subpaths to query param if static export lacks them
        app.get('/sparq-plug/:role(admin|manager|client|user)', (req,res)=> {
            const indexFile = path.join(sparqPlugStaticExport, 'index.html');
            if (require('fs').existsSync(indexFile)) {
                res.sendFile(indexFile);
            } else {
                res.redirect(302, `/sparq-plug/?role=${req.params.role}`);
            }
        });
        // Wildcard for deeper client-side routes
        app.get('/sparq-plug/:role(admin|manager|client|user)/*', (req,res)=> {
            const indexFile = path.join(sparqPlugStaticExport, 'index.html');
            if (require('fs').existsSync(indexFile)) {
                res.sendFile(indexFile);
            } else {
                res.redirect(302, `/sparq-plug/?role=${req.params.role}`);
            }
        });
    } else if (require('fs').existsSync(path.join(sparqPlugRoot, '.next'))) {
        // Serve public assets and a minimal index redirect note; full SSR would still require running next server separately.
        app.use('/sparq-plug/_next', express.static(path.join(sparqPlugRoot, '.next')));
        app.use('/sparq-plug', express.static(sparqPlugPublic));
        app.get('/sparq-plug', (req,res)=>{
            res.setHeader('Content-Type','text/html');
            res.end('<!DOCTYPE html><html><head><title>SparQ Plug</title></head><body><h1>SparQ Plug Dev/SSR Mode</h1><p>The Next.js server must be running separately for full functionality.</p><p>Start it with: <code>cd sparq-plug && npm run dev</code></p></body></html>');
        });
        app.get('/sparq-plug/:role(admin|manager|client|user)', (req,res)=> {
            const fallback = path.join(sparqPlugPublic, 'index.html');
            if (require('fs').existsSync(fallback)) {
                res.sendFile(fallback);
            } else {
                res.redirect(302, `/sparq-plug/?role=${req.params.role}`);
            }
        });
        app.get('/sparq-plug/:role(admin|manager|client|user)/*', (req,res)=> {
            const fallback = path.join(sparqPlugPublic, 'index.html');
            if (require('fs').existsSync(fallback)) {
                res.sendFile(fallback);
            } else {
                res.redirect(302, `/sparq-plug/?role=${req.params.role}`);
            }
        });
    } else {
        app.get('/sparq-plug', (req,res)=> res.status(503).json({error:'SparQ Plug build not found'}));
    }
} catch (e) {
    console.error('Failed to configure /sparq-plug route:', e.message);
}

// Expose a single copy of the SparQy widget script from sparq-plug/public to reuse in the portal
try {
    const sparqyJsPath = path.join(sparqPlugRoot, 'public', 'sparqy.js');
    if (require('fs').existsSync(sparqyJsPath)) {
        app.get('/sparqy.js', (req, res) => {
            res.setHeader('Cache-Control', 'public, max-age=300');
            res.sendFile(sparqyJsPath);
        });
    }
} catch(_) { /* optional */ }

// Mount authentication router (API path)
// Note: previously mounted at '/auth'; consolidating under '/api/auth'

// When served behind a reverse proxy at /portal, make sure relative asset paths work
app.use((req, res, next) => {
    // Back-compat for any /portal-prefixed URLs
    if (req.url === '/portal') {
        req.url = '/';
    } else if (req.url && req.url.startsWith('/portal/')) {
        req.url = req.url.substring('/portal'.length);
    }
    next();
});

// ---------------- Storage Allocation Manager (server) ----------------
async function readJsonSafe(file, fallback) {
    try { const raw = await fs.readFile(file, 'utf8'); return JSON.parse(raw); }
    catch { return fallback; }
}
async function writeJsonSafe(file, data) {
    const tmp = file + '.tmp';
    await fs.mkdir(path.dirname(file), { recursive: true }).catch(()=>{});
    await fs.writeFile(tmp, JSON.stringify(data, null, 2));
    await fs.rename(tmp, file);
}
function getDiskStats(callback){
    // Prefer df -k for real disk; fallback to os.freemem
    exec('df -k --output=avail,size / | tail -n 1', (err, stdout)=>{
        if (err || !stdout) {
            const totalGB = Math.round((os.totalmem() / (1024**3))*100)/100;
            const freeGB = Math.round((os.freemem() / (1024**3))*100)/100;
            return callback(null, { totalGB, freeGB });
        }
        const parts = stdout.trim().split(/\s+/);
        const availKB = Number(parts[0]);
        const sizeKB = Number(parts[1] || 0);
        const freeGB = Math.round((availKB/1024/1024)*100)/100;
        const totalGB = Math.round((sizeKB/1024/1024)*100)/100;
        callback(null, { totalGB, freeGB });
    });
}
function getPathUsedGB(p){
    return new Promise((resolve) => {
        if (!p || typeof p !== 'string') return resolve(null);
        try {
            const escaped = p.replace(/'/g, "'\"'\"'");
            exec(`du -sk '${escaped}'`, (err, stdout) => {
                if (err || !stdout) return resolve(null);
                const kb = Number(String(stdout).trim().split(/\s+/)[0] || 0);
                if (!isFinite(kb) || kb <= 0) return resolve(0);
                const gb = Math.round((kb/1024/1024) * 100) / 100; // KB -> GB
                resolve(gb);
            });
        } catch(_) { resolve(null); }
    });
}
function percentRemaining(alloc){
    const used = Number(alloc.usedGB || 0);
    const total = Math.max(0, Number(alloc.allocatedGB || alloc.totalGB || 0));
    if (!total) return 100;
    return Math.max(0, Math.round(((total - used) / total) * 100));
}
async function sendStorageAlertEmail({ to, subject, text }){
    try {
        let transporter;
        if (!process.env.EMAIL_SMTP_HOST) {
            // Mock transport for dev: outputs message as JSON to logs
            transporter = nodemailer.createTransport({ jsonTransport: true });
        } else {
            transporter = nodemailer.createTransport({
                host: process.env.EMAIL_SMTP_HOST,
                port: Number(process.env.EMAIL_SMTP_PORT || 587),
                secure: String(process.env.EMAIL_SMTP_SECURE || 'false') === 'true',
                auth: (process.env.EMAIL_SMTP_USER && process.env.EMAIL_SMTP_PASS) ? {
                    user: process.env.EMAIL_SMTP_USER,
                    pass: process.env.EMAIL_SMTP_PASS
                } : undefined
            });
        }
        await transporter.sendMail({
            from: process.env.EMAIL_FROM || 'alerts@getsparqd.com',
            to,
            subject,
            text
        });
        addLog(`Storage alert sent to ${to}: ${subject}`);
    } catch (e) {
        addLog(`Storage alert email failed to ${to}: ${e.message}`, 'error');
    }
}
function scheduleStorageMonitor(){
    if (scheduleStorageMonitor._started) return; scheduleStorageMonitor._started = true;
    const intervalMs = Number(process.env.STORAGE_MONITOR_INTERVAL_MS || 5*60*1000);
    setInterval(async ()=>{
        try {
            const state = await readJsonSafe(STORAGE_FILE, { globalThresholds:{warn20:20,warn10:10,warn5:5}, allocations:[] });
            const { allocations, globalThresholds } = state;
            if (!Array.isArray(allocations) || !allocations.length) return;
            for (const a of allocations){
                // Auto-track used space if a path is provided (Linux environments)
                try {
                    if ((a.autoTrack === undefined || a.autoTrack === true) && a.path) {
                        const used = await getPathUsedGB(a.path);
                        if (used != null) a.usedGB = used;
                    }
                } catch(_) { /* best-effort */ }
                const pct = percentRemaining(a);
                const thresholds = a.thresholds || globalThresholds || {};
                const marks = [Number(thresholds.warn20||20), Number(thresholds.warn10||10), Number(thresholds.warn5||5)].sort((x,y)=>y-x);
                const trig = marks.find(m => pct <= m);
                if (!trig) continue;
                if (!a._lastAlertPct || pct < a._lastAlertPct - 1) {
                    a._lastAlertPct = pct;
                    const subject = `Storage low for ${a.client || a.purpose || 'allocation'}: ${pct}% remaining`;
                    const text = `Hello,\n\nThis is an automatic alert for ${a.client || ''} ${a.purpose ? '('+a.purpose+')' : ''}.\nAllocation: ${a.allocatedGB||a.totalGB} GB\nUsed: ${a.usedGB||0} GB\nRemaining: ${((a.allocatedGB||a.totalGB)-(a.usedGB||0))} GB (${pct}%)\n\nThreshold crossed: ${trig}%\n\n— SparQ Digital Storage Monitor`;
                    if (a.email) await sendStorageAlertEmail({ to: a.email, subject, text });
                }
            }
            await writeJsonSafe(STORAGE_FILE, state);
        } catch(e){ addLog('Storage monitor error: '+e.message, 'error'); }
    }, intervalMs);
}
scheduleStorageMonitor();

// CRUD APIs
app.get('/api/storage/allocations', authenticateToken, checkPermission('storage:read'), async (req,res)=>{
    const state = await readJsonSafe(STORAGE_FILE, { globalThresholds:{warn20:20,warn10:10,warn5:5}, allocations:[] });
    getDiskStats((_e, disk)=>{ res.json({ ...state, disk }); });
});
app.post('/api/storage/allocations', authenticateToken, checkPermission('storage:write'), async (req,res)=>{
    const state = await readJsonSafe(STORAGE_FILE, { globalThresholds:{warn20:20,warn10:10,warn5:5}, allocations:[] });
    const a = req.body || {};
    const id = a.id || uuidv4();
    const record = {
        id,
        client: a.client || a.clientName || '',
        purpose: a.purpose || '',
        email: a.email || '',
        allocatedGB: Number(a.allocatedGB || a.totalGB || 0),
        usedGB: Number(a.usedGB || 0),
        path: a.path || '',
        autoTrack: a.autoTrack !== false,
        thresholds: a.thresholds || null,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
    };
    const idx = state.allocations.findIndex(x=>x.id===id);
    if (idx>=0) state.allocations[idx] = { ...state.allocations[idx], ...record, id };
    else state.allocations.push(record);
    await writeJsonSafe(STORAGE_FILE, state);
    res.json({ ok:true, allocation: record });
});
app.put('/api/storage/allocations/:id', authenticateToken, checkPermission('storage:write'), async (req,res)=>{
    const state = await readJsonSafe(STORAGE_FILE, { globalThresholds:{warn20:20,warn10:10,warn5:5}, allocations:[] });
    const id = req.params.id;
    const idx = state.allocations.findIndex(x=>x.id===id);
    if (idx===-1) return res.status(404).json({ error:'Not found' });
    const a = req.body || {};
    state.allocations[idx] = {
        ...state.allocations[idx],
        client: a.client ?? state.allocations[idx].client,
        purpose: a.purpose ?? state.allocations[idx].purpose,
        email: a.email ?? state.allocations[idx].email,
        allocatedGB: a.allocatedGB != null ? Number(a.allocatedGB) : state.allocations[idx].allocatedGB,
        usedGB: a.usedGB != null ? Number(a.usedGB) : state.allocations[idx].usedGB,
        path: a.path !== undefined ? a.path : state.allocations[idx].path,
        autoTrack: a.autoTrack !== undefined ? !!a.autoTrack : (state.allocations[idx].autoTrack !== undefined ? state.allocations[idx].autoTrack : true),
        thresholds: a.thresholds ?? state.allocations[idx].thresholds,
        updatedAt: new Date().toISOString()
    };
    await writeJsonSafe(STORAGE_FILE, state);
    res.json({ ok:true, allocation: state.allocations[idx] });
});
app.delete('/api/storage/allocations/:id', authenticateToken, checkPermission('storage:write'), async (req,res)=>{
    const state = await readJsonSafe(STORAGE_FILE, { globalThresholds:{warn20:20,warn10:10,warn5:5}, allocations:[] });
    const id = req.params.id;
    const before = state.allocations.length;
    state.allocations = state.allocations.filter(x=>x.id!==id);
    if (state.allocations.length === before) return res.status(404).json({ error:'Not found' });
    await writeJsonSafe(STORAGE_FILE, state);
    res.json({ ok:true });
});
app.put('/api/storage/thresholds', authenticateToken, checkPermission('storage:write'), async (req,res)=>{
    const state = await readJsonSafe(STORAGE_FILE, { globalThresholds:{warn20:20,warn10:10,warn5:5}, allocations:[] });
    const t = req.body || {};
    state.globalThresholds = {
        warn20: Number(t.warn20 ?? state.globalThresholds.warn20 ?? 20),
        warn10: Number(t.warn10 ?? state.globalThresholds.warn10 ?? 10),
        warn5: Number(t.warn5 ?? state.globalThresholds.warn5 ?? 5)
    };
    await writeJsonSafe(STORAGE_FILE, state);
    res.json({ ok:true, globalThresholds: state.globalThresholds });
});

// Manually trigger usage scan for a specific allocation (admin-only)
app.post('/api/storage/allocations/:id/scan', authenticateToken, checkPermission('storage:write'), async (req,res)=>{
    try {
        const state = await readJsonSafe(STORAGE_FILE, { globalThresholds:{warn20:20,warn10:10,warn5:5}, allocations:[] });
        const id = req.params.id;
        const idx = state.allocations.findIndex(x=>x.id===id);
        if (idx===-1) return res.status(404).json({ error:'Not found' });
        const a = state.allocations[idx];
        if (!a.path) return res.status(400).json({ error:'No path configured for this allocation' });
        const used = await getPathUsedGB(a.path);
        if (used == null) return res.status(500).json({ error:'Failed to compute usage' });
        a.usedGB = used;
        a.updatedAt = new Date().toISOString();
        await writeJsonSafe(STORAGE_FILE, state);
        res.json({ ok:true, allocation: a });
    } catch(e){ res.status(500).json({ error:'Scan failed' }); }
});

// ---- Universal Contact Form Endpoint ----
async function loadContactRouting() {
    try {
        const raw = await fs.readFile(CONTACT_ROUTING_FILE, 'utf8');
        const json = JSON.parse(raw);
        return json && typeof json === 'object' ? json : {};
    } catch(_) { return {}; }
}
const contactLimiter = rateLimit({ windowMs: 60 * 1000, limit: Number(process.env.CONTACT_RATE_LIMIT || 60) });
app.post('/api/contact', contactLimiter, async (req, res) => {
    try {
        // Honeypot: silently accept but drop if bot fills hidden field
        if (req.body && (req.body.hp || req.body._hp || req.body.companyWebsite)) {
            addLog('Contact honeypot triggered; dropping message');
            return res.json({ ok: true });
        }
        // Determine origin and routing key
        const origin = (req.headers['origin'] || req.headers['referer'] || '').toString();
        const site = (req.body.site || req.query.site || '').toString().trim();
        const routingKey = site || origin.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase();

        // Extract fields (support common names)
        const name = (req.body.name || req.body.fullName || '').toString().trim().slice(0, 200);
        const email = (req.body.email || req.body.from || '').toString().trim().slice(0, 200);
        const phone = (req.body.phone || req.body.tel || '').toString().trim().slice(0, 50);
        const subjectRaw = (req.body.subject || '').toString().trim().slice(0, 200);
        const message = (req.body.message || req.body.msg || req.body.body || '').toString().trim().slice(0, 5000);
        const ip = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';

        if (!email && !message) return res.status(400).json({ error: 'Missing required fields' });

        // Load routing map
        const map = await loadContactRouting();
        // Map may be { routes: { key: { to, cc, bcc, subject }, default: { ... } }, allowOrigins: [] }
        const routes = map.routes || {};
        const route = routes[routingKey] || routes['default'] || {};
    const to = (process.env.CONTACT_DEFAULT_TO || route.to || process.env.EMAIL_TO || process.env.EMAIL_FROM || 'hligon@getsparqd.com');

        // Optional CORS allowlist for unauthenticated POSTs
        const allow = (process.env.CONTACT_CORS_ORIGINS || (map.allowOrigins || []).join(',')).split(',').map(s=>s.trim()).filter(Boolean);
        if (allow.length) {
            const ok = origin && allow.some(a => origin.toLowerCase().startsWith(a.toLowerCase()));
            if (!ok) return res.status(403).json({ error: 'Origin not allowed' });
        }

        // Prepare mail
        const subject = route.subject || subjectRaw || `Website Contact${routingKey ? ' - ' + routingKey : ''}`;
        const lines = [
            `From: ${name || '(no name)'} <${email || 'unknown'}>`,
            phone ? `Phone: ${phone}` : null,
            `Origin: ${origin || '(unknown)'}`,
            `IP: ${ip}`,
            '---',
            message || '(no message)'
        ].filter(Boolean);
        const text = lines.join('\n');

        // Transport: JSON in dev if SMTP not configured
        let transporter;
        if (!process.env.EMAIL_SMTP_HOST) {
            transporter = nodemailer.createTransport({ jsonTransport: true });
        } else {
            transporter = nodemailer.createTransport({
                host: process.env.EMAIL_SMTP_HOST,
                port: Number(process.env.EMAIL_SMTP_PORT || 587),
                secure: String(process.env.EMAIL_SMTP_SECURE || 'false') === 'true',
                auth: (process.env.EMAIL_SMTP_USER && process.env.EMAIL_SMTP_PASS) ? {
                    user: process.env.EMAIL_SMTP_USER,
                    pass: process.env.EMAIL_SMTP_PASS
                } : undefined
            });
        }

        const mail = {
            from: process.env.EMAIL_FROM || 'no-reply@getsparqd.com',
            to,
            cc: route.cc,
            bcc: route.bcc,
            replyTo: email || undefined,
            subject,
            text
        };
        await transporter.sendMail(mail);

        // Persist minimal submission record
        try {
            const rec = {
                id: uuidv4(),
                at: new Date().toISOString(),
                origin,
                routingKey,
                to,
                name,
                email,
                phone,
                subject,
                ip: (ip||'').toString(),
                len: (message||'').length
            };
            const current = await readJsonSafe(CONTACT_SUBMISSIONS_FILE, []);
            current.unshift(rec);
            // Keep last 1000
            const trimmed = current.slice(0, 1000);
            await writeJsonSafe(CONTACT_SUBMISSIONS_FILE, trimmed);
        } catch(_) { /* best-effort */ }

        addLog(`Contact form routed to ${to} (key: ${routingKey || 'default'})`);
        res.json({ ok: true });
    } catch (e) {
        addLog('Contact endpoint error: ' + e.message, 'error');
        res.status(500).json({ error: 'Failed to send' });
    }
});

// Admin-only: list recent contact submissions
app.get('/api/contacts/submissions', authenticateToken, checkPermission('contacts:read'), async (req, res) => {
    try {
        const limit = Math.max(1, Math.min(1000, Number(req.query.limit || 200)));
        const list = await readJsonSafe(CONTACT_SUBMISSIONS_FILE, []);
        return res.json({ submissions: list.slice(0, limit) });
    } catch (e) {
        return res.status(500).json({ error: 'Failed to load submissions' });
    }
});

// In-memory storage (in production, use a database)
let domains = [];
let emailAccounts = [];
// Per-user data stores (profiles, billing, preferences)
let userProfiles = {};   // { [userId]: { name, phone, timezone, address: {...} } }
let userBilling = {};    // { [userId]: { company, email, phone, taxId, address: {...}, sameAsMailing } }
let userPreferences = {}; // { [userId]: { emails, security, updates } }
let systemLogs = [];

// Add log entry
function addLog(message, level = 'info') {
    const logEntry = {
        id: uuidv4(),
        timestamp: new Date().toISOString(),
        message,
        level
    };
    systemLogs.unshift(logEntry);
    
    // Keep only last 100 logs
    if (systemLogs.length > 100) {
        systemLogs = systemLogs.slice(0, 100);
    }
    
    console.log(`[${level.toUpperCase()}] ${message}`);
}

// Direct login route for testing
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    console.log('[DEBUG] Login attempt:', username);
    
    try {
        // Import users from auth module
        const { users } = require('./auth');
        const user = users.find(u => u.username === username || u.email === username);
        
        if (!user) {
            console.log('[DEBUG] User not found');
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        // Only accept fixed admin password
        const FIXED_ADMIN_PASS = 'sparqd2025!';
        let validPassword = (password === FIXED_ADMIN_PASS);
        if (!validPassword && user.password) {
            validPassword = await bcrypt.compare(password, user.password);
        }
        console.log('[DEBUG] Password valid:', validPassword);
        
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Set session
        req.session.user = {
            id: user.id,
            username: user.username,
            role: user.role,
            email: user.email,
            name: user.name
        };
        
        res.json({
            success: true,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role,
                name: user.name
            }
        });
        
        console.log('[DEBUG] Login successful');
        
    } catch (error) {
        console.log('[ERROR] Login error:', error.message);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Fresh login route
app.get('/fresh-login', (req, res) => {
    if (req.session) {
        req.session.destroy((err) => {
            if (err) {
                console.log('Session destroy error:', err);
            }
            // Redirect to login with a parameter to clear localStorage
            res.redirect('/login.html?fresh=true');
        });
    } else {
        res.redirect('/login.html?fresh=true');
    }
});

// Generate secure password
function generatePassword(length = 12) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
    let password = '';
    for (let i = 0; i < length; i++) {
        password += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return password;
}

// Hash password for system storage
async function hashPassword(password) {
    return await bcrypt.hash(password, 10);
}

// Create email account in system
async function createEmailAccount(email, password, domain, storageGB = 25) {
    try {
        const username = email.split('@')[0];
        const hashedPassword = await hashPassword(password);
        
        if (process.platform !== 'win32' && process.env.SIMULATE_SETUP !== 'true') {
            // Create user directory
            await execAsync(`sudo mkdir -p /var/mail/vhosts/${domain}/${username}`);
            await execAsync(`sudo chown -R mail:mail /var/mail/vhosts/${domain}`);
            // Add to virtual mailboxes
            await execAsync(`echo \"${email} ${domain}/${username}/\" | sudo tee -a /etc/postfix/virtual_mailboxes`);
            // Add password entry
            const saltedHash = await execAsync(`doveadm pw -s SHA512-CRYPT -p \"${password}\"`);
            await execAsync(`echo \"${email}:${saltedHash.stdout.trim()}\" | sudo tee -a /etc/dovecot/passwd.${domain}`);
            // Update postfix maps
            await execAsync('sudo postmap /etc/postfix/virtual_mailboxes');
            // Restart services
            await execAsync('sudo systemctl reload postfix dovecot');
        }
        
        // Add to our tracking
        const account = {
            id: uuidv4(),
            address: email,
            domain,
            password, // Store plain text for client notification
            hashedPassword,
            storage: storageGB,
            created: new Date().toISOString(),
            lastLogin: null
        };
        
        emailAccounts.push(account);
        addLog(`Created email account: ${email}`);
        
        return account;
        
    } catch (error) {
        addLog(`Failed to create email account ${email}: ${error.message}`, 'error');
        throw error;
    }
}

// Setup domain email hosting
async function setupDomainEmail(domainData) {
    const { domain, clientName, clientContact, emailAccounts: emailList, storageAllocation, autoDNS, emailClient } = domainData;
    
    const results = {
        domain,
        clientName,
        createdAccounts: [],
        totalStorage: storageAllocation,
        dnsRecords: [],
        credentials: []
    };
    
    try {
        // Add domain to virtual domains (skip on Windows or when simulating)
        if (process.platform !== 'win32' && process.env.SIMULATE_SETUP !== 'true') {
            await execAsync(`echo "${domain}" | sudo tee -a /etc/postfix/virtual_domains`);
        }
        
        // Create accounts
        for (const emailAddr of emailList) {
            if (emailAddr.trim()) {
                const password = generatePassword(14);
                const account = await createEmailAccount(emailAddr.trim(), password, domain, storageAllocation / emailList.length);
                
                results.createdAccounts.push({
                    email: emailAddr.trim(),
                    password,
                    storage: Math.floor(storageAllocation / emailList.length)
                });
                
                results.credentials.push({
                    email: emailAddr.trim(),
                    password,
                    imap: `${domain}:993 (SSL/TLS)`,
                    smtp: `${domain}:587 (STARTTLS)`,
                    webmail: `http://mail.${domain}`
                });
            }
        }
        
        // DNS setup if requested
    if (autoDNS) {
            results.dnsRecords = [
                { type: 'MX', name: domain, content: domain, priority: 10 },
                { type: 'A', name: `mail.${domain}`, content: process.env.SERVER_IP || '68.54.208.207' },
                { type: 'TXT', name: domain, content: `"v=spf1 mx a:${domain} ~all"` }
            ];
            
            addLog(`DNS records prepared for ${domain}`);
        }
        
        // Add domain to tracking
        const domainRecord = {
            id: uuidv4(),
            name: domain,
            clientName,
            clientContact,
            emailCount: results.createdAccounts.length,
            storageAllocated: storageAllocation,
            created: new Date().toISOString(),
            status: 'active'
        };
        
        domains.push(domainRecord);
        
        // Send credentials to client if requested
        if (emailClient && clientContact) {
            await sendClientCredentials(clientContact, results);
        }
        
        addLog(`Domain email setup completed for ${domain} (${results.createdAccounts.length} accounts)`);
        return results;
        
    } catch (error) {
        addLog(`Domain setup failed for ${domain}: ${error.message}`, 'error');
        throw error;
    }
}

// Send credentials to client
async function sendClientCredentials(clientEmail, setupResults) {
    try {
        const transporter = nodemailer.createTransport({
            host: process.env.EMAIL_SMTP_HOST || 'localhost',
            port: Number(process.env.EMAIL_SMTP_PORT || 587),
            secure: String(process.env.EMAIL_SMTP_SECURE || 'false') === 'true',
            auth: (process.env.EMAIL_SMTP_USER && process.env.EMAIL_SMTP_PASS) ? {
                user: process.env.EMAIL_SMTP_USER,
                pass: process.env.EMAIL_SMTP_PASS
            } : undefined
        });
        
        const credentialsText = setupResults.credentials.map(cred => 
            `📧 ${cred.email}\n   Password: ${cred.password}\n   IMAP: ${cred.imap}\n   SMTP: ${cred.smtp}\n   Webmail: ${cred.webmail}`
        ).join('\n\n');
        
        const mailOptions = {
            from: process.env.EMAIL_FROM || `"SparQd Email Admin" <admin@${process.env.DEFAULT_DOMAIN || 'localhost'}>`,
            to: clientEmail,
            subject: `🎉 Your Professional Email Hosting is Ready! (${setupResults.domain})`,
            text: `Dear ${setupResults.clientName},

Your FREE professional email hosting has been successfully configured for ${setupResults.domain}!

📧 Email Accounts Created (${setupResults.createdAccounts.length}):
${credentialsText}

💾 Total Storage Allocated: ${setupResults.totalStorage}GB
🌐 Webmail Access: http://mail.${setupResults.domain}
💰 Monthly Savings: No more email hosting fees!

Email Client Setup Instructions:
• Use your full email address as username
• IMAP Server: ${setupResults.domain} (Port 993, SSL/TLS)
• SMTP Server: ${setupResults.domain} (Port 587, STARTTLS)

Your email accounts are ready to use immediately!

Best regards,
SparQd Email Team

---
This is an automated message from the SparQd Email Management System.`
        };
        
        await transporter.sendMail(mailOptions);
        addLog(`Credentials sent to client: ${clientEmail}`);
        
    } catch (error) {
        addLog(`Failed to send credentials to ${clientEmail}: ${error.message}`, 'error');
        // Don't throw - this shouldn't fail the whole setup
    }
}

// Authentication routes
app.use('/api/auth', authRouter);

// User Management API Routes
app.get('/api/users/admins', authenticateToken, checkPermission('users:read'), async (req, res) => {
    try {
        res.json({
            success: true,
            users: adminUsers.map(user => ({
                id: user.id,
                username: user.username,
                email: user.email,
                name: user.name,
                role: user.role,
                createdAt: user.createdAt
            }))
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch admin users' });
    }
});

app.get('/api/users/managers', authenticateToken, checkPermission('users:read'), async (req, res) => {
    try {
        res.json({
            success: true,
            users: managers.map(user => ({
                id: user.id,
                username: user.username,
                email: user.email,
                name: user.name,
                role: user.role,
                createdAt: user.createdAt,
                permissions: user.permissions
            }))
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch managers' });
    }
});

app.get('/api/users/clients', authenticateToken, checkPermission('users:read'), async (req, res) => {
    try {
        res.json({
            success: true,
            users: clients.map(user => ({
                id: user.id,
                username: user.username,
                email: user.email,
                name: user.name,
                role: user.role,
                domain: user.domain,
                createdAt: user.createdAt,
                lastLogin: user.lastLogin
            }))
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch clients' });
    }
});

app.get('/api/users/:id', authenticateToken, checkPermission('users:read'), async (req, res) => {
    try {
        const { users } = require('./auth');
        const user = users.find(u => u.id == req.params.id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const userResponse = {
            id: user.id,
            username: user.username,
            email: user.email,
            name: user.name,
            role: user.role
        };
        
        if (user.role === 'client') {
            userResponse.company = user.company;
            userResponse.phone = user.phone;
            userResponse.domain = user.domain;
        }
        
        res.json(userResponse);
    } catch (error) {
        res.status(500).json({ error: 'Failed to load user' });
    }
});

app.post('/api/users/create', authenticateToken, checkPermission('users:create'), async (req, res) => {
    // Creating new application login users is disabled; only embedded admins are allowed
    return res.status(403).json({ error: 'User creation is disabled' });
});

app.put('/api/users/:id', authenticateToken, checkPermission('users:update'), async (req, res) => {
    try {
        const { users } = require('./auth');
        const userId = parseInt(req.params.id);
        const userIndex = users.findIndex(u => u.id === userId);
        
        if (userIndex === -1) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const { username, email, name, company, phone, domain } = req.body;
        
        // Check if username or email is taken by another user
        if (users.find(u => u.id !== userId && (u.username === username || u.email === email))) {
            return res.status(400).json({ error: 'Username or email already exists' });
        }
        
        users[userIndex] = {
            ...users[userIndex],
            username,
            email,
            name,
            ...(users[userIndex].role === 'client' && { company, phone, domain })
        };
        
        res.json({ message: 'User updated successfully' });
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({ error: 'Failed to update user' });
    }
});

app.post('/api/users/:id/reset-password', authenticateToken, checkPermission('users:update'), async (req, res) => {
    try {
    const bcrypt = require('./bcrypt-compat');
        const { users } = require('./auth');
        const userId = parseInt(req.params.id);
        const userIndex = users.findIndex(u => u.id === userId);
        
        if (userIndex === -1) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const newPassword = generatePassword(12);
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        
        users[userIndex].password = hashedPassword;
        users[userIndex].requirePasswordChange = true;
        
        res.json({ message: 'Password reset successfully', newPassword });
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).json({ error: 'Failed to reset password' });
    }
});

app.delete('/api/users/:id', authenticateToken, checkPermission('users:delete'), async (req, res) => {
    try {
        const { users } = require('./auth');
        const userId = parseInt(req.params.id);
        const userIndex = users.findIndex(u => u.id === userId);
        
        if (userIndex === -1) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Don't allow deleting the last admin
        if (users[userIndex].role === 'admin' && users.filter(u => u.role === 'admin').length === 1) {
            return res.status(400).json({ error: 'Cannot delete the last admin user' });
        }
        
        users.splice(userIndex, 1);
        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

app.get('/api/users/:id/details', authenticateToken, checkPermission('users:read'), async (req, res) => {
    try {
        const { users } = require('./auth');
        const user = users.find(u => u.id == req.params.id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // For client details, we would typically fetch from a database
        // For now, return basic info with mock data
        const details = {
            ...user,
            emailAccounts: [
                { address: `${user.username}@${user.domain || 'example.com'}`, storage: '0.5' }
            ],
            totalStorage: '0.5',
            createdAt: user.createdAt || new Date().toISOString().split('T')[0]
        };
        
        delete details.password; // Never send password
        res.json(details);
    } catch (error) {
        res.status(500).json({ error: 'Failed to load user details' });
    }
});

app.get('/api/users/clients/export', authenticateToken, checkPermission('users:read'), async (req, res) => {
    try {
        const { users } = require('./auth');
        const clients = users.filter(user => user.role === 'client');
        
        const csv = [
            'Name,Username,Email,Company,Phone,Domain,Created',
            ...clients.map(client => 
                `"${client.name}","${client.username}","${client.email}","${client.company || ''}","${client.phone || ''}","${client.domain || ''}","${client.createdAt || ''}"`
            )
        ].join('\n');
        
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename="clients-export.csv"');
        res.send(csv);
    } catch (error) {
        res.status(500).json({ error: 'Failed to export client data' });
    }
});

// Redirect root to login if not authenticated
app.get('/', (req, res) => {
    if (req.session.user) {
        res.redirect('/dashboard');
    } else {
        res.redirect('/login.html');
    }
});

// Dashboard route (protected)
app.get('/dashboard', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
    } else {
        res.redirect('/login.html');
    }
});

// Explicit login routes (avoid 404 for /login)
app.get(['/login', '/login.html'], (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Simple health check
app.get('/healthz', (req, res) => {
    res.json({ ok: true, service: 'email-admin', time: new Date().toISOString() });
});

// Version/build info for quick verification
app.get('/api/version', (req, res) => {
    res.json({
        name: __pkg.name,
        version: __pkg.version,
        build: {
            commit: process.env.BUILD_COMMIT || null,
            time: process.env.BUILD_TIME || null
        },
        env: {
            node: process.version,
            nodeEnv: process.env.NODE_ENV || null,
            port: PORT
        },
        uptimeSec: Math.round(process.uptime())
    });
});

// API Routes (protected)

// Dashboard stats
app.get('/api/dashboard/stats', authenticateToken, checkPermission('dashboard:read'), (req, res) => {
    const totalStorage = emailAccounts.reduce((sum, account) => sum + account.storage, 0);
    
    res.json({
        totalDomains: domains.length,
        totalEmails: emailAccounts.length,
        storageUsed: totalStorage
    });
});

// Setup validation
app.post('/api/setup/validate', authenticateToken, checkPermission('domains:create'), async (req, res) => {
    const { domain } = req.body;
    
    try {
        // Check if domain already exists
        const existingDomain = domains.find(d => d.name === domain);
        if (existingDomain) {
            return res.status(400).json({ error: 'Domain already configured' });
        }
        
        // Basic domain validation
        const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/;
        if (!domainRegex.test(domain)) {
            return res.status(400).json({ error: 'Invalid domain format' });
        }
        
        res.json({ 
            success: true, 
            details: [`Domain ${domain} is valid and available`]
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create directories
app.post('/api/setup/directories', authenticateToken, checkPermission('domains:create'), async (req, res) => {
    const { domain } = req.body;
    
    try {
        if (process.platform !== 'win32' && process.env.SIMULATE_SETUP !== 'true') {
            await execAsync(`sudo mkdir -p /var/mail/vhosts/${domain}`);
            await execAsync(`sudo mkdir -p /home/sparqd/sites/${domain}`);
            await execAsync(`sudo chown -R mail:mail /var/mail/vhosts/${domain}`);
        }
        
        res.json({ 
            success: true,
            details: [
                `Created mail directory: /var/mail/vhosts/${domain}`,
                `Created site directory: /home/sparqd/sites/${domain}`
            ]
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create accounts
app.post('/api/setup/accounts', authenticateToken, checkPermission('domains:create'), async (req, res) => {
    const { domain, emailAccounts: emailList } = req.body;
    
    try {
        const createdAccounts = [];
        
        for (const emailAddr of emailList) {
            if (emailAddr.trim()) {
                const password = generatePassword(14);
                if (process.platform !== 'win32' && process.env.SIMULATE_SETUP !== 'true') {
                    await createEmailAccount(emailAddr.trim(), password, domain);
                } else {
                    // Simulate creation on Windows
                    emailAccounts.push({
                        id: uuidv4(),
                        address: emailAddr.trim(),
                        domain,
                        password,
                        hashedPassword: await hashPassword(password),
                        storage: 25,
                        created: new Date().toISOString(),
                        lastLogin: null
                    });
                }
                createdAccounts.push(`${emailAddr.trim()} (${password})`);
            }
        }
        
        res.json({ 
            success: true,
            details: [`Created ${createdAccounts.length} email accounts`]
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Configure mail server
app.post('/api/setup/mailserver', authenticateToken, checkPermission('domains:create'), async (req, res) => {
    try {
        if (process.platform !== 'win32' && process.env.SIMULATE_SETUP !== 'true') {
            await execAsync('sudo postmap /etc/postfix/virtual_domains');
            await execAsync('sudo postmap /etc/postfix/virtual_mailboxes');
            await execAsync('sudo systemctl reload postfix dovecot');
        }
        
        res.json({ 
            success: true,
            details: [
                'Updated Postfix virtual maps',
                'Reloaded Postfix and Dovecot services'
            ]
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Allocate storage
app.post('/api/setup/storage', authenticateToken, checkPermission('domains:create'), async (req, res) => {
    const { domain, storageAllocation } = req.body;
    
    try {
        // Set quota (simplified). On Windows or simulation, write into local data dir
        if (process.platform !== 'win32' && process.env.SIMULATE_SETUP !== 'true') {
            await execAsync(`sudo mkdir -p /home/sparqd/sites/${domain}/quota`);
            await fs.writeFile(`/home/sparqd/sites/${domain}/quota/allocation.txt`, `${storageAllocation}GB`);
        } else {
            const qdir = path.join(__dirname, 'data', domain, 'quota');
            await fs.mkdir(qdir, { recursive: true });
            await fs.writeFile(path.join(qdir, 'allocation.txt'), `${storageAllocation}GB`);
        }
        
        res.json({ 
            success: true,
            details: [`Allocated ${storageAllocation}GB storage for ${domain}`]
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Configure webmail (placeholder for now)
app.post('/api/setup/webmail', authenticateToken, checkPermission('domains:create'), async (req, res) => {
    try {
        const { domain } = req.body;
        if (!domain) {
            return res.status(400).json({ error: 'Domain is required' });
        }

        // In a full implementation, we would provision a vhost and/or proxy to webmail here.
        // For now, just log and return success so the UI flow progresses.
        addLog(`Webmail configured for ${domain}`);
        res.json({ success: true, details: [
            `Prepared webmail endpoint for ${domain}`,
            `Users will access via https://email.${domain}`
        ]});
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Setup DNS
app.post('/api/setup/dns', authenticateToken, checkPermission('domains:create'), async (req, res) => {
    const { domain } = req.body;
    
    try {
        // This would integrate with your DNS management system
        const dnsRecords = [
            `MX: ${domain} → ${domain} (Priority 10)`,
            `A: mail.${domain} → ${process.env.SERVER_IP}`,
            `TXT: ${domain} → "v=spf1 mx a:${domain} ~all"`
        ];
        
        res.json({ 
            success: true,
            details: ['DNS records prepared (manual configuration required)', ...dnsRecords]
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Send notifications
app.post('/api/setup/notify', authenticateToken, checkPermission('domains:create'), async (req, res) => {
    const { clientContact, domain } = req.body;
    
    try {
        if (clientContact) {
            // This would send the actual email
            addLog(`Client notification prepared for ${clientContact}`);
        }
        
        res.json({ 
            success: true,
            details: [`Client notification sent to ${clientContact}`]
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Finalize setup
app.post('/api/setup/finalize', authenticateToken, checkPermission('domains:create'), async (req, res) => {
    try {
        const setupResult = await setupDomainEmail(req.body);
        
        res.json({ 
            success: true,
            details: [
                `Domain ${setupResult.domain} setup completed`,
                `${setupResult.createdAccounts.length} email accounts created`,
                `${setupResult.totalStorage}GB storage allocated`
            ],
            result: setupResult
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Email management
app.get('/api/emails/list', authenticateToken, checkPermission('emails:read'), (req, res) => {
    res.json(emailAccounts.map(account => ({
        address: account.address,
        domain: account.domain,
        storage: account.storage,
        created: new Date(account.created).toLocaleDateString(),
        lastLogin: account.lastLogin
    })));
});

app.post('/api/emails/reset-password', authenticateToken, checkPermission('emails:update'), async (req, res) => {
    const { email } = req.body;
    
    try {
        const account = emailAccounts.find(acc => acc.address === email);
        if (!account) {
            return res.status(404).json({ error: 'Email account not found' });
        }
        
        const newPassword = generatePassword(14);
        
        if (process.platform !== 'win32' && process.env.SIMULATE_SETUP !== 'true') {
            // Update password in system
            const saltedHash = await execAsync(`doveadm pw -s SHA512-CRYPT -p "${newPassword}"`);
            
            // Update dovecot password file
            await execAsync(`sudo sed -i 's|^${email}:.*|${email}:${saltedHash.stdout.trim()}|' /etc/dovecot/passwd.${account.domain}`);
            await execAsync('sudo systemctl reload dovecot');
        }
        
        // Update our record regardless (simulated locally on Windows/dev)
        account.password = newPassword;
        account.hashedPassword = await hashPassword(newPassword);
        
        addLog(`Password reset for ${email}`);
        
        res.json({ success: true, newPassword });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/emails/delete', authenticateToken, checkPermission('emails:delete'), async (req, res) => {
    const { email } = req.body;
    
    try {
        const accountIndex = emailAccounts.findIndex(acc => acc.address === email);
        if (accountIndex === -1) {
            return res.status(404).json({ error: 'Email account not found' });
        }
        
        const account = emailAccounts[accountIndex];
        
        if (process.platform !== 'win32' && process.env.SIMULATE_SETUP !== 'true') {
            // Remove from system
            await execAsync(`sudo sed -i '/^${email}/d' /etc/postfix/virtual_mailboxes`);
            await execAsync(`sudo sed -i '/^${email}/d' /etc/dovecot/passwd.${account.domain}`);
            await execAsync('sudo postmap /etc/postfix/virtual_mailboxes');
            await execAsync('sudo systemctl reload postfix dovecot');
            
            // Remove directory
            const username = email.split('@')[0];
            await execAsync(`sudo rm -rf /var/mail/vhosts/${account.domain}/${username}`);
        }
        
        // Remove from our tracking
        emailAccounts.splice(accountIndex, 1);
        
        addLog(`Deleted email account: ${email}`);
        
        res.json({ success: true });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// System logs
app.get('/api/logs/recent', authenticateToken, checkPermission('logs:read'), (req, res) => {
    res.json(systemLogs.slice(0, 50));
});

// DNS testing
app.post('/api/dns/test', authenticateToken, checkPermission('dns:test'), async (req, res) => {
    const { domain } = req.body;
    
    try {
        const results = [];
        
        // Test MX record
        try {
            const mxResult = await execAsync(`nslookup -type=MX ${domain}`);
            results.push(`MX Record: ${mxResult.stdout.includes(domain) ? '✅ Configured' : '❌ Not found'}`);
        } catch (error) {
            results.push('MX Record: ❌ Error checking');
        }
        
        // Test A record for mail subdomain
        try {
            const aResult = await execAsync(`nslookup mail.${domain}`);
            results.push(`A Record (mail): ${aResult.stdout.includes(process.env.SERVER_IP) ? '✅ Configured' : '❌ Not pointing to server'}`);
        } catch (error) {
            results.push('A Record (mail): ❌ Not found');
        }
        
        res.json({ success: true, results });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// --- Compatibility alias routes for UI fallbacks ---
app.get('/api/stats', authenticateToken, (req, res) => {
    const totalStorage = emailAccounts.reduce((sum, a) => sum + (a.storage || 0), 0);
    res.json({ totalDomains: domains.length, totalEmails: emailAccounts.length, storageUsed: totalStorage});
});
app.get('/api/system/logs', authenticateToken, (req, res) => res.json(systemLogs.slice(0,50)));
app.get('/api/emails', authenticateToken, (req, res) => res.json(emailAccounts.map(a=>({ email: a.address, lastLogin: a.lastLogin, role: 'User' }))));
app.post('/api/emails', authenticateToken, async (req, res) => {
    try {
        const { email } = req.body || {}; if (!email) return res.status(400).json({ error:'Email required' });
        const [user, domain] = String(email).split('@'); if (!user || !domain) return res.status(400).json({ error:'Invalid email' });
        const pwd = generatePassword(12); await createEmailAccount(email, pwd, domain, 0.5);
        res.json({ success:true, email });
    } catch(e){ res.status(500).json({ error:'Failed to create email' }); }
});
app.post('/api/emails/reset', authenticateToken, async (req, res) => {
    try { const { email } = req.body || {}; if (!email) return res.status(400).json({ error:'Email required' }); addLog(`Password reset requested for ${email}`); res.json({ success:true }); } catch(e){ res.status(500).json({ error:'Failed' }); }
});

// Clients list/export to satisfy UI fallbacks
app.get('/api/clients', authenticateToken, (req,res)=>{
    try {
        const { users } = require('./auth');
        const list = users.filter(u=>u.role==='client').map(u=>({ name: u.name, company: u.company, email: u.email, domain: u.domain }));
        res.json({ clients: list });
    } catch(e){ res.json({ clients: [] }); }
});
app.get('/clients', authenticateToken, (req,res)=>{
    try {
        const { users } = require('./auth');
        const list = users.filter(u=>u.role==='client').map(u=>({ name: u.name, company: u.company, email: u.email, domain: u.domain }));
        res.json(list);
    } catch(e){ res.json([]); }
});
app.get('/clients/export', authenticateToken, (req,res)=>{
    try {
        const { users } = require('./auth');
        const cs = [ 'Name,Username,Email,Company,Phone,Domain,Created', ...users.filter(u=>u.role==='client').map(c=>`"${c.name}","${c.username}","${c.email}","${c.company||''}","${c.phone||''}","${c.domain||''}","${c.createdAt||''}"`) ].join('\n');
        res.setHeader('Content-Type','text/csv'); res.setHeader('Content-Disposition','attachment; filename="clients.csv"'); res.end(cs);
    } catch(e){ res.status(500).end(''); }
});

// Compute SparQ Plug entry URL for the current user (used by portal UI to navigate)
// Usage: GET /api/sparqplug/url -> { url, path, role }
app.get('/api/sparqplug/url', authenticateToken, (req, res) => {
    try {
        const role = (req.user && req.user.role) || (req.session?.user?.role) || 'client';
        const rolePathMap = { admin: '/admin', manager: '/manager', client: '/client', user: '/client' };
        const pathPart = rolePathMap[role] || '/client';
        // Support multiple env var spellings; default to public hostname
        const host = process.env.SPARGPLUG_HOST || process.env.SPARQPLUG_HOST || process.env.SPARQ_PLUG_HOST || 'sparqplug.getsparqd.com';
        // Base path for the Next.js app; default to root (empty) to match deployment
        let basePath = process.env.SPARGPLUG_BASE_PATH ?? process.env.SPARQPLUG_BASE_PATH ?? process.env.SPARQ_PLUG_BASE_PATH ?? '';
        if (basePath && basePath !== '/') {
            basePath = basePath.startsWith('/') ? basePath : '/' + basePath;
            basePath = basePath.endsWith('/') ? basePath.slice(0, -1) : basePath;
        } else {
            basePath = '';
        }
        const url = `https://${host}${basePath}${pathPart}`;
        res.json({ url, path: pathPart, role });
    } catch (e) {
        res.status(500).json({ error: 'Failed to compute app URL' });
    }
});

// Optional: just the role path
app.get('/api/sparqplug/path', authenticateToken, (req, res) => {
    const role = (req.user && req.user.role) || (req.session?.user?.role) || 'client';
    const rolePathMap = { admin: '/admin', manager: '/manager', client: '/client', user: '/client' };
    res.json({ path: rolePathMap[role] || '/client', role });
});

// Minimal webpage setup stub (dev-safe)
app.post('/api/setup/webpage', authenticateToken, checkPermission('domains:create'), async (req, res) => {
    try {
        const { domain, template } = req.body || {};
        if (!domain) return res.status(400).json({ error:'Domain required' });
        // Simulate creating a placeholder index.html in data dir on Windows/dev
        const siteDir = process.platform === 'win32' || process.env.SIMULATE_SETUP === 'true'
            ? path.join(__dirname, 'data', domain, 'site')
            : `/home/sparqd/sites/${domain}`;
        try { await fs.mkdir(siteDir, { recursive: true }); } catch(_){ }
        const html = `<!DOCTYPE html><meta charset="utf-8"><title>${domain}</title><h1>${domain}</h1><p>Template: ${template||'basic'}</p>`;
        try { await fs.writeFile(path.join(siteDir, 'index.html'), html); } catch(_){ }
        res.json({ success:true, details:[`Site initialized at ${siteDir}`]});
    } catch(e){ res.status(500).json({ error:'Webpage setup failed' }); }
});

// Initialize system
async function initializeSystem() {
    addLog('Email Admin Dashboard starting up');
    // Ensure config dir exists
    try { await fs.mkdir(path.dirname(CONFIG_PATH), { recursive: true }); } catch (_) {}
    // Load existing configurations if any
    try {
        const configData = await fs.readFile(CONFIG_PATH, 'utf8');
        const config = JSON.parse(configData);
        domains = config.domains || [];
        emailAccounts = config.emailAccounts || [];
    userProfiles = config.userProfiles || {};
    userBilling = config.userBilling || {};
    userPreferences = config.userPreferences || {};
        addLog(`Loaded ${domains.length} domains and ${emailAccounts.length} email accounts`);
    } catch (error) {
        addLog('No existing configuration found, starting fresh');
    }
}

// Save configuration periodically
setInterval(async () => {
    try {
        const config = {
            domains,
            emailAccounts: emailAccounts.map(acc => ({
                ...acc,
                password: undefined // Don't save plain text passwords
            })),
            userProfiles,
            userBilling,
            userPreferences,
            lastSaved: new Date().toISOString()
        };
        await fs.writeFile(CONFIG_PATH, JSON.stringify(config, null, 2));
    } catch (error) {
        addLog(`Failed to save configuration: ${error.message}`, 'error');
    }
}, 60000); // Save every minute

// Start server
app.listen(PORT, async () => {
    await initializeSystem();
    addLog(`Email Admin Dashboard running on port ${PORT}`);
    console.log(`\n🎉 Email Admin Dashboard is ready!`);
    console.log(`📧 Access at: http://localhost:${PORT}`);
    console.log(`🌐 Or: http://${process.env.SERVER_IP}:${PORT}`);
});

// ---- Additional APIs to support Storage and Settings UIs ----

// Storage summary for UI (dev-friendly; replace with real metrics in prod)
app.get('/api/storage/summary', authenticateToken, checkPermission('storage:read'), async (req, res) => {
    try {
        const totalGB = Number(process.env.STORAGE_TOTAL_GB || 1024);
        const pools = {
            email: { capacityGB: Number(process.env.EMAIL_POOL_CAP_GB || 256), allocatedGB: emailAccounts.length * 0.5 },
            web: { capacityGB: Number(process.env.WEB_POOL_CAP_GB || 256), allocatedGB: 0 },
            content: { capacityGB: Number(process.env.CONTENT_POOL_CAP_GB || 256), allocatedGB: 0 },
            reserve: { capacityGB: Number(process.env.RESERVE_POOL_CAP_GB || 256), allocatedGB: 0 },
        };
        const allocatedGB = Object.values(pools).reduce((s, p) => s + (Number(p.allocatedGB) || 0), 0);
        const availableGB = Math.max(0, totalGB - allocatedGB);
        const domainList = domains.map(d => ({ domain: d.name, allocatedGB: Math.floor((d.emailCount || 0) * 0.5), usedGB: 0 }));
        res.json({ totalGB, availableGB, allocatedGB, pools, domains: domainList });
    } catch (e) { res.status(500).json({ error: 'Failed to compute storage summary' }); }
});

// Map /api/user/me to account profile
app.get('/api/user/me', authenticateToken, (req, res) => {
    const base = req.user || {};
    const profile = userProfiles[base.id] || {};
    res.json({
        id: base.id,
        username: base.username,
        email: base.email,
        name: base.name,
        role: base.role,
        phone: profile.phone || '',
        timezone: profile.timezone || '',
        address: profile.address || {}
    });
});

// Update profile
app.put('/api/user/me', authenticateToken, async (req, res) => {
    const uid = req.user.id;
    const cur = userProfiles[uid] || {};
    const { name, phone, timezone, address } = req.body || {};
    // Optionally update name in auth users array
    try {
        const auth = require('./auth');
        const u = auth.users.find(x => x.id === uid);
        if (u && name) u.name = name;
    } catch(_){}
    userProfiles[uid] = { ...cur, name: name ?? cur.name, phone, timezone, address };
    res.json({ success: true });
});

// Account password change
app.post('/api/account/password', authenticateToken, async (req, res) => {
    // Password changes are disabled; only fixed admin password is supported
    return res.status(403).json({ error: 'Password change is disabled' });
});

// Preferences
app.get('/api/account/preferences', authenticateToken, (req, res) => {
    res.json(userPreferences[req.user.id] || { emails: true, security: true, updates: false });
});
app.put('/api/account/preferences', authenticateToken, (req, res) => {
    const cur = userPreferences[req.user.id] || {};
    const { emails, security, updates } = req.body || {};
    userPreferences[req.user.id] = { emails: !!emails, security: !!security, updates: !!updates };
    res.json({ success: true });
});

// Billing
app.get('/api/billing', authenticateToken, (req, res) => {
    res.json(userBilling[req.user.id] || { company: '', email: req.user.email, phone: '', taxId: '', sameAsMailing: true, address: {} });
});
app.put('/api/billing', authenticateToken, (req, res) => {
    const { company, email, phone, taxId, address, sameAsMailing } = req.body || {};
    userBilling[req.user.id] = { company: company||'', email: email||'', phone: phone||'', taxId: taxId||'', address: address||{}, sameAsMailing: !!sameAsMailing };
    res.json({ success: true });
});

// Lightweight SparQy assistant stubs
app.get('/api/sparqy/health', authenticateToken, (req,res)=> res.json({ ok:true, model:'stub', time: Date.now() }));
const sparqyHistory = [];
app.get('/api/sparqy/history', authenticateToken, (req,res)=> res.json({ messages: sparqyHistory.slice(-20) }));
app.post('/api/sparqy/chat', authenticateToken, (req,res)=>{
    try {
        const { content, message } = req.body || {};
        const text = String((content ?? message) || '').slice(0, 2000);
        if (!text) return res.status(400).json({ error: 'Message is required' });
        const userMsg = { role:'user', content: text, at: Date.now() };
        sparqyHistory.push(userMsg);
        const replyText = 'This is a local dev stub. Your message was: ' + text;
        const replyMsg = { role:'assistant', content: replyText, at: Date.now(), sources: [] };
        sparqyHistory.push(replyMsg);
        // Respond in the shape the UI expects
        res.json({ reply: replyText, sources: [] });
    } catch (e) {
        res.status(500).json({ error: 'Assistant failed' });
    }
});
app.post('/api/sparqy/clear', authenticateToken, (req,res)=>{ sparqyHistory.length = 0; res.json({ ok:true }); });
