const express = require('express');
const bcrypt = require('./bcrypt-compat');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const cookie = require('cookie');

const router = express.Router();

// User roles and permissions
const ROLES = {
    ADMIN: 'admin',
    MANAGER: 'manager', 
    CLIENT: 'client'
};

const PERMISSIONS = {
    [ROLES.ADMIN]: ['*'], // All permissions
    [ROLES.MANAGER]: [
        'dashboard:read',
        'emails:read', 'emails:create', 'emails:update', 'emails:delete',
        'domains:read', 'domains:create', 'domains:update',
        'storage:read', 'dns:read', 'dns:test',
        'logs:read', 'settings:read',
        'users:read', 'users:update'
    ],
    [ROLES.CLIENT]: [
        'dashboard:read',
        'emails:read',
        'domains:read',  
        'storage:read',
        'profile:read', 'profile:update'
    ]
};

// Only two embedded admin users; password validated against a fixed secret below
const users = [
    {
        id: 1,
        username: 'hligon',
        email: 'hligon@getsparqd.com',
        password: null,
        role: ROLES.ADMIN,
        name: 'Harold Ligon'
    },
    {
        id: 2,
        username: 'bhall',
        email: 'bhall@getsparqd.com', 
        password: null,
        role: ROLES.ADMIN,
        name: 'Bryan Hall'
    }
];

const adminUsers = users.filter(user => user.role === ROLES.ADMIN);
const managers = [];
const clients = [];
// In-memory password reset tokens: token -> { userId, expiresAt }
const resetTokens = new Map();

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token && !req.session.user) {
        return res.status(401).json({ error: 'Access token required' });
    }
    if (token) {
        jwt.verify(token, process.env.JWT_SECRET || 'email-admin-secret', (err, user) => {
            if (err) return res.status(403).json({ error: 'Invalid token' });
            req.user = user;
            next();
        });
    } else if (req.session.user) {
        req.user = req.session.user;
        next();
    }
};

const checkPermission = (requiredPermission) => {
    return (req, res, next) => {
        const userRole = req.user.role;
        const permissions = PERMISSIONS[userRole] || [];
        if (permissions.includes('*') || permissions.includes(requiredPermission)) {
            next();
        } else {
            res.status(403).json({ 
                error: 'Insufficient permissions',
                required: requiredPermission,
                userRole: userRole
            });
        }
    };
};

router.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = users.find(u => u.username === username || u.email === username);
        if (!user) return res.status(401).json({ error: 'Invalid credentials' });
        const FIXED_ADMIN_PASS = 'sparqd2025!';
        let validPassword = (password === FIXED_ADMIN_PASS);
        // Back-compat: if a hash exists, allow it too
        if (!validPassword && user.password) {
            validPassword = await bcrypt.compare(password, user.password);
        }
        if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });
        const token = jwt.sign({ 
            id: user.id, 
            username: user.username, 
            role: user.role,
            email: user.email,
            name: user.name
        }, process.env.JWT_SECRET || 'email-admin-secret', { expiresIn: '24h' });
        req.session.user = {
            id: user.id,
            username: user.username,
            role: user.role,
            email: user.email,
            name: user.name
        };
        // Also issue parent-domain SSO cookies for cross-subdomain auth
        try {
            const domain = process.env.SSO_COOKIE_DOMAIN || process.env.SESSION_DOMAIN || '.getsparqd.com';
            const secure = process.env.NODE_ENV === 'production' ? true : 'auto';
            const sameSite = 'lax';
            const ssoSecret = process.env.SSO_JWT_SECRET || process.env.JWT_SECRET || 'email-admin-secret';
            const ssoTtl = Number(process.env.SSO_ACCESS_TTL_SEC || 60 * 60); // 1h default
            const ssoToken = jwt.sign({ id: user.id, username: user.username, email: user.email, role: user.role, name: user.name }, ssoSecret, { expiresIn: ssoTtl });
            res.cookie?.('sparq_sso', ssoToken, { httpOnly: true, secure, sameSite, domain, maxAge: ssoTtl * 1000, path: '/' });
            res.cookie?.('role', String(user.role || ''), { httpOnly: false, secure, sameSite, domain, maxAge: ssoTtl * 1000, path: '/' });
        } catch (_) { /* best-effort */ }
        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role,
                name: user.name,
                permissions: PERMISSIONS[user.role]
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Login failed' });
    }
});

router.post('/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true, message: 'Logged out successfully' });
});

router.get('/me', authenticateToken, (req, res) => {
    const user = users.find(u => u.id === req.user.id);
    if (user) {
        res.json({
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
            name: user.name,
            permissions: PERMISSIONS[user.role]
        });
    } else {
        res.status(404).json({ error: 'User not found' });
    }
});

// Request password reset: accepts { username, email }
router.post('/request-reset', async (req, res) => {
    try {
        const { username, email } = req.body || {};
        if (!username || !email) return res.status(400).json({ error: 'Username and email are required' });
        const user = users.find(u => (u.username === username || u.email === username) && u.email === email);
        // Always respond success to avoid user enumeration; only set token if user exists
        let resetToken;
        if (user) {
            resetToken = Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
            const expiresAt = Date.now() + 15 * 60 * 1000; // 15 minutes
            resetTokens.set(resetToken, { userId: user.id, expiresAt });
        }
        const baseMsg = 'If the account exists, a reset token has been generated.';
        // In non-production, return token to simplify local testing
        if (process.env.NODE_ENV !== 'production' && resetToken) {
            return res.json({ success: true, message: baseMsg, resetToken, expiresInMinutes: 15 });
        }
        res.json({ success: true, message: baseMsg });
    } catch (e) {
        res.status(500).json({ error: 'Failed to process reset request' });
    }
});

// Complete password reset: accepts { token, newPassword }
router.post('/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body || {};
        if (!token || !newPassword) return res.status(400).json({ error: 'Token and new password are required' });
        const rec = resetTokens.get(token);
        if (!rec || rec.expiresAt < Date.now()) {
            resetTokens.delete(token);
            return res.status(400).json({ error: 'Invalid or expired token' });
        }
        const idx = users.findIndex(u => u.id === rec.userId);
        if (idx === -1) {
            resetTokens.delete(token);
            return res.status(404).json({ error: 'User not found' });
        }
        users[idx].password = await bcrypt.hash(newPassword, 10);
        users[idx].requirePasswordChange = false;
        resetTokens.delete(token);
        res.json({ success: true, message: 'Password reset successfully' });
    } catch (e) {
        res.status(500).json({ error: 'Failed to reset password' });
    }
});

router.post('/create-client-access', authenticateToken, checkPermission('domains:create'), async (req, res) => {
    const { domain, clientEmail, clientName } = req.body;
    try {
        const tempPassword = Math.random().toString(36).slice(-8);
        const hashedPassword = await bcrypt.hash(tempPassword, 10);
        const clientUser = {
            id: users.length + 1,
            username: `client_${domain.replace(/\./g, '_')}`,
            email: clientEmail,
            password: hashedPassword,
            role: ROLES.CLIENT,
            name: clientName,
            domain: domain,
            created: new Date().toISOString()
        };
        users.push(clientUser);
        clients.push(clientUser);
        const token = jwt.sign({
            id: clientUser.id,
            username: clientUser.username,
            role: clientUser.role,
            domain: domain
        }, process.env.JWT_SECRET || 'email-admin-secret', { expiresIn: '30d' });
        res.json({
            success: true,
            clientAccess: {
                username: clientUser.username,
                tempPassword,
                loginUrl: `https://admin.getsparqd.com/client/${domain}`,
                token
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to create client access' });
    }
});

module.exports = {
    router,
    authenticateToken,
    checkPermission,
    ROLES,
    PERMISSIONS,
    adminUsers,
    managers,
    clients,
    users // Add users export
};

// --- SSO endpoints (mounted under /api/auth) ---
// Issues/clears/verifies a parent-domain JWT cookie so subdomains can share auth
// Cookie name and secrets are configurable via env.

// Helper to sign JWT and set cookies on response
function issueSsoCookies(res, user, opts = {}) {
    const jwtSecret = process.env.SSO_JWT_SECRET || process.env.JWT_SECRET || 'email-admin-secret';
    const maxAgeSeconds = Number(process.env.SSO_ACCESS_TTL_SEC || 60 * 60); // 1h default
    const payload = {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        name: user.name
    };
    const token = jwt.sign(payload, jwtSecret, { expiresIn: maxAgeSeconds });
    const domain = process.env.SSO_COOKIE_DOMAIN || process.env.SESSION_DOMAIN || '.getsparqd.com';
    const secure = process.env.NODE_ENV === 'production' ? true : 'auto';
    const sameSite = 'lax';
    // Set main SSO cookie (httpOnly)
    res.cookie?.('sparq_sso', token, {
        httpOnly: true,
        secure,
        sameSite,
        domain,
        maxAge: maxAgeSeconds * 1000,
        path: '/'
    });
    // Also expose a minimal non-HTTPOnly role hint for client-side UX (optional)
    try {
        res.append?.('Set-Cookie', cookie.serialize('role', String(user.role || ''), {
            httpOnly: false,
            secure: !!secure,
            sameSite,
            domain,
            maxAge: maxAgeSeconds,
            path: '/'
        }));
    } catch (_) { /* best-effort */ }
    return token;
}

// POST /api/auth/sso/login — authenticate and set parent-domain cookie(s)
router.post('/sso/login', async (req, res) => {
    try {
        const { username, password, returnTo } = req.body || {};
        if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });
        const user = users.find(u => u.username === username || u.email === username);
        if (!user) return res.status(401).json({ error: 'Invalid credentials' });
        const FIXED_ADMIN_PASS = 'sparqd2025!';
        let validPassword = (password === FIXED_ADMIN_PASS);
        if (!validPassword && user.password) {
            validPassword = await bcrypt.compare(password, user.password);
        }
        if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });

        // Maintain server-side session too (optional but helpful for portal)
        if (req.session) {
            req.session.user = { id: user.id, username: user.username, role: user.role, email: user.email, name: user.name };
        }

        const token = issueSsoCookies(res, user);

        // Validate returnTo for safety
        const safeRt = (typeof returnTo === 'string' && /^https:\/\/(?:[\w-]+\.)*getsparqd\.com(?![^\s]*\s)/.test(returnTo)) ? returnTo : undefined;
        res.json({ success: true, token, user: { id: user.id, username: user.username, email: user.email, role: user.role, name: user.name }, redirect: safeRt });
    } catch (e) {
        res.status(500).json({ error: 'Login failed' });
    }
});

// GET /api/auth/sso/me — verify cookie and return claims
router.get('/sso/me', (req, res) => {
    try {
        const raw = (req.cookies && req.cookies['sparq_sso']) || (req.headers.cookie || '').split(/;\s*/).find(s => s.startsWith('sparq_sso='))?.split('=')[1];
        if (!raw) return res.status(401).json({ error: 'No SSO cookie' });
        const jwtSecret = process.env.SSO_JWT_SECRET || process.env.JWT_SECRET || 'email-admin-secret';
        const payload = jwt.verify(raw, jwtSecret);
        res.set('Cache-Control', 'no-store');
        return res.json({ ok: true, user: { id: payload.id, username: payload.username, email: payload.email, role: payload.role, name: payload.name } });
    } catch (e) {
        return res.status(401).json({ error: 'Invalid or expired SSO' });
    }
});

// POST /api/auth/sso/logout — clear cookies (and session if present)
router.post('/sso/logout', (req, res) => {
    const domain = process.env.SSO_COOKIE_DOMAIN || process.env.SESSION_DOMAIN || '.getsparqd.com';
    const secure = process.env.NODE_ENV === 'production' ? true : 'auto';
    const sameSite = 'lax';
    // Clear cookies by setting empty value and immediate expiry
    res.cookie?.('sparq_sso', '', { httpOnly: true, secure, sameSite, domain, maxAge: 0, expires: new Date(0), path: '/' });
    try { res.append?.('Set-Cookie', cookie.serialize('role', '', { httpOnly: false, secure: !!secure, sameSite, domain, maxAge: 0, expires: new Date(0), path: '/' })); } catch(_){}
    if (req.session) req.session.destroy(() => {});
    res.json({ success: true });
});

