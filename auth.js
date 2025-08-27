const express = require('express');
const bcrypt = require('./bcrypt-compat');
const jwt = require('jsonwebtoken');
const session = require('express-session');

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

const users = [
    {
        id: 1,
        username: 'hligon',
        email: 'hligon@getsparqd.com',
        password: '$2b$10$YylpldJdY2HSz8wnhvMKBecD7f1cm83HS.Q6nsurOwLzIFsKC94f6',
        role: ROLES.ADMIN,
        name: 'Harold Ligon'
    },
    {
        id: 2,
        username: 'bhall',
        email: 'bhall@getsparqd.com', 
        password: '$2b$10$YylpldJdY2HSz8wnhvMKBecD7f1cm83HS.Q6nsurOwLzIFsKC94f6',
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
        let validPassword = await bcrypt.compare(password, user.password);
        // Dev override: allow a plain env password in non-production for bootstrap
        if (!validPassword && process.env.NODE_ENV !== 'production' && process.env.DEFAULT_ADMIN_PASSWORD) {
            if (password === process.env.DEFAULT_ADMIN_PASSWORD) validPassword = true;
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
