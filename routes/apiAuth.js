// routes/apiAuth.js - SIMPLE VERSION
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const ApiUser = require('../models/ApiUser');

const JWT_SECRET = process.env.API_USER_JWT_SECRET || 'your-api-user-jwt-secret';

// Login for API User Dashboard
router.post('/login', async (req, res) => {
    try {
        const { username, apiSecret } = req.body;
        
        if (!username || !apiSecret) {
            return res.status(400).json({ error: 'Username and API Secret required' });
        }
        
        const apiUser = await ApiUser.findOne({ username });
        
        if (!apiUser) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        if (apiUser.status !== 'active') {
            return res.status(403).json({ 
                error: 'Account is suspended',
                status: apiUser.status
            });
        }
        
        if (apiUser.apiSecret !== apiSecret) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Update last login
        apiUser.lastLoginAt = new Date();
        await apiUser.save();
        
        // Generate JWT
        const token = jwt.sign(
            { id: apiUser._id, username: apiUser.username },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({
            success: true,
            token,
            user: {
                id: apiUser._id,
                username: apiUser.username,
                email: apiUser.email,
                status: apiUser.status,
                limits: apiUser.limits,
                totalAttacks: apiUser.totalAttacks,
                createdAt: apiUser.createdAt
            }
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Get dashboard stats (with full API key)
// routes/apiAuth.js - Add/modify this endpoint
router.get('/dashboard/stats', verifyApiUserToken, async (req, res) => {
    try {
        const apiUser = await ApiUser.findById(req.apiUserId);
        
        if (!apiUser) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Clean expired attacks and get count
        const now = new Date();
        const beforeCount = apiUser.activeAttacks.length;
        apiUser.activeAttacks = apiUser.activeAttacks.filter(a => a.expiresAt > now);
        if (beforeCount !== apiUser.activeAttacks.length) {
            await apiUser.save();
        }
        
        const activeCount = apiUser.activeAttacks.length;
        
        res.json({
            success: true,
            user: {
                id: apiUser._id,
                username: apiUser.username,
                email: apiUser.email,
                status: apiUser.status,
                limits: apiUser.limits,
                createdAt: apiUser.createdAt
            },
            stats: {
                totalAttacks: apiUser.totalAttacks || 0,
                totalRequests: apiUser.totalRequests || 0,
                currentActiveAttacks: activeCount,
                remainingSlots: apiUser.limits.maxConcurrent - activeCount
            },
            activeAttacks: apiUser.activeAttacks.map(a => ({
                attackId: a.attackId,
                target: a.target,
                port: a.port,
                expiresIn: Math.max(0, Math.floor((a.expiresAt - now) / 1000))
            })),
            apiKey: apiUser.apiKey
        });
        
    } catch (error) {
        console.error('Dashboard error:', error);
        res.status(500).json({ error: 'Failed to fetch dashboard data' });
    }
});
// Verify JWT middleware
function verifyApiUserToken(req, res, next) {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.apiUserId = decoded.id;
        req.apiUsername = decoded.username;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expired' });
        }
        return res.status(401).json({ error: 'Invalid token' });
    }
}

module.exports = router;
module.exports.verifyApiUserToken = verifyApiUserToken;