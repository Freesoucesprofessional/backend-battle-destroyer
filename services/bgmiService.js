const axios = require('axios');
const { bgmiApis, maxRetries, timeouts } = require('../config/bgmiConfig');

class BGMIService {
    constructor() {
        this.currentApiIndex = 0;
    }

    // ── Initialize (called on server start) ──────────────────────────────────
    async initialize() {
        if (bgmiApis.length === 0) {
            throw new Error('No BGMI API URLs configured');
        }
        console.log(`🎮 BGMIService initialized with ${bgmiApis.length} endpoints`);
    }

    // ── Health check across all APIs ─────────────────────────────────────────
    async checkHealth() {
        const results = await Promise.allSettled(
            bgmiApis.map(url =>
                axios.get(`${url}/status`, { timeout: timeouts.healthCheck })
                    .then(() => true)
                    .catch(() => false)
            )
        );

        const healthy = results.filter(r => r.value === true).length;
        const total = bgmiApis.length;

        return {
            healthy,
            total,
            successRate: total > 0 ? `${Math.round((healthy / total) * 100)}%` : '0%'
        };
    }

    // ── Get count of configured APIs ─────────────────────────────────────────
    getApiCount() {
        return bgmiApis.length;
    }

    // ── Round-robin load balancing ───────────────────────────────────────────
    getNextApi() {
        const api = bgmiApis[this.currentApiIndex];
        this.currentApiIndex = (this.currentApiIndex + 1) % bgmiApis.length;
        return api;
    }

    // ── Start a server with retry logic ─────────────────────────────────────
    async startServer(ip, port, duration, threads = 1) {
        let lastError = null;

        for (let i = 0; i < maxRetries; i++) {
            const apiUrl = this.getNextApi();
            try {
                const response = await axios.post(
                    `${apiUrl}/start-server`,
                    { ip, port, duration, threads },
                    { timeout: timeouts.startServer }
                );

                if (response.data.status === 'success') {
                    return {
                        success: true,
                        data: response.data,
                        apiUrl
                    };
                }
            } catch (error) {
                lastError = error;
                console.error(`Attempt ${i + 1} failed for ${apiUrl}:`, error.message);
            }
        }

        return {
            success: false,
            error: lastError?.response?.data || lastError?.message || 'All attempts failed'
        };
    }

    // ── Stop a running server ────────────────────────────────────────────────
    async stopServer(apiUrl) {
        try {
            const response = await axios.post(
                `${apiUrl}/stop-server`,
                {},
                { timeout: timeouts.stopServer }
            );
            return {
                success: response.data.status === 'success',
                data: response.data
            };
        } catch (error) {
            return {
                success: false,
                error: error.response?.data || error.message
            };
        }
    }

    // ── Get status of a running server ───────────────────────────────────────
    async getStatus(apiUrl) {
        try {
            const response = await axios.get(
                `${apiUrl}/status`,
                { timeout: timeouts.statusCheck }
            );
            return {
                success: true,
                data: response.data
            };
        } catch (error) {
            return {
                success: false,
                error: error.response?.data || error.message
            };
        }
    }

    // ── Cleanup all running servers (called on SIGTERM) ──────────────────────
    async cleanup() {
        console.log('🧹 BGMIService cleanup called');
        // Nothing persistent to clean up in this implementation,
        // but the hook exists for future use (e.g. tracking active servers in-memory)
    }
}

module.exports = new BGMIService();