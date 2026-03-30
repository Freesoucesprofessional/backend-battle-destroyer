// services/bgmiService.js
const axios = require('axios');
const { bgmiApis, maxRetries } = require('../config/bgmiConfig');

class BGMIService {
    constructor() {
        this.currentApiIndex = 0;
    }

    // Round-robin load balancing
    getNextApi() {
        const api = bgmiApis[this.currentApiIndex];
        this.currentApiIndex = (this.currentApiIndex + 1) % bgmiApis.length;
        return api;
    }

    async startServer(ip, port, duration, threads = 1) {
        let lastError = null;

        for (let i = 0; i < maxRetries; i++) {
            const apiUrl = this.getNextApi();
            try {
                const response = await axios.post(`${apiUrl}/start-server`, {
                    ip,
                    port,
                    duration,
                    threads
                });

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

    async stopServer(apiUrl) {
        try {
            const response = await axios.post(`${apiUrl}/stop-server`);
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

    async getStatus(apiUrl) {
        try {
            const response = await axios.get(`${apiUrl}/status`);
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
}

module.exports = new BGMIService();