// config/bgmiConfig.js
const bgmiApis = process.env.BGMI_API_URLS
    ? process.env.BGMI_API_URLS.split(',')
    : [
    'https://test-api-bgmi-production-4bae.up.railway.app',
    'https://test-api-bgmi-production-3e6b.up.railway.app',
    'https://test-api-bgmi-production-4150.up.railway.app',
    'https://test-api-bgmi-production-76f9.up.railway.app',
    'https://test-api-bgmi-production-37f4.up.railway.app',
    'https://test-api-bgmi-production-863b.up.railway.app',
    'https://test-api-bgmi-production-4aeb.up.railway.app',
    'https://test-api-bgmi-production-cd7a.up.railway.app',
    'https://test-api-bgmi-production-4ab5.up.railway.app',
    'https://test-api-bgmi-production-7d9b.up.railway.app',
    'https://test-api-bgmi-production-8e51.up.railway.app',
    'https://test-api-bgmi-production-c315.up.railway.app',
    'https://test-api-bgmi-production-a24f.up.railway.app',
    'https://test-api-bgmi-production-b2c3.up.railway.app',
    'https://test-api-bgmi-production-7565.up.railway.app',
    'https://test-api-bgmi-production-37b6.up.railway.app',
    'https://test-api-bgmi-production-580c.up.railway.app',
    'https://test-api-bgmi-production-2001.up.railway.app',
    'https://test-api-bgmi-production-da98.up.railway.app',
    'https://test-api-bgmi-production-3a34.up.railway.app',
    'https://test-api-bgmi-production-23d9.up.railway.app',
    'https://test-api-bgmi-production-26a5.up.railway.app',
    'https://test-api-bgmi-production-c193.up.railway.app',
    'https://test-api-bgmi-production-f379.up.railway.app'
];

module.exports = {
    bgmiApis,
    maxRetries: 3,
    loadBalancing: {
        strategy: 'round-robin'
    },
    timeouts: {
        startServer: 10000,  // 10 seconds
        stopServer: 5000,    // 5 seconds
        statusCheck: 5000,   // 5 seconds
        healthCheck: 5000    // 5 seconds
    },
    maxConcurrentAttacks: 5,
    healthCheckInterval: 300000 // 5 minutes (0 to disable)
};  