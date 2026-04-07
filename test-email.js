// test-email.js
require('dotenv').config();

console.log('Testing emailService load...');

try {
  const emailService = require('./services/emailService');
  console.log('✅ emailService loaded successfully');
  console.log('Functions available:', Object.keys(emailService));
} catch (error) {
  console.error('❌ Failed to load emailService:', error.message);
  console.error(error.stack);
}
