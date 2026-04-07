// services/emailService.js
const SibApiV3Sdk = require('brevo');

// Initialize Brevo
let apiInstance = null;
let apiKeyConfigured = false;

try {
  if (process.env.BREVO_API_KEY) {
    apiInstance = new SibApiV3Sdk.TransactionalEmailsApi();
    apiInstance.setApiKey(SibApiV3Sdk.TransactionalEmailsApiApiKeys.apiKey, process.env.BREVO_API_KEY);
    apiKeyConfigured = true;
    console.log('[Email] Brevo initialized successfully');
  } else {
    console.warn('[Email] BREVO_API_KEY not found in environment variables');
  }
} catch (error) {
  console.error('[Email] Brevo init failed:', error.message);
}

// Generate 6-digit OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Send OTP email using Brevo
async function sendOTPEmail(email, otp, username = '') {
  if (!apiKeyConfigured) {
    console.error('[Email] Brevo not configured, cannot send email');
    return false;
  }

  const senderEmail = process.env.EMAIL_FROM || process.env.BREVO_SENDER_EMAIL || 'noreply@battle-destroyer.railway.app';
  const senderName = process.env.EMAIL_FROM_NAME || 'Battle Destroyer';

  const sendSmtpEmail = new SibApiV3Sdk.SendSmtpEmail();
  sendSmtpEmail.subject = 'Verify Your Battle Destroyer Account';
  sendSmtpEmail.to = [{ email: email, name: username || email.split('@')[0] }];
  sendSmtpEmail.sender = { email: senderEmail, name: senderName };
  
  sendSmtpEmail.htmlContent = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Verify Your Account</title>
      <style>
        body { font-family: 'Arial', sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #ef4444, #dc2626); padding: 30px; text-align: center; }
        .header h1 { color: white; margin: 0; font-size: 28px; letter-spacing: 2px; }
        .content { padding: 40px 30px; text-align: center; }
        .otp-code { background: #f8f9fa; padding: 20px; font-size: 36px; font-weight: bold; letter-spacing: 8px; color: #dc2626; border-radius: 8px; margin: 20px 0; font-family: monospace; }
        .warning { color: #666; font-size: 12px; margin-top: 20px; padding-top: 20px; border-top: 1px solid #eee; }
        .footer { background: #f8f9fa; padding: 20px; text-align: center; color: #666; font-size: 12px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>BATTLE DESTROYER</h1>
        </div>
        <div class="content">
          <h2>Verify Your Email Address</h2>
          ${username ? `<p>Hello <strong>${username}</strong>,</p>` : '<p>Hello,</p>'}
          <p>Thanks for signing up! Please use the following verification code to complete your registration:</p>
          <div class="otp-code">${otp}</div>
          <p>This code will expire in <strong>10 minutes</strong>.</p>
          <p>If you didn't request this, please ignore this email.</p>
          <div class="warning">
            <strong>⚠️ Security Notice</strong><br>
            Never share this code with anyone. Battle Destroyer will never ask for this code outside the registration process.
          </div>
        </div>
        <div class="footer">
          <p>Battle Destroyer - Attack with Honor</p>
          <p>&copy; ${new Date().getFullYear()} Battle Destroyer. All rights reserved.</p>
        </div>
      </div>
    </body>
    </html>
  `;

  try {
    const data = await apiInstance.sendTransacEmail(sendSmtpEmail);
    console.log(`[Email] OTP sent to ${email}, MessageId: ${data.messageId}`);
    return true;
  } catch (error) {
    console.error('[Email] Send failed:', error.response?.body?.message || error.message);
    return false;
  }
}

// Send welcome email using Brevo
async function sendWelcomeEmail(email, username) {
  if (!apiKeyConfigured) {
    console.error('[Email] Brevo not configured, cannot send welcome email');
    return false;
  }

  const senderEmail = process.env.EMAIL_FROM || process.env.BREVO_SENDER_EMAIL || 'noreply@battle-destroyer.railway.app';
  const senderName = process.env.EMAIL_FROM_NAME || 'Battle Destroyer';
  const frontendUrl = process.env.FRONTEND_URL || 'https://your-app.railway.app';

  const sendSmtpEmail = new SibApiV3Sdk.SendSmtpEmail();
  sendSmtpEmail.subject = 'Welcome to Battle Destroyer! 🎮';
  sendSmtpEmail.to = [{ email: email, name: username }];
  sendSmtpEmail.sender = { email: senderEmail, name: senderName };
  
  sendSmtpEmail.htmlContent = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Welcome to Battle Destroyer</title>
      <style>
        body { font-family: 'Arial', sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #ef4444, #dc2626); padding: 30px; text-align: center; }
        .header h1 { color: white; margin: 0; font-size: 28px; letter-spacing: 2px; }
        .content { padding: 40px 30px; text-align: center; }
        .button { background: linear-gradient(135deg, #ef4444, #dc2626); color: white; padding: 12px 30px; text-decoration: none; border-radius: 8px; display: inline-block; margin: 20px 0; font-weight: bold; }
        .features { text-align: left; margin: 30px 0; padding: 0 20px; }
        .feature { margin: 15px 0; padding: 10px; background: #f8f9fa; border-radius: 8px; }
        .footer { background: #f8f9fa; padding: 20px; text-align: center; color: #666; font-size: 12px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>BATTLE DESTROYER</h1>
        </div>
        <div class="content">
          <h2>Welcome, ${username}! 🎉</h2>
          <p>Your account has been successfully verified and created!</p>
          <div class="features">
            <div class="feature">
              <strong>✨ Referral Bonus</strong> - You received credits from your referral!
            </div>
            <div class="feature">
              <strong>🔗 Referral System</strong> - Share your code and earn +2 credits per referral
            </div>
            <div class="feature">
              <strong>🛡️ Device Protection</strong> - Your account is secured
            </div>
          </div>
          <a href="${frontendUrl}/dashboard" class="button">Start Attacking →</a>
          <p>Ready to dominate the battlefield?</p>
        </div>
        <div class="footer">
          <p>Battle Destroyer - Attack with Honor</p>
        </div>
      </div>
    </body>
    </html>
  `;

  try {
    const data = await apiInstance.sendTransacEmail(sendSmtpEmail);
    console.log(`[Email] Welcome email sent to ${email}, MessageId: ${data.messageId}`);
    return true;
  } catch (error) {
    console.error('[Email] Welcome email failed:', error.response?.body?.message || error.message);
    return false;
  }
}

module.exports = { generateOTP, sendOTPEmail, sendWelcomeEmail };