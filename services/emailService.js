// services/emailService.js
const { Resend } = require('resend');

let resend = null;
let emailReady = false;

try {
  if (process.env.RESEND_API_KEY) {
    resend = new Resend(process.env.RESEND_API_KEY);
    emailReady = true;
    console.log('[Email] Resend initialized successfully');
  } else {
    console.warn('[Email] RESEND_API_KEY not found in environment variables');
  }
} catch (error) {
  console.error('[Email] Resend init failed:', error.message);
}

// The "from" address — must be a verified domain in Resend dashboard
// During testing you can use: onboarding@resend.dev (only sends to your own email)
// For production: use your own domain e.g. noreply@battle-destroyer.shop
const FROM_ADDRESS = process.env.EMAIL_FROM
  || `Battle Destroyer <noreply@battle-destroyer.shop>`;

// Generate 6-digit OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Send OTP email
async function sendOTPEmail(email, otp, username = '') {
  if (!emailReady || !resend) {
    console.error('[Email] Resend not configured, cannot send OTP email');
    return false;
  }

  try {
    const { data, error } = await resend.emails.send({
      from: FROM_ADDRESS,
      to: [email],
      subject: 'Verify Your Battle Destroyer Account',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Verify Your Account</title>
          <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; }
            .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
            .header { background: linear-gradient(135deg, #ef4444, #dc2626); padding: 30px; text-align: center; }
            .header h1 { color: white; margin: 0; font-size: 28px; letter-spacing: 2px; }
            .content { padding: 40px 30px; text-align: center; }
            .otp-code { background: #f8f9fa; padding: 20px; font-size: 42px; font-weight: bold; letter-spacing: 12px; color: #dc2626; border-radius: 8px; margin: 24px 0; font-family: monospace; border: 2px dashed #dc2626; }
            .expire-note { color: #888; font-size: 14px; margin: 10px 0 20px; }
            .warning { color: #666; font-size: 12px; margin-top: 20px; padding-top: 20px; border-top: 1px solid #eee; }
            .footer { background: #f8f9fa; padding: 20px; text-align: center; color: #999; font-size: 12px; }
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
              <p>Thanks for signing up! Use the code below to complete your registration:</p>
              <div class="otp-code">${otp}</div>
              <p class="expire-note">This code expires in <strong>10 minutes</strong>.</p>
              <p>If you did not create an account, you can safely ignore this email.</p>
              <div class="warning">
                <strong>Security Notice</strong><br>
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
      `,
    });

    if (error) {
      console.error(`[Email] OTP send failed to ${email}:`, error.message || JSON.stringify(error));
      return false;
    }

    console.log(`[Email] OTP sent to ${email} | ID: ${data.id}`);
    return true;
  } catch (error) {
    console.error(`[Email] OTP send exception to ${email}: ${error.message}`);
    return false;
  }
}

// Send welcome email
async function sendWelcomeEmail(email, username) {
  if (!emailReady || !resend) {
    console.error('[Email] Resend not configured, cannot send welcome email');
    return false;
  }

  const frontendUrl = process.env.FRONTEND_URL || 'https://battle-destroyer.shop';

  try {
    const { data, error } = await resend.emails.send({
      from: FROM_ADDRESS,
      to: [email],
      subject: 'Welcome to Battle Destroyer!',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Welcome to Battle Destroyer</title>
          <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; }
            .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
            .header { background: linear-gradient(135deg, #ef4444, #dc2626); padding: 30px; text-align: center; }
            .header h1 { color: white; margin: 0; font-size: 28px; letter-spacing: 2px; }
            .content { padding: 40px 30px; text-align: center; }
            .button { background: linear-gradient(135deg, #ef4444, #dc2626); color: white; padding: 14px 34px; text-decoration: none; border-radius: 8px; display: inline-block; margin: 20px 0; font-weight: bold; font-size: 16px; }
            .features { text-align: left; margin: 24px 0; }
            .feature { margin: 12px 0; padding: 12px 16px; background: #f8f9fa; border-radius: 8px; font-size: 14px; }
            .footer { background: #f8f9fa; padding: 20px; text-align: center; color: #999; font-size: 12px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>BATTLE DESTROYER</h1>
            </div>
            <div class="content">
              <h2>Welcome, ${username}!</h2>
              <p>Your account has been successfully verified and is ready to use.</p>
              <div class="features">
                <div class="feature"><strong>Referral System</strong> - Share your code and earn +2 credits per referral</div>
                <div class="feature"><strong>Device Protection</strong> - Your account is secured with fingerprint protection</div>
                <div class="feature"><strong>Attack Hub</strong> - Launch attacks directly from your dashboard</div>
              </div>
              <a href="${frontendUrl}/dashboard" class="button">Go to Dashboard</a>
            </div>
            <div class="footer">
              <p>Battle Destroyer - Attack with Honor</p>
              <p>&copy; ${new Date().getFullYear()} Battle Destroyer. All rights reserved.</p>
            </div>
          </div>
        </body>
        </html>
      `,
    });

    if (error) {
      console.error(`[Email] Welcome email failed to ${email}:`, error.message || JSON.stringify(error));
      return false;
    }

    console.log(`[Email] Welcome email sent to ${email} | ID: ${data.id}`);
    return true;
  } catch (error) {
    console.error(`[Email] Welcome email exception to ${email}: ${error.message}`);
    return false;
  }
}

module.exports = { generateOTP, sendOTPEmail, sendWelcomeEmail };