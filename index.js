const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();

// ===== TRUST PROXY =====
app.set('trust proxy', 1);

// ===== SECURITY =====
app.use(helmet());
app.use(cors({ 
  origin: process.env.CLIENT_URL || 'http://localhost:3000', 
  credentials: true 
}));
app.use(express.json());

// ===== RATE LIMITING =====
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: 'Too many requests, please try again later.'
});
app.use('/api/', limiter);

// ===== HEALTH CHECK =====
app.get('/', (req, res) => {
  res.json({ message: '✅ Battle Destroyer API is running' });
});

// ===== ROUTES =====
app.use('/api/auth', require('./routes/auth'));
app.use('/api/panel', require('./routes/panel'));

// ===== 404 HANDLER =====
app.use((req, res) => {
  res.status(404).json({ message: '❌ Route not found' });
});

// ===== ERROR HANDLER =====
app.use((err, req, res, next) => {
  console.error('❌ Error:', err);
  res.status(err.status || 500).json({ 
    message: err.message || 'Server error' 
  });
});

// ===== MONGODB CONNECTION & SERVER START =====
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log('✅ MongoDB connected successfully');
    app.listen(process.env.PORT || 5000, () => {
      console.log(`🚀 Server running on port ${process.env.PORT || 5000}`);
      console.log(`📍 Local: http://localhost:${process.env.PORT || 5000}`);
      console.log(`🔗 API: http://localhost:${process.env.PORT || 5000}/api`);
    });
  })
  .catch(err => {
    console.error('❌ MongoDB Connection Error:', err.message);
    process.exit(1);
  });

// ===== HANDLE UNHANDLED PROMISE REJECTIONS =====
process.on('unhandledRejection', (err) => {
  console.error('❌ Unhandled Rejection:', err);
  process.exit(1);
});