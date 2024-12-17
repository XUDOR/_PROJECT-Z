const express = require('express');
const cors = require('cors');
const axios = require('axios');
require('dotenv').config();
const path = require('path');
const mainRoutes = require('./routes/mainRoutes');
const { Pool } = require('pg');

// Add security-related middleware
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');


const app = express();

// Enhanced security middleware
app.use(helmet());  // Adds various HTTP headers for security
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || 'http://localhost:3000',
    methods: ['GET', 'POST'],
    credentials: true
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Parse JSON with size limits
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Routes
app.use('/api', mainRoutes);

// Database connection with SSL
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
    ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false
});


// Notify Project F (security events)
const notifyProjectF = async (message, securityLevel = 'info') => {
    try {
        await axios.post('http://localhost:3006/api/security-events', {
            message,
            level: securityLevel,
            source: 'PROJECT-Z',
            timestamp: new Date().toISOString()
        });
        console.log(`Security event logged: ${message}`);
    } catch (error) {
        console.error(`Failed to log security event: ${error.message}`);
    }
};

// Database connection with security logging
pool.connect((err, client, release) => {
    if (err) {
        console.error('Database connection error:', err.stack);
        notifyProjectF('Database connection failed - possible security concern', 'high');
    } else {
        console.log('Database connected successfully!');
        notifyProjectF('Secure database connection established', 'info');
        release();
    }
});

// Start server with security notifications
const PORT = process.env.PORT || 3007;  // Changed to 3007
app.listen(PORT, () => {
    console.log(`PROJECT-Z is running on http://localhost:${PORT}`);
    notifyProjectF('Security service initialized successfully');
});

// Global error handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    notifyProjectF(`Security error occurred: ${err.message}`, 'high');
    res.status(500).json({ 
        error: 'Internal server error',
        requestId: req.id // for tracking purposes
    });
});