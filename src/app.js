require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid'); // Import UUID for unique identifiers
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


// Notify Project F function
const notifyProjectF = async (message, level = 'info') => {
    try {
        const notification = {
            id: uuidv4(),
            message,
            level,
            source: process.env.INSTANCE_NAME || 'PROJECT-Z',
            timestamp: new Date().toISOString()
        };

        await axios.post('http://localhost:3006/api/notifications', notification);
        console.log(`Notification sent to Project F: ${notification.message}`);
    } catch (error) {
        console.error(`Failed to notify Project F: ${error.message}`);
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

// Connectivity check function
const checkServerConnectivity = async (serverName, serverUrl) => {
    try {
        await axios.get(serverUrl);
        const message = `Successfully connected to ${serverName} at ${serverUrl}`;
        console.log(message);
        await notifyProjectF(message, 'info');
    } catch (error) {
        const errorMessage = `Failed to connect to ${serverName} at ${serverUrl}: ${error.message}`;
        console.error(errorMessage);
        await notifyProjectF(errorMessage, 'high');
    }
};

// Serve static files from the public directory
app.use(express.static(path.join(__dirname, '../public')));

// Serve the root index.html file
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Fallback for undefined routes
app.use((req, res) => {
    res.status(404).send('Resource not found.');
});

// Start server with security notifications and connectivity checks
const PORT = process.env.PORT || 3007;
app.listen(PORT, () => {
    console.log(`PROJECT-Z is running on http://localhost:${PORT}`);
    notifyProjectF('Project Z is up and running');
    notifyProjectF('Security service initialized successfully');

    // Perform connectivity checks
    checkServerConnectivity('Project A', 'http://localhost:3001/api/health');
    checkServerConnectivity('Project B', 'http://localhost:3002/api/health');
    checkServerConnectivity('Project D', 'http://localhost:3004/api/health');
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
