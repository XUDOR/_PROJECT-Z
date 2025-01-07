// mainRoutes.js

require('dotenv').config();
const express = require('express');

const { scanFile } = require('../services/scan'); // Import the scanning function
const bcrypt = require('bcrypt');
const axios = require('axios');
const pool = require('../db/db');
const { logSecurityEvent, notifyProjectF } = require('../utils/securityUtils');
const jwtAuthHandler = require('../utils/jwtAuthHandler');
const authenticateToken = require('../middleware/authenticateToken');

const router = express.Router();
const PROJECT_F_URL = process.env.PROJECT_F_URL || 'http://localhost:3006';

//=====================
//     SCAN function //
//====================


// Scan Endpoint
router.post('/api/scan', async (req, res) => {
    try {
        const { filePath, metadata } = req.body;

        // Validate inputs
        if (!filePath || !metadata) {
            return res.status(400).json({ success: false, error: 'Invalid request. filePath and metadata are required.' });
        }

        // Call the scanning function
        const scanResult = await scanFile(filePath, metadata);

        if (!scanResult.success) {
            return res.status(400).json({ success: false, error: scanResult.error });
        }

        res.json({ success: true, message: 'File scanned successfully.' });
    } catch (error) {
        console.error('Error in /api/scan:', error.message);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});





// ===============================
// Authentication Routes
// ===============================

/**
 * Sign Up a new user
 */
router.post('/auth/signup', async (req, res) => {
    try {
        const { username, name, email, password, accountType } = req.body;

        if (!username || !email || !password || !accountType) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const query = `
            INSERT INTO user_auth (username, email, password_hash, salt, account_type)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, username, email;
        `;
        const result = await pool.query(query, [username, email, hashedPassword, '', accountType]);

        await logSecurityEvent('USER_SIGNUP', { username, email }, 'info');

        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('Signup error:', error);
        await logSecurityEvent('SIGNUP_FAILURE', { error: error.message }, 'error');
        res.status(500).json({ error: error.message });
    }
});

/**
 * Login user and create JWT token
 */
router.post('/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const user = await pool.query(
            'SELECT * FROM user_auth WHERE email = $1',
            [email]
        );

        if (user.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const validPassword = await bcrypt.compare(password, user.rows[0].password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Create JWT token and track it
        const { token, tokenId } = await jwtAuthHandler.createToken(user.rows[0], req);

        // Update last login timestamp
        await pool.query(
            'UPDATE user_auth SET last_login = CURRENT_TIMESTAMP WHERE id = $1',
            [user.rows[0].id]
        );

        // Notify Project F
        await notifyProjectF({
            message: `Login successful for user ${user.rows[0].username}`,
            level: 'info',
            source: 'Project Z',
            timestamp: new Date().toISOString(),
        });

        res.json({ 
            token,
            tokenId,
            user: {
                id: user.rows[0].id,
                username: user.rows[0].username,
                email: user.rows[0].email
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

/**
 * Logout user and revoke token
 */
router.post('/auth/logout', authenticateToken, async (req, res) => {
    try {
        const tokenId = req.user.tokenId;
        await jwtAuthHandler.revokeToken(tokenId, 'User initiated logout');
        
        res.json({ message: 'Successfully logged out' });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ error: 'Failed to logout' });
    }
});

/**
 * Verify token validity
 */
router.get('/auth/verify', authenticateToken, (req, res) => {
    res.json({ 
        valid: true, 
        user: req.user 
    });
});

// ===============================
// Security Event Routes
// ===============================

/**
 * Fetch recent security events
 */
router.get('/security/events', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 100'
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching security events:', error);
        res.status(500).json({ error: 'Failed to fetch security events' });
    }
});

/**
 * Log a new security event
 */
router.post('/security/events', async (req, res) => {
    const { eventType, details, severity } = req.body;
    if (!eventType || !details) {
        return res.status(400).json({ error: 'Event type and details are required.' });
    }
    try {
        const event = await logSecurityEvent(eventType, details, severity);
        res.status(201).json(event);
    } catch (error) {
        console.error('Error logging security event:', error);
        res.status(500).json({ error: 'Failed to log security event' });
    }
});

// ===============================
// Security Alerts Routes
// ===============================

/**
 * Log a security alert
 */
router.post('/security/alerts', async (req, res) => {
    const { alertType, message, severity, sourceIp } = req.body;
    if (!alertType || !message) {
        return res.status(400).json({ error: 'Alert type and message are required.' });
    }
    try {
        const query = `
            INSERT INTO security_alerts (alert_type, message, severity, source_ip, timestamp)
            VALUES ($1, $2, $3, $4, NOW())
            RETURNING *;
        `;
        const result = await pool.query(query, [alertType, message, severity, sourceIp]);

        if (severity === 'high') {
            await logSecurityEvent('HIGH_SEVERITY_ALERT', message, 'critical');
        }

        await notifyProjectF({
            type: alertType,
            details: message,
            severity,
            sourceIp,
            timestamp: new Date().toISOString(),
        });

        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('Error logging security alert:', error);
        res.status(500).json({ error: 'Failed to log security alert' });
    }
});

// ===============================
// Monitoring Routes
// ===============================

/**
 * Fetch recent authentication logs
 */
router.get('/security/auth-logs', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM auth_logs ORDER BY timestamp DESC LIMIT 100'
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching authentication logs:', error);
        res.status(500).json({ error: 'Failed to fetch authentication logs' });
    }
});

/**
 * Fetch recent suspicious activities
 */
router.get('/security/suspicious-activities', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM suspicious_activities ORDER BY timestamp DESC LIMIT 100'
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching suspicious activities:', error);
        res.status(500).json({ error: 'Failed to fetch suspicious activities' });
    }
});

// ===============================
// Health & Status Routes
// ===============================

/**
 * Basic service status check
 */
router.get('/status', (req, res) => {
    res.json({
        status: 'active',
        version: '1.0',
        message: 'Security Service Z is operational',
        lastCheck: new Date().toISOString(),
    });
});

/**
 * Detailed health check
 */
router.get('/health', async (req, res) => {
    try {
        await pool.query('SELECT NOW()');
        res.json({
            status: 'healthy',
            timestamp: new Date().toISOString(),
            services: {
                database: 'operational',
                notifications: 'active',
            },
        });
    } catch (error) {
        console.error('Health check failed:', error);
        res.status(500).json({
            status: 'unhealthy',
            error: error.message,
        });
    }
});

// ===============================
// Notification Routes
// ===============================

/**
 * Forward notifications to Project F
 */
router.post('/api/notify', async (req, res) => {
    try {
        const { message, level, source, timestamp } = req.body;

        if (!message) {
            return res.status(400).json({ error: 'Message is required.' });
        }

        const axiosResponse = await axios.post(`${PROJECT_F_URL}/api/notify`, {
            message,
            level: level || 'info',
            source: source || 'Project Z',
            timestamp: timestamp || new Date().toISOString(),
        });

        return res.status(200).json({
            status: 'success',
            message: 'Notification handled by Project Z and forwarded to Project F.',
        });
    } catch (error) {
        console.error('Error in /api/notify route:', error.message);
        return res.status(500).json({ error: 'Failed to process notification.' });
    }
});

module.exports = router;