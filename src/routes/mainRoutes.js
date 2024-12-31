require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const pool = require('../db/db');
const { logSecurityEvent, notifyProjectF } = require('../utils/securityUtils');

const router = express.Router();

// ===============================
// AUTH ROUTES
// ===============================

/**
 * Sign Up a new user.
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
 * Log in an existing user.
 */
router.post('/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        console.log('Login attempt for email:', email);

        const user = await pool.query(
            'SELECT * FROM user_auth WHERE email = $1',
            [email]
        );

        if (user.rows.length === 0) {
            console.log('No user found for email:', email);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const validPassword = await bcrypt.compare(password, user.rows[0].password_hash);
        if (!validPassword) {
            console.log('Invalid password for user:', email);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            {
                id: user.rows[0].id,
                username: user.rows[0].username,
                email: user.rows[0].email,
            },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        console.log('Generated JWT:', token);

        await notifyProjectF({
            message: `Login successful for user ${user.rows[0].username}`,
            level: 'info',
            source: 'Project Z',
            timestamp: new Date().toISOString(),
        });

        res.json({ token, user: user.rows[0] });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: error.message });
    }
});

/**
 * Basic status route to check if the Security Service is operational.
 */
router.get('/status', (req, res) => {
    res.json({
        status: 'active',
        version: '1.0',
        message: 'Security Service Z is operational',
        lastCheck: new Date().toISOString(),
    });
});

// ===============================
// SECURITY EVENTS ROUTES
// ===============================

/**
 * Fetch recent security events (limit 100).
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
 * Log a new security event.
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
// SECURITY ALERTS ROUTE
// ===============================

/**
 * Log a security alert.
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
// HEALTH CHECK ROUTE
// ===============================

/**
 * Health endpoint to confirm DB and notifications are operational.
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
// AUTH LOGS & SUSPICIOUS ACTIVITIES
// ===============================

/**
 * Fetch recent authentication logs (limit 100).
 * NOTE: Table must exist in the DB with name 'auth_logs'.
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
 * Fetch recent suspicious activities (limit 100).
 * NOTE: Table must exist in the DB with name 'suspicious_activities'.
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
// NEW: /api/notify ROUTE
// FORWARDING TO PROJECT F (IF DESIRED)
// ===============================
const PROJECT_F_URL = process.env.PROJECT_F_URL || 'http://localhost:3006';

router.post('/api/notify', async (req, res) => {
    try {
        const { message, level, source, timestamp } = req.body;

        if (!message) {
            return res.status(400).json({ error: 'Message is required.' });
        }

        // Forward to Project F
        const axiosResponse = await axios.post(`${PROJECT_F_URL}/api/notify`, {
            message,
            level: level || 'info',
            source: source || 'Project Z',
            timestamp: timestamp || new Date().toISOString(),
        });

        console.log('Forwarded notification to Project F:', axiosResponse.data);

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
