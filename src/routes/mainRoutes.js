require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('../db/db'); // <-- Adjust path if needed
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

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert into user_auth table
        const query = `
            INSERT INTO user_auth (username, email, password_hash, salt, account_type)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, username, email;
        `;
        const result = await pool.query(query, [username, email, hashedPassword, '', accountType]);

        // Log security event
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

        // Fetch user by email
        const user = await pool.query(
            'SELECT * FROM user_auth WHERE email = $1',
            [email]
        );

        // If user not found
        if (user.rows.length === 0) {
            console.log('No user found for email:', email);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Compare provided password with stored hash
        const validPassword = await bcrypt.compare(password, user.rows[0].password_hash);
        if (!validPassword) {
            console.log('Invalid password for user:', email);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Create JWT token
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

        // Notify Project F of successful login
        await notifyProjectF({
            message: `Login successful for user ${user.rows[0].username}`,
            level: 'info',
            source: 'Project Z',
            timestamp: new Date().toISOString(),
        });

        // Return token and user data
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

        // If severity is high, log a critical event
        if (severity === 'high') {
            await logSecurityEvent('HIGH_SEVERITY_ALERT', message, 'critical');
        }

        // Notify Project F
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
        // Simple DB check
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
// (Updated endpoints to match main.js calls)
// ===============================

/**
 * Fetch recent authentication logs (limit 100).
 * NOTE: You must have a table named 'auth_logs' or adjust this query.
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
 * NOTE: You must have a table named 'suspicious_activities' or adjust this query.
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

module.exports = router;
