const express = require('express');
const bcrypt = require('bcrypt');
const pool = require('../db/db');
const { logSecurityEvent, notifyProjectF } = require('../utils/securityUtils');
const router = express.Router();
require('dotenv').config();

// Auth Routes
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


router.post('/auth/login', async (req, res) => {
   try {
       const { email, password } = req.body;
       const user = await pool.query('SELECT * FROM user_auth WHERE email = $1', [email]);
       
       if (user.rows.length === 0) {
           return res.status(401).json({ error: 'Invalid credentials' });
       }

       const validPassword = await bcrypt.compare(password, user.rows[0].password_hash);
       if (!validPassword) {
           return res.status(401).json({ error: 'Invalid credentials' });
       }

       const token = jwt.sign({ id: user.rows[0].id }, process.env.JWT_SECRET, { expiresIn: '1h' });
       res.json({ token, user: user.rows[0] });
       
   } catch (error) {
       console.error('Login error:', error);
       res.status(500).json({ error: error.message });
   }
});

// Status Route
router.get('/status', (req, res) => {
   res.json({
       status: 'active',
       version: '1.0',
       message: 'Security Service Z is operational',
       lastCheck: new Date().toISOString(),
   });
});

// Security Events Routes
router.get('/security/events', async (req, res) => {
   try {
       const result = await pool.query('SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 100');
       res.json(result.rows);
   } catch (error) {
       console.error('Error fetching security events:', error);
       res.status(500).json({ error: 'Failed to fetch security events' });
   }
});

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

// Security Alerts Route
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

// Health Check Route
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

module.exports = router;