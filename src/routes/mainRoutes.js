const express = require('express');
const pool = require('../db/db'); // Modularized database connection
const { logSecurityEvent, notifyProjectF } = require('../utils/securityUtils'); // Utility functions
const router = express.Router();
require('dotenv').config();

// ------------------- API STATUS ROUTE ------------------- //
router.get('/api/security/status', (req, res) => {
    res.json({
        status: 'active',
        version: '1.0',
        message: 'Security Service Z is operational',
        lastCheck: new Date().toISOString(),
    });
});

// ---------------- SECURITY EVENTS ROUTES ---------------- //

// Fetch security events
router.get('/api/security/events', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 100');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching security events:', error);
        res.status(500).json({ error: 'Failed to fetch security events' });
    }
});

// Log new security event
router.post('/api/security/events', async (req, res) => {
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

// ---------------- SECURITY ALERTS ROUTES ---------------- //

// Log security alerts and notify Project F
router.post('/api/security/alerts', async (req, res) => {
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

        // Notify Project F and escalate high-severity alerts
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

// ---------------- SYSTEM HEALTH CHECK ---------------- //

// Check health of the security service
router.get('/api/security/health', async (req, res) => {
    try {
        // Check database connection
        await pool.query('SELECT NOW()');

        // Add other health checks as needed
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
