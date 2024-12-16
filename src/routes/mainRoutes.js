const express = require('express');
const { Pool } = require('pg');
const axios = require('axios');
const { PROJECT_F_NOTIFICATIONS_URL } = require('../../config/const');
require('dotenv').config();

const router = express.Router();

// ------------------- API STATUS ROUTE ------------------- //
router.get('/api/security/status', (req, res) => {
    res.json({
        status: 'active',
        version: '1.0',
        message: 'Security Service Z is operational',
        lastCheck: new Date().toISOString()
    });
});

// ---------------- DATABASE CONNECTION ---------------- //
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
    ssl: {
        rejectUnauthorized: false // Enable in production with proper cert
    }
});

// ---------------- SECURITY LOGGING & NOTIFICATIONS ---------------- //
async function logSecurityEvent(eventType, details, severity = 'info') {
    try {
        const query = `
            INSERT INTO security_events (event_type, details, severity, timestamp)
            VALUES ($1, $2, $3, NOW())
            RETURNING *;
        `;
        const result = await pool.query(query, [eventType, details, severity]);
        
        // Notify Project F of security event
        await notifyProjectF({
            type: eventType,
            details: details,
            severity: severity,
            timestamp: new Date().toISOString()
        });
        
        return result.rows[0];
    } catch (error) {
        console.error('Error logging security event:', error);
    }
}

async function notifyProjectF(securityEvent) {
    try {
        await axios.post(PROJECT_F_NOTIFICATIONS_URL, {
            source: 'PROJECT-Z',
            ...securityEvent
        });
    } catch (error) {
        console.error('Failed to notify Project F:', error.message);
    }
}

// ---------------- SECURITY EVENTS ROUTES ---------------- //
// Get security events
router.get('/api/security/events', async (req, res) => {
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
router.post('/api/security/alerts', async (req, res) => {
    const { alertType, message, severity, sourceIp } = req.body;

    try {
        const query = `
            INSERT INTO security_alerts (alert_type, message, severity, source_ip, timestamp)
            VALUES ($1, $2, $3, $4, NOW())
            RETURNING *;
        `;
        const result = await pool.query(query, [alertType, message, severity, sourceIp]);
        
        // Log high severity alerts as security events
        if (severity === 'high') {
            await logSecurityEvent('HIGH_SEVERITY_ALERT', message, 'critical');
        }

        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('Error creating security alert:', error);
        res.status(500).json({ error: 'Failed to create security alert' });
    }
});

// ---------------- SYSTEM HEALTH CHECK ---------------- //
router.get('/api/security/health', async (req, res) => {
    try {
        // Check database connection
        await pool.query('SELECT NOW()');
        
        // Add other security-related health checks here
        
        res.json({
            status: 'healthy',
            timestamp: new Date().toISOString(),
            services: {
                database: 'operational',
                notifications: 'active'
            }
        });
    } catch (error) {
        console.error('Health check failed:', error);
        res.status(500).json({
            status: 'unhealthy',
            error: error.message
        });
    }
});

module.exports = router;