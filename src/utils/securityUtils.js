//securityUtils.js

const pool = require('../db/db');
const axios = require('axios');
const { PROJECT_F_NOTIFICATIONS_URL } = require('../../config/const');

async function notifyProjectF(message) {
    try {
        // Don't proceed if URL is undefined
        if (!PROJECT_F_NOTIFICATIONS_URL) {
            console.log('PROJECT_F_NOTIFICATIONS_URL is not defined. Skipping notification.');
            return;
        }

        await axios.post(PROJECT_F_NOTIFICATIONS_URL, {
            source: 'PROJECT-Z',
            message: message,
            timestamp: new Date().toISOString()
        });
        console.log('Successfully notified Project F:', message);
    } catch (error) {
        // Log error but don't crash
        console.error('Failed to notify Project F:', error.message);
    }
}

async function logSecurityEvent(eventType, details, severity = 'info') {
    try {
        const query = `
            INSERT INTO security_events (event_type, details, severity, timestamp)
            VALUES ($1, $2, $3, NOW())
            RETURNING *;
        `;
        const result = await pool.query(query, [eventType, JSON.stringify(details), severity]);

        // Don't let notification failure crash the process
        try {
            await notifyProjectF({
                type: eventType,
                details,
                severity,
                timestamp: new Date().toISOString(),
            });
        } catch (notifyError) {
            console.error('Notification error:', notifyError.message);
        }

        return result.rows[0];
    } catch (error) {
        console.error('Error logging security event:', error);
        // Don't throw, just return null
        return null;
    }
}

module.exports = { logSecurityEvent, notifyProjectF };