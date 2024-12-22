// securityUtils.js


const pool = require('../db/db');
const axios = require('axios');
const { PROJECT_F_NOTIFICATIONS_URL } = require('../../config/const');

async function logSecurityEvent(eventType, details, severity = 'info') {
    try {
        const query = `
            INSERT INTO security_events (event_type, details, severity, timestamp)
            VALUES ($1, $2, $3, NOW())
            RETURNING *;
        `;
        const result = await pool.query(query, [eventType, details, severity]);

        await notifyProjectF({
            type: eventType,
            details,
            severity,
            timestamp: new Date().toISOString(),
        });

        return result.rows[0];
    } catch (error) {
        console.error('Error logging security event:', error);
        throw error;
    }
}

async function notifyProjectF(securityEvent) {
    try {
        await axios.post(PROJECT_F_NOTIFICATIONS_URL, {
            source: 'PROJECT-Z',
            ...securityEvent,
        });
        console.log('Notification sent to Project F');
    } catch (error) {
        console.error('Failed to notify Project F:', error.message);
        throw error;
    }
}

module.exports = { logSecurityEvent, notifyProjectF };
