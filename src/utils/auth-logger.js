// auth-logger.js

const pool = require('../db/db');
const { notifyProjectF } = require('./securityUtils');

/**
 * Log authentication activity with detailed JWT information
 */
async function logAuthActivity(type, details, severity = 'info') {
    try {
        // Insert into auth_logs table
        const query = `
            INSERT INTO auth_logs 
            (activity_type, user_id, username, jwt_id, ip_address, details, severity, timestamp)
            VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
            RETURNING *
        `;
        
        const values = [
            type,
            details.userId || null,
            details.username || 'anonymous',
            details.jwtId || null,
            details.ipAddress || null,
            JSON.stringify(details),
            severity
        ];

        const result = await pool.query(query, values);
        
        // Notify Project F about the auth activity
        await notifyProjectF({
            message: `${type}: ${details.username || 'anonymous'}`,
            level: severity,
            source: 'Project Z',
            timestamp: new Date().toISOString(),
            details: {
                activityType: type,
                username: details.username,
                ipAddress: details.ipAddress
            }
        });

        return result.rows[0];
    } catch (error) {
        console.error('Error logging auth activity:', error);
        throw error;
    }
}

/**
 * Track JWT token lifecycle events
 */
async function logJWTActivity(tokenId, action, details) {
    try {
        // Insert into auth_logs table instead of jwt_activity
        const query = `
            INSERT INTO auth_logs 
            (jwt_id, activity_type, user_id, username, ip_address, details, severity)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        `;
        
        await pool.query(query, [
            tokenId,
            `JWT_${action}`,
            details.userId,
            details.username,
            details.ipAddress,
            JSON.stringify(details),
            'info'
        ]);

        // Notify Project F about JWT activity
        await notifyProjectF({
            message: `JWT ${action}: User ${details.username}`,
            level: 'info',
            source: 'Project Z',
            timestamp: new Date().toISOString(),
            details: {
                action,
                username: details.username,
                tokenId
            }
        });
    } catch (error) {
        console.error('Error logging JWT activity:', error);
        throw error;
    }
}

module.exports = {
    logAuthActivity,
    logJWTActivity
};