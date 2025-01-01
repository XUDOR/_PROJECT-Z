//authenticateToken.js

// src/middleware/authenticateToken.js in Project Z

const jwtAuthHandler = require('../utils/jwtAuthHandler');

async function authenticateToken(req, res, next) {
    try {
        const authHeader = req.headers.authorization;
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        try {
            const user = await jwtAuthHandler.validateToken(token, req);
            req.user = user;
            next();
        } catch (error) {
            // Log failed validation
            await pool.query(
                `INSERT INTO auth_logs 
                (ip_address, auth_action, status, details)
                VALUES ($1, $2, $3, $4)`,
                [
                    req.ip,
                    'TOKEN_VALIDATION_FAILED',
                    'FAILURE',
                    JSON.stringify({ error: error.message })
                ]
            );
            
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
    } catch (error) {
        console.error('Auth middleware error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}

module.exports = authenticateToken;