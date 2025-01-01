// src/utils/jwtAuthHandler.js

const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const pool = require('../db/db');
const { logAuthActivity, logJWTActivity } = require('./auth-logger');
const { SECURITY } = require('../../config/const');

class JWTAuthHandler {
    async createToken(user, req) {
        try {
            // Generate unique token ID
            const tokenId = uuidv4();
            
            // Create token payload
            const payload = {
                id: user.id,
                username: user.username,
                email: user.email,
                tokenId: tokenId // Include tokenId in JWT for tracking
            };

            // Sign the token
            const token = jwt.sign(payload, process.env.JWT_SECRET, { 
                expiresIn: SECURITY.JWT_EXPIRY 
            });

            // Calculate expiration
            const expiresAt = new Date(Date.now() + (60 * 60 * 1000)); // 1 hour from now

            // Store token in database
            await pool.query(
                `INSERT INTO jwt_tokens 
                (token_id, user_id, expires_at, ip_address, user_agent)
                VALUES ($1, $2, $3, $4, $5)`,
                [
                    tokenId,
                    user.id,
                    expiresAt,
                    req.ip,
                    req.headers['user-agent']
                ]
            );

            // Log token creation
            await logAuthActivity('TOKEN_CREATED', {
                userId: user.id,
                username: user.username,
                jwtId: tokenId,
                ipAddress: req.ip,
                userAgent: req.headers['user-agent']
            });

            // Log JWT activity
            await logJWTActivity(tokenId, 'ISSUED', {
                userId: user.id,
                username: user.username,
                ipAddress: req.ip
            });

            return { token, tokenId };
        } catch (error) {
            console.error('Error creating token:', error);
            throw error;
        }
    }

    async validateToken(token, req) {
        try {
            // Verify the JWT signature and expiration
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            
            // Check if token exists and is not revoked
            const result = await pool.query(
                `SELECT * FROM jwt_tokens 
                WHERE token_id = $1 AND NOT is_revoked 
                AND expires_at > CURRENT_TIMESTAMP`,
                [decoded.tokenId]
            );

            if (result.rows.length === 0) {
                throw new Error('Token not found or revoked');
            }

            // Update last used timestamp
            await pool.query(
                `UPDATE jwt_tokens 
                SET last_used_at = CURRENT_TIMESTAMP 
                WHERE token_id = $1`,
                [decoded.tokenId]
            );

            // Log token usage
            await logAuthActivity('TOKEN_USED', {
                userId: decoded.id,
                username: decoded.username,
                jwtId: decoded.tokenId,
                ipAddress: req.ip,
                endpoint: req.originalUrl
            });

            // Log JWT activity
            await logJWTActivity(decoded.tokenId, 'USED', {
                userId: decoded.id,
                username: decoded.username,
                ipAddress: req.ip,
                endpoint: req.originalUrl
            });

            return decoded;
        } catch (error) {
            // Log validation failure
            await logAuthActivity('TOKEN_VALIDATION_FAILED', {
                ipAddress: req.ip,
                error: error.message,
                token: token.substring(0, 10) + '...' // Log only beginning of token
            }, 'warning');

            throw error;
        }
    }

    async revokeToken(tokenId, reason = 'User logout') {
        try {
            // Get token info before revoking
            const tokenInfo = await pool.query(
                'SELECT user_id FROM jwt_tokens WHERE token_id = $1',
                [tokenId]
            );

            if (tokenInfo.rows.length === 0) {
                throw new Error('Token not found');
            }

            // Mark token as revoked
            await pool.query(
                `UPDATE jwt_tokens 
                SET is_revoked = true,
                    revoked_at = CURRENT_TIMESTAMP,
                    revocation_reason = $2
                WHERE token_id = $1`,
                [tokenId, reason]
            );

            // Get user info for logging
            const userInfo = await pool.query(
                'SELECT username FROM user_auth WHERE id = $1',
                [tokenInfo.rows[0].user_id]
            );

            // Log token revocation
            await logAuthActivity('TOKEN_REVOKED', {
                userId: tokenInfo.rows[0].user_id,
                username: userInfo.rows[0]?.username,
                jwtId: tokenId,
                reason
            });

            // Log JWT activity
            await logJWTActivity(tokenId, 'REVOKED', {
                userId: tokenInfo.rows[0].user_id,
                username: userInfo.rows[0]?.username,
                reason
            });

            return true;
        } catch (error) {
            console.error('Error revoking token:', error);
            throw error;
        }
    }

    // Helper method to check if a token is still valid
    async isTokenValid(tokenId) {
        try {
            const result = await pool.query(
                `SELECT * FROM jwt_tokens 
                WHERE token_id = $1 
                AND NOT is_revoked 
                AND expires_at > CURRENT_TIMESTAMP`,
                [tokenId]
            );
            return result.rows.length > 0;
        } catch (error) {
            console.error('Error checking token validity:', error);
            return false;
        }
    }
}

module.exports = new JWTAuthHandler();