// const.js

const PROTOCOL = 'http';
const BASE_HOST = 'localhost';

module.exports = {
    // External Service URLs
    PROJECT_A_URL: `${PROTOCOL}://${BASE_HOST}:3001`,
    PROJECT_B_URL: `${PROTOCOL}://${BASE_HOST}:3002`,
    PROJECT_C_URL: `${PROTOCOL}://${BASE_HOST}:3003`,
    PROJECT_D_URL: `${PROTOCOL}://${BASE_HOST}:3004`,
    PROJECT_E_URL: `${PROTOCOL}://${BASE_HOST}:3005`,
    PROJECT_F_URL: `${PROTOCOL}://${BASE_HOST}:3006`,
    PROJECT_X_URL: `${PROTOCOL}://${BASE_HOST}:3010`,

    // Project F Communication (Main Messaging Hub)
    PROJECT_F_ENDPOINTS: {
        MESSAGES: `${PROTOCOL}://${BASE_HOST}:3006/api/messages`,
        NOTIFICATIONS: `${PROTOCOL}://${BASE_HOST}:3006/api/notifications`,
        SECURITY_ALERTS: `${PROTOCOL}://${BASE_HOST}:3006/api/security-alerts`,
    },

    // System Configuration
    SYSTEM: {
        MAX_RETRY_ATTEMPTS: 3,
        RETRY_DELAY_MS: 1000,
        TIMEOUT_MS: 5000,
    },

    // Security Configuration
    SECURITY: {
        JWT_EXPIRY: '1h',
        RATE_LIMIT_WINDOW_MS: 15 * 60 * 1000, // 15 minutes
        MAX_FAILED_ATTEMPTS: 5,
        LOCK_DURATION_MS: 30 * 60 * 1000, // 30 minutes
    },

    // Error Messages
    ERROR_MESSAGES: {
        AUTH_FAILED: 'Authentication failed',
        RATE_LIMIT_EXCEEDED: 'Rate limit exceeded',
        SERVICE_UNAVAILABLE: 'Service temporarily unavailable',
        INVALID_TOKEN: 'Invalid or expired token',
    },

    // Event Types
    EVENT_TYPES: {
        SECURITY_BREACH: 'SECURITY_BREACH',
        AUTH_SUCCESS: 'AUTH_SUCCESS',
        AUTH_FAILURE: 'AUTH_FAILURE',
        ACCOUNT_LOCKED: 'ACCOUNT_LOCKED',
        SUSPICIOUS_ACTIVITY: 'SUSPICIOUS_ACTIVITY',
    },

    // Severity Levels
    SEVERITY_LEVELS: {
        LOW: 'low',
        MEDIUM: 'medium',
        HIGH: 'high',
        CRITICAL: 'critical',
    }
};