// main.js - Complete Security Monitoring Implementation for Project Z

document.addEventListener('DOMContentLoaded', function () {
    // ===============================
    // Constants and Configurations
    // ===============================
    const REFRESH_INTERVAL = 30000; // 30 seconds
    const MAX_RETRY_ATTEMPTS = 3;
    const RETRY_DELAY = 2000; // 2 seconds

    // Severity Levels
    const SEVERITY_LEVELS = {
        LOW: 'low',
        MEDIUM: 'medium',
        HIGH: 'high',
        CRITICAL: 'critical'
    };

    // Event Types
    const EVENT_TYPES = {
        AUTH_SUCCESS: 'AUTH_SUCCESS',
        AUTH_FAILURE: 'AUTH_FAILURE',
        SUSPICIOUS_ACTIVITY: 'SUSPICIOUS_ACTIVITY',
        SECURITY_ALERT: 'SECURITY_ALERT',
        SYSTEM_ERROR: 'SYSTEM_ERROR'
    };

    // ===============================
    // DOM Elements
    // ===============================
    const elements = {
        // Loading / Status Indicators
        loadingIndicator: document.querySelector('.loading'),
        sslIndicator: document.getElementById('ssl-indicator'),
        apiHealthIndicator: document.getElementById('api-health-indicator'),

        // Security Events
        securityEventsLog: document.getElementById('security-events-log'),
        refreshSecurityEvents: document.getElementById('refresh-security-events'),
        eventFilter: document.getElementById('event-filter'),
        eventCount: document.getElementById('event-count'),
        highPriorityCount: document.getElementById('high-priority-count'),

        // Authentication Logs
        authLogsLog: document.getElementById('auth-logs-log'),
        refreshAuthLogs: document.getElementById('refresh-auth-logs'),
        authFilter: document.getElementById('auth-filter'),
        authSuccessCount: document.getElementById('auth-success-count'),
        authFailureCount: document.getElementById('auth-failure-count'),

        // Suspicious Activities
        suspiciousActivitiesLog: document.getElementById('suspicious-activities-log'),
        refreshSuspiciousActivities: document.getElementById('refresh-suspicious-activities'),
        threatFilter: document.getElementById('threat-filter'),
        currentThreatLevel: document.getElementById('current-threat-level'),
        activeThreatsCount: document.getElementById('active-threats-count'),

        // System Status
        serviceStatusList: document.getElementById('service-status-list'),
        refreshSystemStatus: document.getElementById('refresh-system-status'),
        servicesOnlineCount: document.getElementById('services-online-count'),

        // JWT Token elements
        tokenActivityLog: document.getElementById('token-activity-log'),
        refreshTokenActivity: document.getElementById('refresh-token-activity'),
        tokenFilter: document.getElementById('token-filter'),
        activeTokensCount: document.getElementById('active-tokens-count'),
        expiredTokensCount: document.getElementById('expired-tokens-count'),


        // Navigation
        navLinks: document.querySelectorAll('.nav-menu a'),

        // Footer Information
        lastUpdated: document.getElementById('last-updated'),
        activeConnections: document.getElementById('active-connections')
    };

    // ===============================
    // Utility Functions
    // ===============================

    /**
     * Displays the loading overlay.
     */
    function showLoading() {
        if (elements.loadingIndicator) {
            elements.loadingIndicator.style.display = 'block';
        }
    }

    /**
     * Hides the loading overlay.
     */
    function hideLoading() {
        if (elements.loadingIndicator) {
            elements.loadingIndicator.style.display = 'none';
        }
    }

    /**
     * Fetch with automatic retry attempts.
     * @param {string} url - The endpoint URL.
     * @param {object} options - Fetch options.
     * @param {number} attempts - Max retry attempts.
     * @returns {Promise<any>}
     */
    async function fetchWithRetry(url, options = {}, attempts = MAX_RETRY_ATTEMPTS) {
        for (let i = 0; i < attempts; i++) {
            try {
                const response = await fetch(url, options);
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                return await response.json();
            } catch (error) {
                // If it's the last attempt, rethrow
                if (i === attempts - 1) throw error;
                // Otherwise, wait RETRY_DELAY then retry
                await new Promise(resolve => setTimeout(resolve, RETRY_DELAY));
            }
        }
    }

    /**
     * Formats a timestamp to a human-readable string.
     * @param {string|number|Date} timestamp
     * @returns {string}
     */
    function formatTimestamp(timestamp) {
        return new Date(timestamp).toLocaleString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    }

    /**
     * Updates the "Last Updated" footer text to current time.
     */
    function updateLastChecked() {
        if (elements.lastUpdated) {
            elements.lastUpdated.textContent = `Last Updated: ${formatTimestamp(new Date())}`;
        }
    }

    /**
     * Checks the SSL status of the current page (simple version).
     */
    function checkSSLStatus() {
        const isSecure = window.location.protocol === 'https:';
        if (!elements.sslIndicator) return;

        if (isSecure) {
            elements.sslIndicator.textContent = 'Secure';
            elements.sslIndicator.classList.remove('not-secure');
            elements.sslIndicator.classList.add('secure');
        } else {
            elements.sslIndicator.textContent = 'Not Secure';
            elements.sslIndicator.classList.remove('secure');
            elements.sslIndicator.classList.add('not-secure');
        }
    }

    // ===============================
    // Security Events Handling
    // ===============================

    /**
     * Fetches and displays security events.
     * @param {string} filter - Filter by severity level (e.g. "high", "low").
     */
    async function refreshSecurityEvents(filter = 'all') {
        try {
            showLoading();
            const events = await fetchWithRetry('/api/security/events');

            let filteredEvents = events;
            if (filter !== 'all') {
                filteredEvents = events.filter(event => event.severity === filter);
            }

            updateSecurityEventsUI(filteredEvents);
            updateEventStatistics(events);

            // Update button severity based on highest severity event
            const highestSeverity = getHighestSeverity(events);
            elements.refreshSecurityEvents.setAttribute('data-severity', highestSeverity);
        } catch (error) {
            console.error('Error refreshing security events:', error);
            if (elements.securityEventsLog) {
                elements.securityEventsLog.innerHTML = 'Failed to load security events.';
            }
            await notifyError('Security Events Refresh Failed', error);
        } finally {
            hideLoading();
        }
    }

    /**
     * Updates the UI with the given list of security events.
     * @param {Array} events
     */
    function updateSecurityEventsUI(events) {
        if (!elements.securityEventsLog) return;
        elements.securityEventsLog.innerHTML = '';

        events.forEach(event => {
            const eventDiv = document.createElement('div');
            eventDiv.classList.add('bundle-row', `severity-${event.severity || 'low'}`);

            eventDiv.innerHTML = `
                <div class="bundle-content">
                    <div class="event-header">
                        <span class="event-type">${event.event_type || 'UNKNOWN_EVENT'}</span>
                        <span class="severity-badge ${event.severity || 'low'}">
                            ${event.severity || 'low'}
                        </span>
                    </div>
                    <p class="event-message">${event.message || 'No message provided.'}</p>
                    <div class="event-details">
                        ${event.details
                    ? `<pre>${JSON.stringify(event.details, null, 2)}</pre>`
                    : ''
                }
                    </div>
                    <div class="bundle-timestamp">
                        <span class="timestamp-label">Time:</span>
                        <span class="timestamp-value">${formatTimestamp(event.timestamp)}</span>
                    </div>
                </div>
            `;
            elements.securityEventsLog.appendChild(eventDiv);
        });
    }

    // ===============================
    // Authentication Log Handling
    // ===============================

    /**
     * Fetches and displays authentication logs.
     * @param {string} filter - Filter by status (e.g. "success", "failure").
     */
    async function refreshAuthLogs(filter = 'all') {
        try {
            showLoading();
            const logs = await fetchWithRetry('/api/security/auth-logs');

            let filteredLogs = logs;
            if (filter !== 'all') {
                filteredLogs = logs.filter(log => log.status === filter);
            }

            updateAuthLogsUI(filteredLogs);
            updateAuthStatistics(logs);

            // Update button severity based on failed attempts
            const failedCount = logs.filter(log => log.status === 'failure').length;
            const severity = getAuthSeverityLevel(failedCount);
            elements.refreshAuthLogs.setAttribute('data-severity', severity);
        } catch (error) {
            console.error('Error refreshing auth logs:', error);
            if (elements.authLogsLog) {
                elements.authLogsLog.innerHTML = 'Failed to load authentication logs.';
            }
            await notifyError('Auth Logs Refresh Failed', error);
        } finally {
            hideLoading();
        }
    }

    /**
     * Updates the UI with the given list of authentication logs.
     * @param {Array} logs
     */
    function updateAuthLogsUI(logs) {
        if (!elements.authLogsLog) return;
        elements.authLogsLog.innerHTML = '';

        logs.forEach(log => {
            const logDiv = document.createElement('div');
            logDiv.classList.add('bundle-row', `status-${log.status || 'unknown'}`);

            logDiv.innerHTML = `
                <div class="bundle-content">
                    <div class="auth-header">
                        <span class="auth-user">${log.username || 'Unknown User'}</span>
                        <span class="status-badge ${log.status}">
                            ${log.status || 'unknown'}
                        </span>
                    </div>
                    <p class="auth-details">
                        <strong>IP:</strong> ${log.ip_address || 'N/A'} |
                        <strong>Method:</strong> ${log.auth_method || 'Standard'}
                    </p>
                    ${log.details
                    ? `<pre class="auth-additional-details">${JSON.stringify(log.details, null, 2)}</pre>`
                    : ''
                }
                    <div class="bundle-timestamp">
                        <span class="timestamp-label">Time:</span>
                        <span class="timestamp-value">${formatTimestamp(log.timestamp)}</span>
                    </div>
                </div>
            `;
            elements.authLogsLog.appendChild(logDiv);
        });
    }

    // ===============================
    // Suspicious Activity Monitoring
    // ===============================

    /**
     * Fetches and displays suspicious activities.
     * @param {string} filter - Filter by threat level (e.g. "critical", "warning").
     */
    async function refreshSuspiciousActivities(filter = 'all') {
        try {
            showLoading();
            const activities = await fetchWithRetry('/api/security/suspicious-activities');

            let filteredActivities = activities;
            if (filter !== 'all') {
                filteredActivities = activities.filter(
                    activity => activity.threat_level === filter
                );
            }

            updateSuspiciousActivitiesUI(filteredActivities);
            updateThreatStatistics(activities);

            // Update button severity based on highest threat level
            const highestThreat = getHighestThreatLevel(activities);
            elements.refreshSuspiciousActivities.setAttribute('data-severity', highestThreat);
        } catch (error) {
            console.error('Error refreshing suspicious activities:', error);
            if (elements.suspiciousActivitiesLog) {
                elements.suspiciousActivitiesLog.innerHTML =
                    'Failed to load suspicious activities.';
            }
            await notifyError('Suspicious Activities Refresh Failed', error);
        } finally {
            hideLoading();
        }
    }

    /**
     * Updates the UI with the given list of suspicious activities.
     * @param {Array} activities
     */
    function updateSuspiciousActivitiesUI(activities) {
        if (!elements.suspiciousActivitiesLog) return;
        elements.suspiciousActivitiesLog.innerHTML = '';

        activities.forEach(activity => {
            const activityDiv = document.createElement('div');
            activityDiv.classList.add('bundle-row', `threat-${activity.threat_level || 'low'}`);

            activityDiv.innerHTML = `
                <div class="bundle-content">
                    <div class="activity-header">
                        <span class="activity-type">${activity.activity_type || 'Unknown'}</span>
                        <span class="threat-badge ${activity.threat_level || 'low'}">
                            Threat Level: ${activity.threat_level || 'low'}
                        </span>
                    </div>
                    <p class="activity-description">${activity.description || 'No description.'}</p>
                    <div class="activity-details">
                        <p><strong>Source IP:</strong> ${activity.source_ip || 'N/A'}</p>
                        <p><strong>Target:</strong> ${activity.target || 'N/A'}</p>
                        ${activity.details
                    ? `<pre>${JSON.stringify(activity.details, null, 2)}</pre>`
                    : ''
                }
                    </div>
                    <div class="bundle-timestamp">
                        <span class="timestamp-label">Detected:</span>
                        <span class="timestamp-value">${formatTimestamp(activity.timestamp)}</span>
                    </div>
                </div>
            `;
            elements.suspiciousActivitiesLog.appendChild(activityDiv);
        });
    }

    // ===============================
    // System Status Monitoring
    // ===============================

    /**
     * Checks overall system status, including API health and SSL status.
     * @returns {Promise<boolean>} - Returns true if healthy, false otherwise.
     */
    async function checkSystemStatus() {
        try {
            const healthData = await fetchWithRetry('/api/health');

            // Update API health indicator
            if (healthData.status) {
                elements.apiHealthIndicator.textContent = healthData.status;
                elements.apiHealthIndicator.className = `status-${healthData.status.toLowerCase()}`;
            }

            // Update service status list
            if (healthData.services) {
                updateServiceStatusList(healthData.services);
            }

            // Update SSL status
            checkSSLStatus();

            // Update last checked timestamp
            updateLastChecked();

            return healthData.status === 'healthy';
        } catch (error) {
            console.error('Error checking system status:', error);
            elements.apiHealthIndicator.textContent = 'Error';
            elements.apiHealthIndicator.className = 'status-error';
            await notifyError('System Status Check Failed', error);
            return false;
        }
    }

    /**
     * Updates the service status list UI.
     * @param {object} services
     */
    function updateServiceStatusList(services) {
        if (!elements.serviceStatusList) return;
        elements.serviceStatusList.innerHTML = '';

        const serviceNames = Object.keys(services);
        let onlineCount = 0;

        serviceNames.forEach(name => {
            const status = services[name];
            if (status === 'operational') {
                onlineCount++;
            }

            const serviceDiv = document.createElement('div');
            serviceDiv.classList.add('service-item', `status-${status.toLowerCase()}`);
            serviceDiv.innerHTML = `
                <span class="service-name">${name}</span>
                <span class="service-status">${status}</span>
            `;
            elements.serviceStatusList.appendChild(serviceDiv);
        });

        // Update "Services Online" count
        elements.servicesOnlineCount.textContent = `${onlineCount}/${serviceNames.length}`;
    }

    // ===============================
    // JWT Token Activity Monitoring
    // ===============================

    /**
     * Fetches and displays JWT token activity.
     * @param {string} filter - Filter by status (e.g. "active", "expired", "revoked").
     */
    async function refreshTokenActivity(filter = 'all') {
        try {
            showLoading();
            const tokens = await fetchWithRetry('/api/security/token-activity');

            let filteredTokens = tokens;
            if (filter !== 'all') {
                filteredTokens = tokens.filter(token => {
                    switch (filter) {
                        case 'active':
                            return !token.is_revoked && new Date(token.expires_at) > new Date();
                        case 'expired':
                            return !token.is_revoked && new Date(token.expires_at) <= new Date();
                        case 'revoked':
                            return token.is_revoked;
                        default:
                            return true;
                    }
                });
            }

            updateTokenActivityUI(filteredTokens);
            updateTokenStatistics(tokens);

        } catch (error) {
            console.error('Error refreshing token activity:', error);
            if (elements.tokenActivityLog) {
                elements.tokenActivityLog.innerHTML = 'Failed to load token activity.';
            }
            await notifyError('Token Activity Refresh Failed', error);
        } finally {
            hideLoading();
        }
    }

    /**
     * Updates the UI with token activity data.
     * @param {Array} tokens
     */
    function updateTokenActivityUI(tokens) {
        if (!elements.tokenActivityLog) return;
        elements.tokenActivityLog.innerHTML = '';

        tokens.forEach(token => {
            const tokenDiv = document.createElement('div');
            const status = token.is_revoked ? 'revoked' :
                (new Date(token.expires_at) > new Date() ? 'active' : 'expired');

            tokenDiv.classList.add('bundle-row', `token-${status}`);

            tokenDiv.innerHTML = `
            <div class="bundle-content">
                <div class="token-header">
                    <span class="token-id">Token: ${token.token_id.substr(0, 8)}...</span>
                    <span class="status-badge ${status}">${status.toUpperCase()}</span>
                </div>
                <div class="token-details">
                    <p><strong>User:</strong> ${token.username || 'Unknown'}</p>
                    <p><strong>Issued:</strong> ${formatTimestamp(token.issued_at)}</p>
                    <p><strong>Expires:</strong> ${formatTimestamp(token.expires_at)}</p>
                    ${token.last_used_at ? `<p><strong>Last Used:</strong> ${formatTimestamp(token.last_used_at)}</p>` : ''}
                    ${token.is_revoked ? `<p><strong>Revoked:</strong> ${formatTimestamp(token.revoked_at)} (${token.revocation_reason})</p>` : ''}
                    <p><strong>IP:</strong> ${token.ip_address || 'N/A'}</p>
                </div>
            </div>
        `;

            elements.tokenActivityLog.appendChild(tokenDiv);
        });
    }

    /**
     * Updates token statistics.
     * @param {Array} tokens
     */
    function updateTokenStatistics(tokens) {
        if (!elements.activeTokensCount || !elements.expiredTokensCount) return;

        const now = new Date();
        const active = tokens.filter(t => !t.is_revoked && new Date(t.expires_at) > now).length;
        const expired = tokens.filter(t => !t.is_revoked && new Date(t.expires_at) <= now).length;

        elements.activeTokensCount.textContent = active;
        elements.expiredTokensCount.textContent = expired;
    }


//=================== FILE SCAN UI

/**
 * Add a new scan log entry to the scan activity section.
 * @param {string} message - The log message to display.
 * @param {string} status - The status of the scan (success or failure).
 */
function addScanLog(message, status) {
    const scanLog = document.getElementById('scan-activity-log');
    const logEntry = document.createElement('div');
    logEntry.textContent = `${new Date().toLocaleString()}: ${message}`;
    logEntry.classList.add(status === 'success' ? 'log-success' : 'log-failure');

    scanLog.appendChild(logEntry);
    scanLog.scrollTop = scanLog.scrollHeight; // Scroll to the latest log
}

/**
 * Fetch scan activity data from the server and update the UI.
 */
async function fetchScanActivity() {
    try {
        const response = await fetch('/api/activity-logs');
        const data = await response.json();

        const scanLog = document.getElementById('scan-activity-log');
        const successCount = document.getElementById('successful-scans-count');
        const failureCount = document.getElementById('failed-scans-count');

        scanLog.innerHTML = ''; // Clear existing logs
        let success = 0;
        let failure = 0;

        data.logs.forEach((log) => {
            addScanLog(log.message, log.status);
            if (log.status === 'success') success++;
            else failure++;
        });

        successCount.textContent = success;
        failureCount.textContent = failure;
    } catch (error) {
        console.error('Error fetching scan activity:', error);
    }
}

// Event listener for refreshing scan activity
document.getElementById('refresh-scan-activity').addEventListener('click', fetchScanActivity);



router.get('/api/scans/logs', async (req, res) => {
    try {
        const logs = await pool.query('SELECT * FROM scan_logs ORDER BY timestamp DESC LIMIT 50');
        res.status(200).json({ success: true, logs: logs.rows });
    } catch (error) {
        console.error('Error fetching scan logs:', error.message);
        res.status(500).json({ success: false, error: 'Failed to fetch scan logs' });
    }
});


    // ===============================
    // Statistics Updates
    // ===============================

    /**
     * Updates event statistics (total count, high priority count).
     * @param {Array} events
     */
    function updateEventStatistics(events) {
        const totalCount = events.length;
        const highCount = events.filter(
            event => event.severity === 'high' || event.severity === 'critical'
        ).length;

        if (elements.eventCount) {
            elements.eventCount.textContent = totalCount;
        }
        if (elements.highPriorityCount) {
            elements.highPriorityCount.textContent = highCount;
        }
    }

    /**
     * Updates authentication statistics (success vs. failure count).
     * @param {Array} logs
     */
    function updateAuthStatistics(logs) {
        const successCount = logs.filter(log => log.status === 'success').length;
        const failureCount = logs.filter(log => log.status === 'failure').length;

        if (elements.authSuccessCount) {
            elements.authSuccessCount.textContent = successCount;
        }
        if (elements.authFailureCount) {
            elements.authFailureCount.textContent = failureCount;
        }
    }

    /**
     * Updates suspicious activity statistics (active threats, overall threat level).
     * @param {Array} activities
     */
    function updateThreatStatistics(activities) {
        const activeThreats = activities.filter(
            activity => activity.status === 'active' || activity.status === 'investigating'
        ).length;

        if (elements.activeThreatsCount) {
            elements.activeThreatsCount.textContent = activeThreats;
        }
        if (elements.currentThreatLevel) {
            elements.currentThreatLevel.textContent = getOverallThreatLevel(activities);
        }
    }

    // ===============================
    // Severity & Threat Level Helpers
    // ===============================

    /**
     * Finds the highest severity in a list of events.
     * @param {Array} events
     * @returns {string}
     */
    function getHighestSeverity(events) {
        if (!events || events.length === 0) return SEVERITY_LEVELS.LOW;

        const severityOrder = {
            low: 1,
            medium: 2,
            high: 3,
            critical: 4
        };

        return events.reduce((highest, event) => {
            const current = event.severity || 'low';
            return severityOrder[current] > severityOrder[highest] ? current : highest;
        }, 'low');
    }

    /**
     * Returns an auth severity level based on number of failed attempts.
     * @param {number} failedCount
     * @returns {string}
     */
    function getAuthSeverityLevel(failedCount) {
        if (failedCount >= 10) return SEVERITY_LEVELS.CRITICAL;
        if (failedCount >= 5) return SEVERITY_LEVELS.HIGH;
        if (failedCount >= 3) return SEVERITY_LEVELS.MEDIUM;
        return SEVERITY_LEVELS.LOW;
    }

    /**
     * Finds the highest threat level in suspicious activities.
     * @param {Array} activities
     * @returns {string}
     */
    function getHighestThreatLevel(activities) {
        if (!activities || activities.length === 0) return SEVERITY_LEVELS.LOW;

        const threatOrder = {
            low: 1,
            moderate: 2,
            high: 3,
            critical: 4
        };

        return activities.reduce((highest, activity) => {
            const current = activity.threat_level || 'low';
            return threatOrder[current] > threatOrder[highest] ? current : highest;
        }, 'low');
    }

    /**
     * Returns an overall threat level (Normal, Moderate, Elevated, Critical).
     * @param {Array} activities
     * @returns {string}
     */
    function getOverallThreatLevel(activities) {
        // Filter only active suspicious activities
        const activeThreats = activities.filter(a => a.status === 'active');
        if (activeThreats.length === 0) {
            return 'Normal';
        }

        const highestThreat = getHighestThreatLevel(activeThreats);
        if (highestThreat === 'critical') return 'Critical';
        if (highestThreat === 'high') return 'Elevated';
        return 'Moderate';
    }

    // ===============================
    // Project F Notification
    // ===============================

    /**
     * Sends a notification message to Project F.
     * @param {string} message
     * @param {string} level
     */
    async function notifyProjectF(message, level = 'info') {
        try {
            await fetch('/api/notify', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    message,
                    level,
                    source: 'Security Monitor',
                    timestamp: new Date().toISOString()
                })
            });
        } catch (error) {
            console.error('Failed to notify Project F:', error);
        }
    }

    /**
     * Sends an error message to Project F.
     * @param {string} context
     * @param {Error} error
     */
    async function notifyError(context, error) {
        await notifyProjectF(`${context}: ${error.message}`, 'error');
    }

    // ===============================
    // Navigation Handlers
    // ===============================

    /**
     * Handles navigation clicks (simple example).
     * @param {string} section
     */
    function handleNavigation(section) {
        console.log(`Navigating to ${section}`);
        // You can implement more complex behavior if needed (e.g., hide/show sections)
    }

    // Assign event listeners to navigation links
    elements.navLinks.forEach(link => {
        link.addEventListener('click', function (event) {
            event.preventDefault();
            const section = this.dataset.section || 'Security Dashboard';
            handleNavigation(section);
        });
    });

    // ===============================
    // Automatic Refresh and Initialization
    // ===============================

    /**
     * Starts the automatic refresh for security data.
     */
    function startAutoRefresh() {
        setInterval(async () => {
            const isHealthy = await checkSystemStatus();
            if (isHealthy) {
                refreshSecurityEvents(elements.eventFilter.value);
                refreshAuthLogs(elements.authFilter.value);
                refreshSuspiciousActivities(elements.threatFilter.value);
                refreshTokenActivity(elements.tokenFilter.value);  // Add this line
            }
        }, REFRESH_INTERVAL);
    }

    /**
     * Initializes the security monitoring and loads the initial data.
     */
    async function initialize() {
        try {
            showLoading();

            // Initial check of system status
            await checkSystemStatus();

            // Initial data loads
            await Promise.all([
                refreshSecurityEvents(),
                refreshAuthLogs(),
                refreshSuspiciousActivities(),
                refreshTokenActivity()
            ]);

            // Start the auto-refresh cycle
            startAutoRefresh();

            // Hide loading indicator
            hideLoading();

            // Notify Project F that monitoring started successfully
            await notifyProjectF('Security monitoring initialized successfully', 'info');
        } catch (error) {
            console.error('Initialization error:', error);
            hideLoading();
            await notifyError('Initialization Failed', error);
        }
    }

    // ===============================
    // Event Listeners for Filters and Refresh Buttons
    // ===============================

    if (elements.tokenFilter) {
        elements.tokenFilter.addEventListener('change', e =>
            refreshTokenActivity(e.target.value)
        );
    }

    if (elements.refreshTokenActivity) {
        elements.refreshTokenActivity.addEventListener('click', () =>
            refreshTokenActivity(elements.tokenFilter.value)
        );
    }


    if (elements.eventFilter) {
        elements.eventFilter.addEventListener('change', e =>
            refreshSecurityEvents(e.target.value)
        );
    }

    if (elements.authFilter) {
        elements.authFilter.addEventListener('change', e =>
            refreshAuthLogs(e.target.value)
        );
    }

    if (elements.threatFilter) {
        elements.threatFilter.addEventListener('change', e =>
            refreshSuspiciousActivities(e.target.value)
        );
    }

    if (elements.refreshSecurityEvents) {
        elements.refreshSecurityEvents.addEventListener('click', () =>
            refreshSecurityEvents(elements.eventFilter.value)
        );
    }

    if (elements.refreshAuthLogs) {
        elements.refreshAuthLogs.addEventListener('click', () =>
            refreshAuthLogs(elements.authFilter.value)
        );
    }

    if (elements.refreshSuspiciousActivities) {
        elements.refreshSuspiciousActivities.addEventListener('click', () =>
            refreshSuspiciousActivities(elements.threatFilter.value)
        );
    }

    if (elements.refreshSystemStatus) {
        elements.refreshSystemStatus.addEventListener('click', checkSystemStatus);
    }




    // ===============================
    // Start the Application
    // ===============================
    initialize();
});
