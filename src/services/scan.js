//======== scan.js

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const { exec } = require('child_process');

/**
 * Scans a file for validation and security.
 * @param {string} filePath - The path of the file to scan.
 * @param {object} metadata - Additional metadata for the scan.
 * @returns {object} - Scan result with success, metadata, and error properties.
 */
async function scanFile(filePath, metadata) {
    try {
        console.log(`[SCAN] Starting scan for: ${filePath}`);
        console.log(`[SCAN] Metadata received:`, metadata);

        // Ensure the filePath is inside the STORAGE directory
        const STORAGE_DIR = path.resolve(__dirname, '../STORAGE');
        const resolvedPath = path.resolve(filePath);

        if (!resolvedPath.startsWith(STORAGE_DIR)) {
            console.error(`[SCAN] File is outside the STORAGE directory: ${resolvedPath}`);
            return { success: false, error: 'Invalid file path: File must be within the STORAGE directory.' };
        }

        console.log(`[SCAN] Resolved file path: ${resolvedPath}`);

        // Check if file exists
        await fs.access(resolvedPath);
        console.log(`[SCAN] File exists.`);

        // Validate file type
        const fileExtension = path.extname(resolvedPath).toLowerCase();
        const allowedExtensions = ['.pdf', '.docx'];
        if (!allowedExtensions.includes(fileExtension)) {
            return { success: false, error: 'Invalid file type. Only PDF and DOCX are allowed.' };
        }

        // Validate file size (e.g., limit to 10MB)
        const stats = await fs.stat(resolvedPath);
        const maxFileSize = 10 * 1024 * 1024; // 10MB
        if (stats.size > maxFileSize) {
            return { success: false, error: 'File size exceeds the 10MB limit.' };
        }

        // Generate a SHA256 hash for file integrity tracking
        const fileBuffer = await fs.readFile(resolvedPath);
        const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
        console.log(`[SCAN] File SHA256 hash: ${hash}`);

        // Simulate antivirus scanning (replace with real implementation)
        const isClean = await simulateAntivirusScan(resolvedPath);
        if (!isClean) {
            return { success: false, error: 'File contains malicious content.' };
        }

        // Append additional metadata from scan
        const updatedMetadata = {
            ...metadata,
            scannedBy: 'Project Z',
            scannedAt: new Date().toISOString(),
            fileHash: hash,
            fileSize: stats.size,
            fileExtension,
        };

        console.log(`[SCAN] File passed validation. Updated metadata:`, updatedMetadata);

        return { success: true, metadata: updatedMetadata };
    } catch (error) {
        console.error(`[SCAN] Error during file scan: ${error.message}`);
        return { success: false, error: `Error during file scan: ${error.message}` };
    }
}

/**
 * Simulates an antivirus scan.
 * Replace this with actual antivirus logic (e.g., ClamAV, VirusTotal API).
 * @param {string} filePath - The path of the file to scan.
 * @returns {boolean} - Whether the file is clean.
 */
async function simulateAntivirusScan(filePath) {
    return new Promise((resolve) => {
        console.log(`[SCAN] Simulating antivirus scan for: ${filePath}`);

        // Check if ClamAV is installed
        exec(`which clamscan`, (checkError) => {
            if (checkError) {
                console.warn(`[SCAN] ClamAV is not installed. Treating all files as clean.`);
                return resolve(true); // Treat all files as clean
            }

            // Run ClamAV scan
            exec(`clamscan --stdout ${filePath}`, (error, stdout) => {
                if (error) {
                    console.error(`[SCAN] Antivirus scan failed: ${error.message}`);
                    return resolve(false); // Treat as infected
                }
                console.log(`[SCAN] Antivirus scan result:`, stdout);
                resolve(stdout.includes('OK')); // Simulate clean result
            });
        });
    });
}

module.exports = { scanFile };
