const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const secretPath = path.join(__dirname, '..', '..', '.jwt-secret');

// Function to generate a secure random secret
function generateSecret() {
    return crypto.randomBytes(64).toString('hex');
}

// Function to read or create JWT secret
function getJWTSecret() {
    try {
        // Check if secret file exists
        if (fs.existsSync(secretPath)) {
            return fs.readFileSync(secretPath, 'utf8').trim();
        }
        
        // Generate and save a new secret
        const secret = generateSecret();
        fs.writeFileSync(secretPath, secret, { mode: 0o600 }); // Secure file permissions
        return secret;
    } catch (error) {
        console.error('Error managing JWT secret:', error);
        return generateSecret(); // Fallback to a new random secret
    }
}

// JWT configuration
module.exports = {
    secret: getJWTSecret(),
    expiresIn: '24h' // Token expiration time
};
