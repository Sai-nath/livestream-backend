/**
 * Script to update CORS configuration file using the centralized network config
 */

const fs = require('fs');
const path = require('path');
const networkConfig = require('../src/config/network-config');

// Path to CORS config file
const corsConfigPath = path.join(__dirname, '..', 'cors-config.json');

// Read existing CORS config
let corsConfig;
try {
  const corsConfigContent = fs.readFileSync(corsConfigPath, 'utf8');
  corsConfig = JSON.parse(corsConfigContent);
} catch (error) {
  console.error('Error reading CORS config file:', error);
  process.exit(1);
}

// Update the AllowedOrigins with values from network config
if (corsConfig && corsConfig.CORSRules && corsConfig.CORSRules.length > 0) {
  corsConfig.CORSRules[0].AllowedOrigins = networkConfig.cors.allowedOrigins;
  
  // Write updated config back to file
  try {
    fs.writeFileSync(
      corsConfigPath,
      JSON.stringify(corsConfig, null, 4),
      'utf8'
    );
    console.log('CORS config file updated successfully with network configuration');
  } catch (error) {
    console.error('Error writing CORS config file:', error);
    process.exit(1);
  }
} else {
  console.error('Invalid CORS config structure');
  process.exit(1);
}
