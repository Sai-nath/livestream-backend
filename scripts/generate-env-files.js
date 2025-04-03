/**
 * Script to generate environment files based on centralized network configuration
 */

const fs = require('fs');
const path = require('path');
const networkConfig = require('../src/config/network-config');

// Generate backend environment files
const generateBackendEnvFiles = () => {
  const backendDir = path.join(__dirname, '..');
  
  // Development environment
  const devEnvContent = `# Development Environment Configuration

# Server Configuration
NODE_ENV=development
PORT=${networkConfig.backend.port}
WEBSITE_HOSTNAME=${networkConfig.networkIP}
FRONTEND_URL=${networkConfig.frontend.url}
WEBSITE_CORS_ALLOWED_ORIGINS=${networkConfig.cors.allowedOrigins.join(',')}

# JWT Configuration
JWT_SECRET=Sainath@518181

# Database Configuration
DB_SERVER=insurenexcore.database.windows.net
DB_NAME=LiveStreaming
DB_USER=saiadmin
DB_PASSWORD=Sainath@518181
AWS_ACCESS_KEY_ID=AKIAQZFG5EPCOJL2OE55
AWS_SECRET_ACCESS_KEY=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
AWS_REGION=${networkConfig.aws.region}
S3_BUCKET=${networkConfig.aws.s3Bucket}
`;

  // Production environment
  const prodEnvContent = `# Production Environment Configuration

# Server Configuration
NODE_ENV=production
PORT=${networkConfig.backend.port}
WEBSITE_HOSTNAME=livestreaming-fjghamgvdsdbd7ct.centralindia-01.azurewebsites.net
FRONTEND_URL=https://nice-sea-057f1c900.4.azurestaticapps.net
WEBSITE_CORS_ALLOWED_ORIGINS=https://nice-sea-057f1c900.4.azurestaticapps.net,https://livestreaming-fjghamgvdsdbd7ct.centralindia-01.azurewebsites.net,wss://livestreaming-fjghamgvdsdbd7ct.centralindia-01.azurewebsites.net

# JWT Configuration
JWT_SECRET=Sainath@518181

# Database Configuration
DB_SERVER=insurenexcore.database.windows.net
DB_NAME=LiveStreaming
DB_USER=saiadmin
DB_PASSWORD=Sainath@518181
AWS_ACCESS_KEY_ID=AKIAQZFG5EPCOJL2OE55
AWS_SECRET_ACCESS_KEY=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
AWS_REGION=${networkConfig.aws.region}
S3_BUCKET=${networkConfig.aws.s3Bucket}
`;

  try {
    fs.writeFileSync(path.join(backendDir, '.env.development'), devEnvContent);
    fs.writeFileSync(path.join(backendDir, '.env.production'), prodEnvContent);
    console.log('Backend environment files generated successfully');
  } catch (error) {
    console.error('Error generating backend environment files:', error);
  }
};

// Run the generator
generateBackendEnvFiles();

console.log('Backend environment files have been generated based on the network configuration');
