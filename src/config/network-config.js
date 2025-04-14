/**
 * Centralized Network Configuration
 * This file contains all IP addresses, ports, and URLs used across the application.
 */

const config = {
  // Network IP Configuration
  networkIP: '192.168.8.120',
  
  // Frontend Configuration
  frontend: {
    protocol: 'https',
    port: 3000,
    get url() {
      return `${this.protocol}://${config.networkIP}:${this.port}`;
    }
  },
  
  // Backend Configuration
  backend: {
    protocol: 'https',
    port: 5000,
    get url() {
      return `${this.protocol}://${config.networkIP}:${this.port}`;
    },
    get wsUrl() {
      return `${this.protocol}://${config.networkIP}:${this.port}`;
    }
  },
  
  // CORS Configuration
  cors: {
    // Additional allowed origins beyond the main frontend/backend
    additionalOrigins: [
      'http://localhost:3000',
      'https://localhost:3000',
      'http://localhost:5000',
      'https://localhost:5000',
      'http://192.168.8.120:3000',
      'https://192.168.8.120:3000',
      'http://192.168.8.120:5000',
      'https://192.168.8.120:5000',
      'https://livestreaming-fjghamgvdsdbd7ct.centralindia-01.azurewebsites.net',
      'https://livestreamingclaims-hpaedbd6b6gbhkb0.centralindia-01.azurewebsites.net',
      'https://thankful-dune-06ac8a600.6.azurestaticapps.net',
      'https://lvsadvance.web.app'
    ],
    
    // Get all allowed origins
    get allowedOrigins() {
      return [
        config.frontend.url,
        config.backend.url,
        ...this.additionalOrigins
      ];
    }
  },
  
  // AWS Configuration
  aws: {
    region: process.env.AWS_REGION || 'eu-north-1',
    s3Bucket: process.env.AWS_S3_BUCKET || 'lvsbucket-5181',
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  },
  
  // Environment Detection
  isProduction: process.env.NODE_ENV === 'production',
  isDevelopment: process.env.NODE_ENV === 'development' || !process.env.NODE_ENV
  
};

module.exports = config;
