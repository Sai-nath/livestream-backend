/**
 * Centralized Network Configuration
 * This file contains all IP addresses, ports, and URLs used across the application.
 */

const config = {
  // Network IP Configuration
  networkIP: '192.168.8.150',
  
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
    protocol: 'http',
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
      'https://livestreaming-fjghamgvdsdbd7ct.centralindia-01.azurewebsites.net',
      'https://nice-sea-057f1c900.4.azurestaticapps.net'
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
    region: 'eu-north-1',
    s3Bucket: 'lvsbucket-5181'
  }
};

module.exports = config;
