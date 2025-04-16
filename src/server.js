const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const { initializeSocket } = require('./socket');
const db = require('./models');
const apiRoutes = require('./routes/api.routes');
const networkConfig = require('./config/network-config');

const app = express();

// CORS configuration
const corsOptions = {
    origin: function (origin, callback) {
        // Get allowed origins from centralized network configuration
        const allowedOrigins = networkConfig.cors.allowedOrigins;
        
        // Add frontend URL from environment if specified
        if (process.env.FRONTEND_URL && !allowedOrigins.includes(process.env.FRONTEND_URL)) {
            allowedOrigins.push(process.env.FRONTEND_URL);
        }
        
        // Add Azure deployment URLs
        const azureUrls = [
            'https://livestreamingclaims-hpaedbd6b6gbhkb0.centralindia-01.azurewebsites.net',
            'https://thankful-dune-06ac8a600.6.azurestaticapps.net'
        ];
        
        // Combine all origins
        const combinedOrigins = [...new Set([...allowedOrigins, ...azureUrls])];

        console.log('=== CORS Configuration ===');
        console.log('Allowed Origins:', combinedOrigins);
        console.log('Incoming Origin:', origin);
        console.log('========================');

        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) {
            return callback(null, true);
        }

        if (combinedOrigins.includes(origin) || process.env.NODE_ENV === 'development') {
            callback(null, true);
        } else {
            console.warn('Origin not allowed by CORS:', origin);
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-access-token'],
    credentials: true,
    preflightContinue: false,
    optionsSuccessStatus: 204
};

// Apply CORS to all routes
app.use(cors(corsOptions));

// Middleware
app.use(express.json());
app.use(express.urlencoded({
    extended: true
}));

// Handle preflight requests for all routes
app.options('*', cors(corsOptions));

// Health check endpoint
app.get('/health', (req, res) => {
    console.log('=== Health Check ===');
    console.log('Time:', new Date().toISOString());
    console.log('Request IP:', req.ip);
    console.log('Headers:', req.headers);
    console.log('===================');
    res.status(200).json({
        status: 'healthy',
        time: new Date().toISOString(),
        env: process.env.NODE_ENV,
        node: process.version,
        cors: {
            frontendUrl: process.env.FRONTEND_URL,
            allowedOrigins: networkConfig.cors.allowedOrigins
        }
    });
});

// Single API route
app.use('/api', apiRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('=== Error Handler ===');
    console.error('Time:', new Date().toISOString());
    console.error('Error:', err.message);
    console.error('Stack:', err.stack);
    console.error('Request Path:', req.path);
    console.error('Request Method:', req.method);
    console.error('===================');
    res.status(500).json({
        message: 'Something broke!'
    });
});

// Determine if we should use HTTPS based on environment
let server;

if (process.env.NODE_ENV === 'production') {
    // In production, we'll use whatever the hosting platform provides
    server = http.createServer(app);
} else {
    // For local development, try to use HTTPS with self-signed certificates
    try {
        // Check if certificates exist, otherwise fall back to HTTP
        const certPath = path.join(__dirname, '../ssl');
        const privateKey = fs.readFileSync(path.join(certPath, 'key.pem'), 'utf8');
        const certificate = fs.readFileSync(path.join(certPath, 'cert.pem'), 'utf8');
        
        const credentials = { key: privateKey, cert: certificate };
        server = https.createServer(credentials, app);
        console.log('HTTPS server created successfully with self-signed certificates');
    } catch (error) {
        console.warn('Failed to create HTTPS server, falling back to HTTP:', error.message);
        server = http.createServer(app);
    }
}

const io = initializeSocket(server);

// Initialize database with test data
db.initialize()
    .then(() => {
        console.log('=== Database Connection ===');
        console.log('Status: Connected');
        console.log('Server:', process.env.DB_SERVER);
        console.log('Database:', process.env.DB_NAME);
        console.log('Time:', new Date().toISOString());
        console.log('========================');
    })
    .catch((err) => {
        console.error('=== Database Error ===');
        console.error('Time:', new Date().toISOString());
        console.error('Error:', err.message);
        console.error('Stack:', err.stack);
        console.error('====================');
    });

const PORT = process.env.PORT || networkConfig.backend.port;
const HOST = process.env.WEBSITE_HOSTNAME || networkConfig.networkIP;

server.listen(PORT, networkConfig.networkIP, () => {
    const protocol = server instanceof https.Server ? 'HTTPS' : 'HTTP';
    console.log(`=== Server Started ===`);
    console.log(`Server is running on ${protocol}://${networkConfig.networkIP}:${PORT}`);
    console.log('CORS origins:', networkConfig.cors.allowedOrigins.length, 'origins configured');
    console.log('Environment:', process.env.NODE_ENV || 'development');
});

module.exports = server;