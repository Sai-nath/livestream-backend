const express = require('express');
const cors = require('cors');
const {
    createServer
} = require('http');
const {
    initializeSocket
} = require('./socket');
const db = require('./models');
const apiRoutes = require('./routes/api.routes');
const networkConfig = require('./config/network-config');

const app = express();

// CORS configuration
const corsOptions = {
    origin: function (origin, callback) {
        // Parse allowed origins from environment variable
        const allowedOrigins = (process.env.WEBSITE_CORS_ALLOWED_ORIGINS || 'https://192.168.8.120:3000')
            .split(',')
            .map(origin => origin.trim())
            .filter(Boolean);

        // Add frontend URL if specified
        if (process.env.FRONTEND_URL) {
            allowedOrigins.push(process.env.FRONTEND_URL);
        }

        // Default development origins
        const defaultOrigins = [
            'http://localhost:3000',
            'https://localhost:3000',
            'http://192.168.8.120:3000',
            'https://192.168.8.120:3001',
            'http://192.168.8.120:5000',
            'https://192.168.8.120:5000',
            'http://localhost:5000',
            'https://lvsadvance.web.app'
        ];

        // Combine and deduplicate origins
        const combinedOrigins = [...new Set([...allowedOrigins, ...defaultOrigins])];

        console.log('=== CORS Configuration ===');
        console.log('Allowed Origins:', allowedOrigins);
        console.log('Incoming Origin:', origin);
        console.log('========================');

        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) {
            return callback(null, true);
        }

        if (combinedOrigins.includes(origin)) {
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
            allowedOrigins: ['http://localhost:3000', 'https://localhost:3000', 'http://192.168.8.120:3000', 'https://192.168.8.120:3001', 'http://192.168.8.120:5000', 'https://192.168.8.120:5000', 'https://livestreaming-fjghamgvdsdbd7ct.centralindia-01.azurewebsites.net', 'https://livestreamingclaims-hpaedbd6b6gbhkb0.centralindia-01.azurewebsites.net', 'https://nice-sea-057f1c900.4.azurestaticapps.net', 'https://lvsadvance.web.app']
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

const server = createServer(app);
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

const PORT = process.env.PORT || 5000;
const HOST = process.env.WEBSITE_HOSTNAME || '192.168.8.120';

server.listen(PORT, '192.168.8.120', () => {
    console.log(`Server is running on 192.168.8.120:${PORT}`);
    console.log('CORS origins:', networkConfig.cors.allowedOrigins);
    console.log('Environment:', process.env.NODE_ENV);
});

module.exports = server;