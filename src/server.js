const express = require('express');
const cors = require('cors');
const { createServer } = require('http');
const { initializeSocket } = require('./socket');
const db = require('./models');
const apiRoutes = require('./routes/api.routes');

const app = express();

// Get allowed origin from environment variable
const getAllowedOrigin = () => {
    const origins = [process.env.FRONTEND_URL];
    if (process.env.WEBSITE_CORS_ALLOWED_ORIGINS) {
        origins.push(...process.env.WEBSITE_CORS_ALLOWED_ORIGINS.split(','));
    }
    return origins.filter(origin => origin); // Filter out empty values
};

// Middleware
app.use(cors({
    origin: getAllowedOrigin(),
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Health check endpoint
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'healthy' });
});

// Single API route
app.use('/api', apiRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Something broke!' });
});

const server = createServer(app);
const io = initializeSocket(server);

// Initialize database with test data
db.initialize()
    .then(() => {
        console.log('Database synced successfully');
    })
    .catch((err) => {
        console.error('Failed to sync database:', err);
    });

const PORT = process.env.PORT || 5000;
const HOST = process.env.WEBSITE_HOSTNAME || 'localhost';

server.listen(PORT, () => {
    console.log(`Server is running on ${HOST}:${PORT}`);
    console.log('CORS origins:', getAllowedOrigin());
    console.log('Environment:', process.env.NODE_ENV);
});
