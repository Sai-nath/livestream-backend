require('dotenv').config();
const server = require('./server');

const PORT = process.env.PORT || 5000;
const HOST = process.env.WEBSITE_HOSTNAME || 'localhost';

// Global error handlers
process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// Start the server
server.listen(PORT, () => {
    console.log(`Server is running on ${HOST}:${PORT}`);
    console.log('Environment:', process.env.NODE_ENV);
});