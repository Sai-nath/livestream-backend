require('dotenv').config({
    path: process.env.NODE_ENV === 'development' 
        ? '.env.development'
        : '.env'
});
const server = require('./server');

const PORT = process.env.PORT || 5000;
const HOST = process.env.WEBSITE_HOSTNAME || 'localhost';

// Log environment details
console.log('=== Environment Details ===');
console.log('Node Version:', process.version);
console.log('Environment:', process.env.NODE_ENV);
console.log('Port:', PORT);
console.log('Host:', HOST);
console.log('Frontend URL:', process.env.FRONTEND_URL);
console.log('Database Server:', process.env.DB_SERVER);
console.log('Database Name:', process.env.DB_NAME);
console.log('Current Directory:', process.cwd());
console.log('========================');

// Global error handlers
process.on('uncaughtException', (error) => {
    console.error('=== Uncaught Exception ===');
    console.error('Error:', error.message);
    console.error('Stack:', error.stack);
    console.error('========================');
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('=== Unhandled Rejection ===');
    console.error('Reason:', reason);
    console.error('Promise:', promise);
    console.error('========================');
});

// Start the server
server.listen(PORT, () => {
    console.log(`=== Server Started ===`);
    console.log(`Server is running on ${HOST}:${PORT}`);
    console.log(`Time: ${new Date().toISOString()}`);
    console.log('=====================');
});