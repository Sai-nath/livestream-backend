const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();
const server = http.createServer(app);

// CORS configuration
const corsOptions = {
    origin: process.env.CORS_ORIGIN || '*',
    methods: ['GET', 'POST'],
    credentials: true
};

app.use(cors(corsOptions));
app.use(express.json());

// Serve static files from public directory
app.use(express.static(path.join(__dirname, '../public')));

// Socket.io setup with CORS
const io = socketIo(server, {
    cors: corsOptions,
    transports: ['websocket', 'polling']
});

// Import and setup routes
const apiRoutes = require('./routes/api.routes');
app.use('/api', apiRoutes);

// Setup socket handlers
require('./socket')(io);

// Serve index.html for all other routes (SPA support)
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/index.html'));
});

const PORT = process.env.PORT || 8080;

server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
