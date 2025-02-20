const jwt = require('jsonwebtoken');
const config = require('./config/auth');
const db = require('./models');
const { QueryTypes } = require('sequelize');

let io;

// Map to store user's socket connections
// Key: userId, Value: Set of socket IDs
const userSockets = new Map();

// Map to store user online status and metadata
const onlineUsers = new Map();

const addUserSocket = (userId, socketId) => {
    if (!userSockets.has(userId)) {
        userSockets.set(userId, new Set());
    }
    userSockets.get(userId).add(socketId);
};

const removeUserSocket = (userId, socketId) => {
    if (userSockets.has(userId)) {
        userSockets.get(userId).delete(socketId);
        // If user has no more sockets, they're offline
        if (userSockets.get(userId).size === 0) {
            userSockets.delete(userId);
            return true; // User went offline
        }
    }
    return false; // User still has other connections
};

const isUserOnline = (userId) => {
    return userSockets.has(userId) && userSockets.get(userId).size > 0;
};

const broadcastUserStatus = (userId, isOnline, role) => {
    io.emit('user_status_change', {
        userId,
        isOnline,
        role,
        timestamp: new Date()
    });
};

const updateUserStatus = async (userId, isOnline) => {
    try {
        // Update user's online status in database
        await db.sequelize.query(
            `UPDATE Users 
             SET isOnline = :isOnline, 
                 lastLogin = GETDATE(), 
                 updatedAt = GETDATE() 
             WHERE id = :userId`,
            {
                replacements: { 
                    isOnline: isOnline,
                    userId: userId
                },
                type: QueryTypes.UPDATE
            }
        );

        // Get user role
        const [user] = await db.sequelize.query(
            `SELECT role FROM Users WHERE id = :userId`,
            {
                replacements: { userId: userId },
                type: QueryTypes.SELECT
            }
        );

        // Update online users map
        if (isOnline) {
            onlineUsers.set(userId, {
                role: user.role,
                lastActivity: new Date()
            });
        } else {
            onlineUsers.delete(userId);
        }

        // Broadcast status change to all connected clients
        broadcastUserStatus(userId, isOnline, user.role);

        if (user && user.role === 'SUPERVISOR') {
            // Get all claims assigned by this supervisor
            const claims = await db.sequelize.query(
                `SELECT ClaimId, InvestigatorId 
                 FROM Claims 
                 WHERE SupervisorId = :supervisorId 
                 AND ClaimStatus = 'Assigned'`,
                {
                    replacements: { supervisorId: userId },
                    type: QueryTypes.SELECT
                }
            );

            // Notify investigators of supervisor status change
            for (const claim of claims) {
                if (claim.InvestigatorId) {
                    io.emit('claim_supervisor_status', {
                        claimId: claim.ClaimId,
                        supervisorId: userId,
                        isOnline: isOnline,
                        timestamp: new Date()
                    });
                }
            }
        }
    } catch (error) {
        console.error('Error updating user status:', error);
    }
};

const initializeSocket = (server) => {
    io = require('socket.io')(server, {
        cors: {
            origin: [
                'http://localhost:3000',
                'http://192.168.8.120:3000',
                'https://localhost:3000',
                'https://192.168.8.120:3000'
            ],
            methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization', 'x-access-token'],
            credentials: true
        },
        pingTimeout: 60000, // Increase ping timeout to 60 seconds
        pingInterval: 25000, // Send ping every 25 seconds
        connectTimeout: 30000, // Connection timeout
        transports: ['websocket', 'polling']
    });

    io.use(async (socket, next) => {
        try {
            const token = socket.handshake.auth.token;
            if (!token) {
                throw new Error('Authentication error');
            }

            const decoded = jwt.verify(token, config.secret);
            socket.userId = decoded.id;
            socket.userRole = decoded.role;

            // Add socket to user's socket list
            addUserSocket(decoded.id, socket.id);

            // Only update status if this is the user's first socket
            if (userSockets.get(decoded.id).size === 1) {
                await updateUserStatus(decoded.id, true);
            }

            // Send current online users to the newly connected client
            const onlineUsersList = Array.from(onlineUsers.entries()).map(([id, data]) => ({
                userId: parseInt(id),
                role: data.role,
                isOnline: true,
                timestamp: data.lastActivity
            }));
            socket.emit('online_users', onlineUsersList);

            next();
        } catch (err) {
            console.error('Socket authentication error:', err);
            next(new Error('Authentication error'));
        }
    });

    io.on('connection', (socket) => {
        console.log(`Socket connected: ${socket.id} for user: ${socket.userId}`);
        console.log(`Active connections for user ${socket.userId}:`, userSockets.get(socket.userId).size);

        // Handle ping to keep connection alive
        socket.on('ping', async () => {
            const user = onlineUsers.get(socket.userId);
            if (user) {
                user.lastActivity = new Date();
                await updateUserStatus(socket.userId, true);
            }
            socket.emit('pong');
        });

        // Handle heartbeat to track user activity
        socket.on('heartbeat', async () => {
            try {
                if (onlineUsers.has(socket.userId)) {
                    onlineUsers.get(socket.userId).lastActivity = new Date();
                }
            } catch (error) {
                console.error('Error handling heartbeat:', error);
            }
        });

        // Handle investigation call request
        socket.on('investigation_call_request', async (data) => {
            try {
                const { claimId } = data;
                
                if (!claimId) {
                    socket.emit('call_error', { message: 'Claim ID is required' });
                    return;
                }

                // Get claim details with supervisor info
                const [claim] = await db.sequelize.query(
                    `SELECT c.*, u.id as supervisorId, u.name as supervisorName 
                     FROM Claims c
                     JOIN Users u ON c.SupervisorId = u.id
                     WHERE c.ClaimId = :claimId`,
                    {
                        replacements: { claimId },
                        type: db.Sequelize.QueryTypes.SELECT,
                        model: db.Claims,
                        mapToModel: true
                    }
                );

                if (!claim) {
                    socket.emit('call_error', { message: 'Claim not found' });
                    return;
                }

                // Check if supervisor is online
                if (!isUserOnline(claim.supervisorId)) {
                    socket.emit('call_error', { message: 'Supervisor is offline' });
                    return;
                }

                // Get investigator details
                const [investigator] = await db.sequelize.query(
                    `SELECT name FROM Users WHERE id = :investigatorId`,
                    {
                        replacements: { investigatorId: socket.userId },
                        type: db.Sequelize.QueryTypes.SELECT
                    }
                );

                if (!investigator) {
                    socket.emit('call_error', { message: 'Investigator not found' });
                    return;
                }

                // Emit incoming call to all supervisor's sockets
                const supervisorSockets = userSockets.get(claim.supervisorId);
                if (supervisorSockets) {
                    const callData = {
                        callId: `${claimId}-${Date.now()}`,
                        claimId,
                        claimNumber: claim.ClaimNumber,
                        investigatorId: socket.userId,
                        investigatorName: investigator.name,
                        timestamp: new Date()
                    };

                    supervisorSockets.forEach(socketId => {
                        io.to(socketId).emit('incoming_investigation_call', callData);
                    });

                    // Store the call request
                    socket.callRequest = callData;
                    
                    socket.emit('call_requesting', { 
                        message: 'Call request sent to supervisor',
                        callId: callData.callId
                    });
                } else {
                    socket.emit('call_error', { message: 'Supervisor connection not found' });
                }
            } catch (error) {
                console.error('Error handling call request:', error);
                socket.emit('call_error', { message: 'Error initiating call' });
            }
        });

        // Handle accept investigation call
        socket.on('accept_investigation_call', async ({ callId }) => {
            try {
                console.log('Accepting call request:', { callId, socketId: socket.id });
                
                // Find investigator socket
                const investigatorSocket = Array.from(io.sockets.sockets.values())
                    .find(s => s.callRequest?.callId === callId);

                if (!investigatorSocket) {
                    console.error('Investigator socket not found for call:', callId);
                    socket.emit('call_error', { message: 'Investigator not found' });
                    return;
                }

                // Update call status for both parties
                const callData = {
                    callId,
                    investigatorId: investigatorSocket.userId,
                    investigatorSocketId: investigatorSocket.id,
                    supervisorId: socket.userId,
                    supervisorSocketId: socket.id
                };

                // Notify both parties
                investigatorSocket.emit('investigation_call_accepted', callData);
                socket.emit('investigation_call_accepted', callData);

                // Store call info for both parties
                const callInfo = { 
                    ...investigatorSocket.callRequest, 
                    accepted: true,
                    supervisorId: socket.userId,
                    supervisorSocketId: socket.id
                };
                
                socket.callRequest = callInfo;
                investigatorSocket.callRequest = callInfo;
                
                console.log('Call accepted:', callData);

                // Update claim status
                await db.sequelize.query(
                    `UPDATE Claims 
                     SET ClaimStatus = 'InvestigationStarted',
                         StartedAt = GETDATE()
                     WHERE ClaimId = :claimId`,
                    {
                        replacements: { claimId: investigatorSocket.callRequest.claimId },
                        type: db.Sequelize.QueryTypes.UPDATE
                    }
                );

                // Notify all clients about status update
                io.emit('claim_status_updated', {
                    claimId: investigatorSocket.callRequest.claimId,
                    status: 'InvestigationStarted',
                    timestamp: new Date()
                });

            } catch (error) {
                console.error('Error accepting call:', error);
                socket.emit('call_error', { message: 'Error accepting call' });
            }
        });

        // Handle rejection
        socket.on('reject_investigation_call', async (data) => {
            try {
                const { callId, investigatorId, reason } = data;
                
                // Notify investigator that call was rejected
                const investigatorSockets = userSockets.get(investigatorId);
                if (investigatorSockets) {
                    investigatorSockets.forEach(socketId => {
                        io.to(socketId).emit('investigation_call_rejected', {
                            callId,
                            reason: reason || 'Call rejected by supervisor'
                        });
                    });
                }
            } catch (error) {
                console.error('Error rejecting call:', error);
                socket.emit('call_error', { message: 'Error rejecting call' });
            }
        });

        // Handle call cancellation by investigator
        socket.on('cancel_investigation_call', async (data) => {
            try {
                const { callId, supervisorId } = data;
                
                // Notify supervisor that call was cancelled
                const supervisorSockets = userSockets.get(supervisorId);
                if (supervisorSockets) {
                    supervisorSockets.forEach(socketId => {
                        io.to(socketId).emit('investigation_call_cancelled', {
                            callId
                        });
                    });
                }
            } catch (error) {
                console.error('Error cancelling call:', error);
                socket.emit('call_error', { message: 'Error cancelling call' });
            }
        });

        // WebRTC signaling
        socket.on('video_offer', ({ callId, offer }) => {
            try {
                console.log('Received video offer:', { callId, fromSocket: socket.id });
                
                // Only allow offers from sockets in an active call
                if (!socket.callRequest?.accepted) {
                    console.error('Unauthorized video offer from socket:', socket.id);
                    return;
                }

                const otherSockets = Array.from(io.sockets.sockets.values())
                    .filter(s => s.callRequest?.callId === callId && s.id !== socket.id);

                otherSockets.forEach(s => {
                    console.log('Sending video offer to:', s.id);
                    s.emit('video_offer', { 
                        callId, 
                        offer,
                        fromSocketId: socket.id 
                    });
                });
            } catch (error) {
                console.error('Error handling video offer:', error);
                socket.emit('call_error', { message: 'Error in video offer' });
            }
        });

        socket.on('video_answer', ({ callId, answer }) => {
            try {
                console.log('Received video answer:', { callId, fromSocket: socket.id });

                // Only allow answers from sockets in an active call
                if (!socket.callRequest?.accepted) {
                    console.error('Unauthorized video answer from socket:', socket.id);
                    return;
                }

                const otherSockets = Array.from(io.sockets.sockets.values())
                    .filter(s => s.callRequest?.callId === callId && s.id !== socket.id);

                otherSockets.forEach(s => {
                    console.log('Sending video answer to:', s.id);
                    s.emit('video_answer', { 
                        callId, 
                        answer,
                        fromSocketId: socket.id 
                    });
                });
            } catch (error) {
                console.error('Error handling video answer:', error);
                socket.emit('call_error', { message: 'Error in video answer' });
            }
        });

        socket.on('ice_candidate', ({ callId, candidate }) => {
            try {
                console.log('Received ICE candidate:', { callId, fromSocket: socket.id });

                // Only allow ICE candidates from sockets in an active call
                if (!socket.callRequest?.accepted) {
                    console.error('Unauthorized ICE candidate from socket:', socket.id);
                    return;
                }

                const otherSockets = Array.from(io.sockets.sockets.values())
                    .filter(s => s.callRequest?.callId === callId && s.id !== socket.id);

                otherSockets.forEach(s => {
                    console.log('Sending ICE candidate to:', s.id);
                    s.emit('ice_candidate', { 
                        callId, 
                        candidate,
                        fromSocketId: socket.id 
                    });
                });
            } catch (error) {
                console.error('Error handling ICE candidate:', error);
                socket.emit('call_error', { message: 'Error in ICE candidate' });
            }
        });

        socket.on('end_call', ({ callId }) => {
            const otherSockets = Array.from(io.sockets.sockets.values())
                .filter(s => s.callRequest?.callId === callId);
            
            otherSockets.forEach(s => {
                s.emit('call_ended');
                s.callRequest = null;
            });
        });

        socket.on('save_screenshot', async ({ callId, screenshot, timestamp }) => {
            try {
                // Save screenshot to database or file system
                // TODO: Implement screenshot storage
                console.log('Screenshot saved:', { callId, timestamp });
            } catch (error) {
                console.error('Error saving screenshot:', error);
            }
        });

        // Handle claim status update
        socket.on('update_claim_status', async ({ claimId, status }) => {
            try {
                console.log('Updating claim status:', { claimId, status });
                
                // Update claim status in database
                await db.sequelize.query(
                    `UPDATE Claims 
                     SET ClaimStatus = :status,
                         ${status === 'InvestigationStarted' ? 'StartedAt = GETDATE()' : ''}
                     WHERE ClaimId = :claimId`,
                    {
                        replacements: { claimId, status },
                        type: db.Sequelize.QueryTypes.UPDATE
                    }
                );

                // Notify all connected clients about the status update
                io.emit('claim_status_updated', {
                    claimId,
                    status,
                    timestamp: new Date()
                });

                console.log('Claim status updated successfully:', { claimId, status });
            } catch (error) {
                console.error('Error updating claim status:', error);
                socket.emit('call_error', { message: 'Error updating claim status' });
            }
        });

        // Handle chat messages
        socket.on('chat_message', ({ callId, role, message, timestamp }) => {
            try {
                console.log('Received chat message:', { callId, role, message });
                
                // Find all sockets in the same call
                const callSockets = Array.from(io.sockets.sockets.values())
                    .filter(s => s.callRequest?.callId === callId && s.id !== socket.id);

                // Broadcast message to all other sockets in the call
                callSockets.forEach(s => {
                    console.log('Sending chat message to:', s.id);
                    s.emit('chat_message', { role, message, timestamp });
                });
            } catch (error) {
                console.error('Error handling chat message:', error);
            }
        });

        // Handle mute status
        socket.on('participant_muted', (data) => {
            const { callId, isMuted } = data;
            socket.to(callId).emit('participant_muted', { role: socket.role, isMuted });
        });

        // Handle call rejoin after refresh
        socket.on('rejoin_call', ({ callId, role }) => {
            console.log(`User ${socket.id} rejoining call ${callId} as ${role}`);
            
            // Update socket data
            socket.callId = callId;
            socket.role = role;
            
            // Join room
            socket.join(callId);
            
            // Notify others
            socket.to(callId).emit('participant_rejoined', { role });
        });

        // Handle disconnect
        socket.on('disconnect', async () => {
            try {
                console.log(`Socket disconnected: ${socket.id} for user: ${socket.userId}`);
                
                // Remove socket from user's socket list
                const userWentOffline = removeUserSocket(socket.userId, socket.id);
                
                // Only update status if user has no more active sockets
                if (userWentOffline) {
                    await updateUserStatus(socket.userId, false);
                    console.log(`User ${socket.userId} went offline (no more active connections)`);
                } else {
                    console.log(`User ${socket.userId} still has ${userSockets.get(socket.userId).size} active connections`);
                }

                // Check for inactive users
                const now = Date.now();
                for (const [userId, data] of onlineUsers.entries()) {
                    const inactiveTime = now - data.lastActivity;
                    if (inactiveTime > 5 * 60 * 1000) { // 5 minutes of inactivity
                        const userSockets = io.sockets.adapter.rooms.get(userId);
                        if (!userSockets || userSockets.size === 0) {
                            await updateUserStatus(userId, false);
                            onlineUsers.delete(userId);
                        }
                    }
                }
            } catch (error) {
                console.error('Error handling disconnect:', error);
            }
        });

        // Handle ping to keep connection alive
        socket.on('ping_call', ({ callId }) => {
            const call = socket.callRequest;
            if (call) {
                socket.emit('pong_call', { callId });
            }
        });

        // Handle explicit call end
        socket.on('end_call', ({ callId }) => {
            const call = socket.callRequest;
            if (call) {
                // Notify all participants
                io.to(callId).emit('call_ended');
                
                // Cleanup call data
                for (const participantId of call.participants) {
                    socket.callRequest = null;
                }
            }
        });
    });
};

const broadcastOnlineUsers = () => {
    if (io) {
        const onlineUsersList = Array.from(onlineUsers.values());
        io.emit('onlineUsers', onlineUsersList);
    }
};

module.exports = {
    initializeSocket,
    getIO: () => io,
    getOnlineUsers: () => Array.from(onlineUsers.values())
};
