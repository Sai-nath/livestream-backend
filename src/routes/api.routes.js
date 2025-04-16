const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const config = require('../config/auth');
const db = require('../models');
const { Op, QueryTypes } = require('sequelize');
const router = express.Router();

// Middleware to verify JWT token
const verifyToken = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ message: 'No token provided' });
        }

        const decoded = jwt.verify(token, config.secret);
        
        // Fetch user from database to ensure they exist
        const user = await db.User.findByPk(decoded.id);
        
        if (!user) {
            return res.status(401).json({ message: 'Invalid user' });
        }

        // Attach user to request
        req.user = user;
        next();
    } catch (error) {
        console.error('Token verification error:', error);
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ message: 'Invalid token' });
        }
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ message: 'Token expired' });
        }
        res.status(500).json({ message: 'Error authenticating user' });
    }
};

// Handle CORS preflight for all routes
router.options('*', (req, res) => {
    res.sendStatus(200);
});

// Login route
router.post('/auth/login', async (req, res) => {
    try {
        console.log('Login attempt with body:', req.body);
        const { email, password } = req.body;
        
        if (!email || !password) {
            console.log('Missing credentials - Email:', !!email, 'Password:', !!password);
            return res.status(400).json({ message: 'Email and password are required' });
        }

        console.log('Searching for user with email:', email);
        const user = await db.User.findOne({ 
            where: { 
                email: email,
                status: 'ACTIVE'
            },
            raw: true
        });
        
        if (!user) {
            console.log('User not found with email:', email);
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        
        console.log('Found user:', {
            id: user.id,
            email: user.email,
            role: user.role,
            status: user.status
        });

        // Compare password using bcrypt
        const isValidPassword = await bcrypt.compare(password, user.password);
        console.log('Password verification result:', isValidPassword);

        if (!isValidPassword) {
            console.log('Password mismatch for user:', email);
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Skip lastLogin update for now since it's causing SQL Server issues
        const token = jwt.sign(
            { id: user.id, role: user.role },
            config.secret,
            { expiresIn: '24h' }
        );

        console.log('Login successful for:', email);
        res.json({
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role,
            token
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Internal server error', error: error.message });
    }
});

// Get users by role
router.get('/users', verifyToken, async (req, res) => {
    try {
        const { role } = req.query;
        const users = await db.User.findAll({
            where: {
                role: role,
                status: 'Active'
            },
            attributes: ['id', 'name', 'email', 'lastLogin'],
            raw: true
        });

        // Format lastLogin for each user
        const formattedUsers = users.map(user => ({
            ...user,
            lastLogin: user.lastLogin ? user.lastLogin : null
        }));

        res.json(formattedUsers);
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ message: error.message });
    }
});

// Get claims
router.get('/claims', verifyToken, async (req, res) => {
    try {
        // Extract pagination parameters
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const offset = (page - 1) * limit;
        
        // Extract filter parameters
        const { status, search, sortBy, sortOrder } = req.query;
        
        // Build where clause for filtering
        let whereClause = {};
        if (status) {
            // Special handling for 'Assigned' status to include 'In Progress' claims as well
            if (status === 'Assigned') {
                whereClause.ClaimStatus = {
                    [Op.in]: ['Assigned', 'In Progress']
                };
            } else {
                whereClause.ClaimStatus = status;
            }
        }
        
        // Add search functionality
        if (search) {
            whereClause = {
                ...whereClause,
                [Op.or]: [
                    { ClaimNumber: { [Op.like]: `%${search}%` } },
                    { PolicyNumber: { [Op.like]: `%${search}%` } },
                    { InsuredName: { [Op.like]: `%${search}%` } },
                    { VehicleNumber: { [Op.like]: `%${search}%` } }
                ]
            };
        }
        
        // Set up sorting
        const order = [];
        if (sortBy) {
            order.push([sortBy, sortOrder === 'desc' ? 'DESC' : 'ASC']);
        } else {
            order.push(['CreatedAt', 'DESC']);
        }
        
        // Get total count for pagination metadata
        const totalCount = await db.Claim.count({ where: whereClause });
        
        // Execute query with pagination
        const claims = await db.Claim.findAll({
            where: whereClause,
            include: [{
                model: db.User,
                as: 'investigator',
                attributes: ['id', 'name', 'email', 'lastLogin']
            }, {
                model: db.User,
                as: 'supervisor',
                attributes: ['id', 'name', 'email']
            }],
            order,
            limit,
            offset
        });
        
        // Return paginated results with metadata
        res.json({
            totalItems: totalCount,
            totalPages: Math.ceil(totalCount / limit),
            currentPage: page,
            pageSize: limit,
            data: claims
        });
    } catch (error) {
        console.error('Get claims error:', error);
        res.status(500).json({ message: error.message });
    }
});

// Get assigned claims for investigator with pagination and filtering
router.get('/claims/assigned', verifyToken, async (req, res) => {
    try {
        if (!req.user || !req.user.id) {
            return res.status(401).json({ message: 'User not authenticated' });
        }
        
        // Extract pagination parameters
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const offset = (page - 1) * limit;
        
        // Extract filter parameters
        const { search, sortBy, sortOrder } = req.query;
        
        // Build the base query - use explicit column selection to avoid duplicates
        let query = `SELECT 
                    c.ClaimId, c.ClaimNumber, c.VehicleNumber, c.VehicleType, 
                    c.PolicyNumber, c.InsuredName, c.ClaimStatus, 
                    c.CreatedAt, c.AssignedAt, c.CompletedAt, c.ClosedAt, 
                    c.SupervisorNotes, c.InvestigatorNotes, c.InvestigatorId,
                    i.name as InvestigatorName,
                    i.email as InvestigatorEmail,
                    s.id as SupervisorId,
                    s.name as SupervisorName,
                    s.email as SupervisorEmail,
                    s.isOnline as SupervisorOnline,
                    s.lastLogin as SupervisorLastLogin
             FROM Claims c
             LEFT JOIN Users i ON c.InvestigatorId = i.id
             LEFT JOIN Users s ON c.SupervisorId = s.id
             WHERE c.InvestigatorId = :userId
             AND c.ClaimStatus IN ('Assigned', 'In Progress')`;
        
        // Add search condition if provided
        const queryParams = { userId: req.user.id };
        if (search) {
            query += ` AND (c.ClaimNumber LIKE :search 
                      OR c.PolicyNumber LIKE :search 
                      OR c.CustomerName LIKE :search 
                      OR c.CustomerPhone LIKE :search 
                      OR c.CustomerEmail LIKE :search)`;
            queryParams.search = `%${search}%`;
        }
        
        // Add sorting
        if (sortBy) {
            const direction = sortOrder === 'desc' ? 'DESC' : 'ASC';
            query += ` ORDER BY c.${sortBy} ${direction}`;
        } else {
            query += ` ORDER BY c.createdAt DESC`;
        }
        
        // Create a query without ORDER BY for the count subquery
        // SQL Server doesn't allow ORDER BY in subqueries used for COUNT
        let countQuery = query;
        // Remove any ORDER BY clause for the count query
        if (countQuery.includes(' ORDER BY ')) {
            countQuery = countQuery.substring(0, countQuery.indexOf(' ORDER BY '));
        }
        
        // Get total count for pagination metadata
        const countResult = await db.sequelize.query(
            `SELECT COUNT(*) as total FROM (${countQuery}) as subquery`,
            {
                replacements: queryParams,
                type: db.sequelize.QueryTypes.SELECT
            }
        );
        const totalCount = countResult[0].total;
        
        // Add pagination
        query += ` OFFSET :offset ROWS FETCH NEXT :limit ROWS ONLY`;
        queryParams.offset = offset;
        queryParams.limit = limit;
        
        // Execute the final query
        const claims = await db.sequelize.query(
            query,
            {
                replacements: queryParams,
                type: QueryTypes.SELECT
            }
        );

        console.log('Raw claim from database:', JSON.stringify(claims[0], null, 2));

        const formattedClaims = claims.map(claim => ({
            id: claim.id,
            claimId: claim.ClaimId, // Matches DB column ClaimId
            ClaimNumber: claim.ClaimNumber, // Explicitly map ClaimNumber from DB
            vehicleInfo: {
                make: claim.VehicleType ? claim.VehicleType.split(' ')[0] : '',
                model: claim.VehicleType ? claim.VehicleType.split(' ').slice(1).join(' ') : '',
                registrationNumber: claim.VehicleNumber || ''
            },
            claimDetails: {
                policyNumber: claim.PolicyNumber || '',
                insuredName: claim.InsuredName || '',
                dateOfIncident: claim.IncidentDate,
                location: claim.IncidentLocation,
                description: claim.Description,
                supervisorNotes: claim.SupervisorNotes,
                investigatorNotes: claim.InvestigatorNotes
            },
            status: claim.ClaimStatus,
            assignedAt: claim.AssignedAt,
            investigationId: claim.InvestigationId,
            investigator: claim.InvestigatorId ? {
                id: claim.InvestigatorId,
                name: claim.InvestigatorName,
                email: claim.InvestigatorEmail
            } : null,
            supervisor: claim.SupervisorId ? {
                id: claim.SupervisorId,
                name: claim.SupervisorName,
                email: claim.SupervisorEmail,
                isOnline: claim.SupervisorOnline,
                lastLogin: claim.SupervisorLastLogin,
                notes: claim.SupervisorNotes // Added here to match your data
            } : null
        }));

        console.log('Formatted claim:', JSON.stringify(formattedClaims[0], null, 2));
        
        // Return paginated results with metadata
        res.json({
            totalItems: totalCount,
            totalPages: Math.ceil(totalCount / limit),
            currentPage: page,
            pageSize: limit,
            data: formattedClaims
        });
    } catch (error) {
        console.error('Error fetching assigned claims:', error);
        res.status(500).json({ 
            message: 'Error fetching assigned claims',
            error: error.message 
        });
    }
});


// Create new claim
router.post('/claims', verifyToken, async (req, res) => {
    try {
        const { 
            claimNumber, 
            vehicleNumber, 
            vehicleType, 
            policyNumber, 
            insuredName, 
            supervisorNotes 
        } = req.body;
        const supervisorId = req.user.id;

        // Format the date in SQL Server compatible format
        const currentDate = new Date().toISOString().slice(0, 19).replace('T', ' ');

        const [claim] = await db.sequelize.query(
            `INSERT INTO Claims 
             (ClaimNumber, ClaimStatus, SupervisorId, CreatedAt, VehicleNumber, VehicleType, PolicyNumber, InsuredName, SupervisorNotes) 
             OUTPUT INSERTED.*
             VALUES (:claimNumber, 'New', :supervisorId, :createdAt, :vehicleNumber, :vehicleType, :policyNumber, :insuredName, :supervisorNotes)`,
            {
                replacements: {
                    claimNumber: claimNumber || `CLM-${Date.now()}`,
                    supervisorId,
                    createdAt: currentDate,
                    vehicleNumber: vehicleNumber || null,
                    vehicleType: vehicleType || null,
                    policyNumber: policyNumber || null,
                    insuredName: insuredName || null,
                    supervisorNotes: supervisorNotes || null
                },
                type: QueryTypes.INSERT
            }
        );

        console.log('Created claim:', claim);
        res.status(201).json(claim);
    } catch (error) {
        console.error('Create claim error:', error);
        res.status(500).json({ 
            message: 'Error creating claim', 
            error: error.message 
        });
    }
});

// Assign investigator to claim
router.post('/claims/:claimId/assign', verifyToken, async (req, res) => {
    try {
        const { claimId } = req.params;
        const { investigatorId } = req.body;

        if (!claimId || !investigatorId) {
            return res.status(400).json({ message: 'Claim ID and Investigator ID are required' });
        }

        // Parse IDs to integers
        const parsedClaimId = parseInt(claimId, 10);
        const parsedInvestigatorId = parseInt(investigatorId, 10);

        if (isNaN(parsedClaimId) || isNaN(parsedInvestigatorId)) {
            return res.status(400).json({ message: 'Invalid Claim ID or Investigator ID format' });
        }

        // Find the claim
        const claim = await db.sequelize.query(
            `SELECT ClaimId, ClaimStatus, SupervisorId 
             FROM Claims 
             WHERE ClaimId = :claimId`,
            {
                replacements: { claimId: parsedClaimId },
                type: QueryTypes.SELECT
            }
        );

        if (!claim || claim.length === 0) {
            return res.status(404).json({ message: 'Claim not found' });
        }

        // Verify the claim is not already assigned
        if (claim[0].ClaimStatus === 'Assigned' || claim[0].ClaimStatus === 'In Progress') {
            return res.status(400).json({ message: 'Claim is already assigned' });
        }

        // Update the claim
        await db.sequelize.query(
            `UPDATE Claims 
             SET InvestigatorId = :investigatorId,
                 ClaimStatus = 'Assigned',
                 AssignedAt = GETDATE()
             WHERE ClaimId = :claimId`,
            {
                replacements: { 
                    investigatorId: parsedInvestigatorId,
                    claimId: parsedClaimId
                },
                type: QueryTypes.UPDATE
            }
        );

        // Get the updated claim with supervisor and investigator details
        const [updatedClaim] = await db.sequelize.query(
            `SELECT c.ClaimId, c.ClaimNumber, c.VehicleNumber, c.VehicleType, 
                    c.PolicyNumber, c.InsuredName, c.ClaimStatus, 
                    c.SupervisorId, c.InvestigatorId, c.CreatedAt, 
                    c.AssignedAt, c.CompletedAt, c.ClosedAt,
                    u1.name as supervisorName, u1.email as supervisorEmail,
                    u2.name as investigatorName, u2.email as investigatorEmail
             FROM Claims c
             LEFT JOIN Users u1 ON c.SupervisorId = u1.id
             LEFT JOIN Users u2 ON c.InvestigatorId = u2.id
             WHERE c.ClaimId = :claimId`,
            {
                replacements: { claimId: parsedClaimId },
                type: QueryTypes.SELECT
            }
        );

        // Emit socket event for real-time update
        const io = req.app.get('io');
        if (io) {
            io.emit('claim_assigned', {
                claimId: parsedClaimId,
                investigatorId: parsedInvestigatorId,
                claim: updatedClaim
            });
        }

        res.json(updatedClaim);
    } catch (error) {
        console.error('Assign claim error:', error);
        res.status(500).json({ message: 'Error assigning investigator to claim', error: error.message });
    }
});

// Update claim status after livestream completion
router.post('/claims/:claimId/submit', verifyToken, async (req, res) => {
    try {
        const { claimId } = req.params;
        const { recordingUrl, notes } = req.body;

        if (!claimId) {
            return res.status(400).json({ message: 'Claim ID is required' });
        }

        // Update claim status to submitted
        await db.sequelize.query(
            `UPDATE Claims 
             SET ClaimStatus = 'Submitted',
                 RecordingUrl = :recordingUrl,
                 InvestigatorNotes = CASE 
                    WHEN InvestigatorNotes IS NULL THEN :notes
                    ELSE InvestigatorNotes + CHAR(13) + CHAR(10) + :notes
                 END,
                 SubmittedAt = GETDATE()
             WHERE ClaimId = :claimId`,
            {
                replacements: { 
                    claimId,
                    recordingUrl: recordingUrl || null,
                    notes: notes || 'Investigation completed via video call.'
                },
                type: QueryTypes.UPDATE
            }
        );

        // Get updated claim details
        const [updatedClaim] = await db.sequelize.query(
            `SELECT c.*, 
                    i.name as InvestigatorName,
                    s.name as SupervisorName
             FROM Claims c
             LEFT JOIN Users i ON c.InvestigatorId = i.id
             LEFT JOIN Users s ON c.SupervisorId = s.id
             WHERE c.ClaimId = :claimId`,
            {
                replacements: { claimId },
                type: QueryTypes.SELECT
            }
        );

        // Emit socket event for real-time update
        const io = req.app.get('io');
        if (io) {
            io.emit('claim_submitted', {
                claimId,
                claim: updatedClaim
            });
        }

        res.json(updatedClaim);
    } catch (error) {
        console.error('Submit claim error:', error);
        res.status(500).json({ message: 'Error submitting claim', error: error.message });
    }
});

// Update claim status after livestreaming ends
router.put('/claims/:claimId/livestream-completed', verifyToken, async (req, res) => {
    try {
        const { claimId } = req.params;
        
        console.log(`Updating claim status for claim ID: ${claimId}`);
        
        // Check if claim exists
        const [claims] = await db.sequelize.query(
            `SELECT ClaimId, ClaimStatus FROM Claims WHERE ClaimId = :claimId`,
            {
                replacements: { claimId },
                type: QueryTypes.SELECT
            }
        );
        
        if (!claims || claims.length === 0) {
            console.error(`Claim with ID ${claimId} not found`);
            return res.status(404).json({ error: 'Claim not found' });
        }
        
        console.log(`Current claim status: ${claims[0]?.ClaimStatus}`);
        
        // Update claim status to InvestigationCompleted
        const [updateResult] = await db.sequelize.query(
            `UPDATE Claims 
             SET ClaimStatus = 'InvestigationCompleted',
                 UpdatedAt = GETDATE()
             WHERE ClaimId = :claimId`,
            {
                replacements: { claimId },
                type: QueryTypes.UPDATE
            }
        );
        
        console.log(`Update result:`, updateResult);
        
        // Verify the update
        const [updatedClaims] = await db.sequelize.query(
            `SELECT ClaimId, ClaimStatus FROM Claims WHERE ClaimId = :claimId`,
            {
                replacements: { claimId },
                type: QueryTypes.SELECT
            }
        );
        
        console.log(`Updated claim status: ${updatedClaims[0]?.ClaimStatus}`);
        
        res.json({ 
            message: 'Claim status updated successfully',
            previousStatus: claims[0]?.ClaimStatus,
            currentStatus: updatedClaims[0]?.ClaimStatus
        });
    } catch (error) {
        console.error('Error updating claim status:', error);
        res.status(500).json({ error: 'Failed to update claim status', details: error.message });
    }
});

// Get videos for a specific claim
router.get('/claims/:claimId/videos', verifyToken, async (req, res) => {
    try {
        const { claimId } = req.params;
        
        // Check if the claimId contains a date format (like 20250325-5650)
        const isDateFormatted = /^\d{8}-\d+$/.test(claimId);
        
        // Construct the query based on the format of the claim ID
        let queryCondition;
        let replacements;
        
        if (isDateFormatted) {
            // If it's a date-formatted claim number, search by ClaimNumber
            queryCondition = 'c.ClaimNumber = :claimNumber';
            replacements = { claimNumber: claimId };
        } else {
            // Otherwise, assume it's a numeric ClaimId
            queryCondition = 'c.ClaimId = :claimId';
            replacements = { claimId: claimId };
        }

        // Fetch video records using the appropriate condition
        const videos = await db.sequelize.query(
            `SELECT sm.*
             FROM StreamMedia sm
             INNER JOIN Claims c ON sm.ClaimNumber = c.ClaimNumber
             WHERE ${queryCondition}
             AND sm.MediaType = 'video'
             ORDER BY sm.Timestamp DESC`,
            {
                replacements: replacements,
                type: db.Sequelize.QueryTypes.SELECT
            }
        );

        // Include the original S3 URL for pre-signed URL generation
        const modifiedVideos = videos.map(video => ({
            ...video,
            OriginalMediaUrl: video.MediaUrl,   // Store original URL separately
            MediaUrl: video.MediaUrl            // Use same URL (preserve for pre-signed URL handling)
        }));

        res.json(modifiedVideos);

    } catch (error) {
        console.error('Error fetching videos:', error);
        res.status(500).json({ error: 'Failed to fetch videos' });
    }
});


// Get screenshots for a specific claim
router.get('/claims/:claimId/screenshots', verifyToken, async (req, res) => {
    try {
        const { claimId } = req.params;
        
        // Check if the claimId contains a date format (like 20250325-5650)
        const isDateFormatted = /^\d{8}-\d+$/.test(claimId);
        
        // Construct the query based on the format of the claim ID
        let queryCondition;
        let replacements;
        
        if (isDateFormatted) {
            // If it's a date-formatted claim number, search by ClaimNumber
            queryCondition = 'c.ClaimNumber = :claimNumber';
            replacements = { claimNumber: claimId };
        } else {
            // Otherwise, assume it's a numeric ClaimId
            queryCondition = 'c.ClaimId = :claimId';
            replacements = { claimId: claimId };
        }

        // Fetch screenshot records using the appropriate condition
        const screenshots = await db.sequelize.query(
            `SELECT sm.*
             FROM StreamMedia sm
             INNER JOIN Claims c ON sm.ClaimNumber = c.ClaimNumber
             WHERE ${queryCondition}
             AND sm.MediaType = 'screenshot'
             ORDER BY sm.Timestamp DESC`,
            {
                replacements: replacements,
                type: db.Sequelize.QueryTypes.SELECT
            }
        );

        // Include the original S3 URL for pre-signed URL generation
        const modifiedScreenshots = screenshots.map(screenshot => ({
            ...screenshot,
            OriginalMediaUrl: screenshot.MediaUrl,  // Store original URL separately
            MediaUrl: screenshot.MediaUrl           // Use same URL (preserve for pre-signed URL handling)
        }));

        res.json(modifiedScreenshots);

    } catch (error) {
        console.error('Error fetching screenshots:', error);
        res.status(500).json({ error: 'Failed to fetch screenshots' });
    }
});

// Add a proxy endpoint to fetch media from S3
router.get('/media/proxy', async (req, res) => {
    try {
        const { url, token } = req.query;
        
        console.log('Media proxy request:', { url });
        
        if (!url) {
            return res.status(400).json({ message: 'URL parameter is required' });
        }
        
        // Verify token if provided, but make it optional
        if (token) {
            try {
                const decoded = jwt.verify(token, process.env.JWT_SECRET);
                req.user = decoded;
                console.log('Token verified successfully');
            } catch (err) {
                console.log('Invalid token in proxy request:', err.message);
                // Continue without authentication
            }
        }
        
        // Use a simpler approach - just forward the request directly to S3
        const fetch = require('node-fetch');
        
        console.log('Making direct request to:', url);
        
        // Make the request directly to the URL
        const response = await fetch(url);
        
        if (!response.ok) {
            console.error('Request failed:', { 
                status: response.status, 
                statusText: response.statusText 
            });
            return res.status(response.status).json({ 
                message: `Failed to fetch media: ${response.statusText}` 
            });
        }
        
        // Get content type and set appropriate headers
        const contentType = response.headers.get('content-type');
        if (contentType) {
            res.setHeader('Content-Type', contentType);
            console.log('Setting content type:', contentType);
        }
        
        // Set additional headers to prevent caching issues
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
        
        console.log('Streaming response to client');
        
        // Stream the response to the client
        response.body.pipe(res);
        
    } catch (error) {
        console.error('Media proxy error:', error);
        res.status(500).json({ message: error.message, stack: error.stack });
    }
});

// Download media directly from S3
router.get('/media/download/:mediaId', async (req, res) => {
    try {
        const { mediaId } = req.params;
        const { token } = req.query;
        
        console.log('Media download request for ID:', mediaId);
        
        // Verify token if provided
        if (token) {
            try {
                // Use the same secret as the verifyToken middleware
                const decoded = jwt.verify(token, config.secret);
                req.user = decoded;
                console.log('Token verified successfully');
            } catch (err) {
                console.log('Invalid token in download request:', err.message);
                return res.status(401).json({ message: 'Invalid token' });
            }
        } else {
            // Token is required
            return res.status(401).json({ message: 'Authentication token is required' });
        }
        
        // Fetch media record from StreamMedia table
        const mediaRecord = await db.sequelize.query(
            `SELECT * FROM StreamMedia WHERE MediaId = :mediaId`,
            {
                replacements: { mediaId },
                type: db.Sequelize.QueryTypes.SELECT
            }
        );
        
        if (!mediaRecord || mediaRecord.length === 0) {
            return res.status(404).json({ message: 'Media not found' });
        }
        
        const media = mediaRecord[0];
        const s3Url = media.MediaUrl;
        
        console.log('Media S3 URL:', s3Url);
        
        // Parse the S3 URL to get bucket and key
        const s3UrlPattern = /https:\/\/([^.]+)\.s3\.([^.]+)\.amazonaws\.com\/(.+)/;
        const match = s3Url.match(s3UrlPattern);
        
        if (!match) {
            console.log('Invalid S3 URL format:', s3Url);
            return res.status(400).json({ message: 'Invalid S3 URL format' });
        }
        
        const [, bucket, region, key] = match;
        console.log('Parsed S3 URL:', { bucket, region, key });
        
        // Load AWS SDK
        const { S3Client, GetObjectCommand } = require('@aws-sdk/client-s3');
        
        // Get AWS credentials from environment variables
        const AWS_ACCESS_KEY_ID = process.env.AWS_ACCESS_KEY_ID;
        const AWS_SECRET_ACCESS_KEY = process.env.AWS_SECRET_ACCESS_KEY;
        const AWS_REGION = process.env.AWS_REGION || 'eu-north-1';
        
        // Check if AWS credentials are available
        if (!AWS_ACCESS_KEY_ID || !AWS_SECRET_ACCESS_KEY) {
            console.error('AWS credentials are not configured');
            return res.status(500).json({ 
                message: 'AWS credentials are not configured in the server environment' 
            });
        }
        
        console.log('Using AWS region:', AWS_REGION);
        
        // Create S3 client
        const s3Client = new S3Client({
            region: AWS_REGION,
            credentials: {
                accessKeyId: AWS_ACCESS_KEY_ID,
                secretAccessKey: AWS_SECRET_ACCESS_KEY,
            },
        });
        
        // Create command to get object
        const command = new GetObjectCommand({
            Bucket: bucket,
            Key: key,
        });
        
        try {
            // Get the object from S3
            const s3Response = await s3Client.send(command);
            
            // Set content type header
            if (s3Response.ContentType) {
                res.setHeader('Content-Type', s3Response.ContentType);
            } else {
                // Set default content type based on media type
                res.setHeader('Content-Type', media.MediaType === 'video' ? 'video/webm' : 'image/jpeg');
            }
            
            // Set content disposition header for download
            const extension = media.MediaType === 'video' ? 'webm' : 'jpg';
            const filename = `${media.MediaType}-${media.MediaId}.${extension}`;
            res.setHeader('Content-Disposition', `inline; filename="${filename}"`);
            
            // Stream the response to the client
            s3Response.Body.pipe(res);
            
        } catch (s3Error) {
            console.error('Error getting object from S3:', s3Error);
            return res.status(500).json({ 
                message: 'Error retrieving media from S3', 
                error: s3Error.message 
            });
        }
        
    } catch (error) {
        console.error('Media download error:', error);
        res.status(500).json({ message: error.message });
    }
});

// Generate pre-signed URL for S3 objects
router.get('/media/presigned', verifyToken, async (req, res) => {
    try {
        const { s3Url } = req.query;
        
        if (!s3Url) {
            return res.status(400).json({ message: 'S3 URL is required' });
        }
        
        console.log('Generating pre-signed URL for:', s3Url);
        
        // Parse the S3 URL to get bucket and key
        const s3UrlPattern = /https:\/\/([^.]+)\.s3\.([^.]+)\.amazonaws\.com\/(.+)/;
        const match = s3Url.match(s3UrlPattern);
        
        if (!match) {
            console.log('Invalid S3 URL format:', s3Url);
            return res.status(400).json({ message: 'Invalid S3 URL format' });
        }
        
        const [, bucket, region, key] = match;
        console.log('Parsed S3 URL:', { bucket, region, key });
        
        // Load AWS SDK
        const { S3Client, GetObjectCommand } = require('@aws-sdk/client-s3');
        const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
        
        // Get AWS credentials from environment variables
        const AWS_ACCESS_KEY_ID = process.env.AWS_ACCESS_KEY_ID;
        const AWS_SECRET_ACCESS_KEY = process.env.AWS_SECRET_ACCESS_KEY;
        const AWS_REGION = process.env.AWS_REGION || 'eu-north-1';
        
        // Check if AWS credentials are available
        if (!AWS_ACCESS_KEY_ID || !AWS_SECRET_ACCESS_KEY) {
            console.error('AWS credentials are not configured');
            return res.status(500).json({ 
                message: 'AWS credentials are not configured in the server environment' 
            });
        }
        
        console.log('Using AWS region:', AWS_REGION);
        
        // Create S3 client
        const s3Client = new S3Client({
            region: AWS_REGION,
            credentials: {
                accessKeyId: AWS_ACCESS_KEY_ID,
                secretAccessKey: AWS_SECRET_ACCESS_KEY,
            },
        });
        
        // Create command to get object
        const command = new GetObjectCommand({
            Bucket: bucket,
            Key: key,
        });
        
        // Generate pre-signed URL
        const presignedUrl = await getSignedUrl(s3Client, command, { expiresIn: 3600 });
        
        res.json({ presignedUrl });
    } catch (error) {
        console.error('Pre-signed URL generation error:', error);
        res.status(500).json({ message: error.message });
    }
});

// Get claim counts by status
router.get('/claims/counts', verifyToken, async (req, res) => {
    try {
        // Get counts for each status
        const counts = {
            New: 0,
            Assigned: 0,
            Submitted: 0,
            Closed: 0
        };

        // Query for New claims
        const newClaimsQuery = `
            SELECT COUNT(*) AS count 
            FROM Claims 
            WHERE ClaimStatus = 'New'
        `;
        const [newClaimsResult] = await db.sequelize.query(newClaimsQuery, { type: QueryTypes.SELECT });
        counts.New = newClaimsResult.count;

        // Query for Assigned claims
        const assignedClaimsQuery = `
            SELECT COUNT(*) AS count 
            FROM Claims 
            WHERE ClaimStatus = 'Assigned'
        `;
        const [assignedClaimsResult] = await db.sequelize.query(assignedClaimsQuery, { type: QueryTypes.SELECT });
        counts.Assigned = assignedClaimsResult.count;

        // Query for Submitted claims (InvestigationCompleted)
        const submittedClaimsQuery = `
            SELECT COUNT(*) AS count 
            FROM Claims 
            WHERE ClaimStatus = 'InvestigationCompleted'
        `;
        const [submittedClaimsResult] = await db.sequelize.query(submittedClaimsQuery, { type: QueryTypes.SELECT });
        counts.Submitted = submittedClaimsResult.count;

        // Query for Closed claims
        const closedClaimsQuery = `
            SELECT COUNT(*) AS count 
            FROM Claims 
            WHERE ClaimStatus = 'Closed'
        `;
        const [closedClaimsResult] = await db.sequelize.query(closedClaimsQuery, { type: QueryTypes.SELECT });
        counts.Closed = closedClaimsResult.count;

        console.log('Claim counts:', counts);
        res.json(counts);
    } catch (error) {
        console.error('Error fetching claim counts:', error);
        res.status(500).json({ 
            message: 'Error fetching claim counts',
            error: error.message 
        });
    }
});

// Search claims by claim number
router.get('/claims/search', verifyToken, async (req, res) => {
    try {
        const { query } = req.query;
        
        if (!query) {
            return res.status(400).json({ message: 'Search query is required' });
        }
        
        console.log(`Searching for claims with query: ${query}`);
        
        // Search for claims that match the query in the claim number
        const searchQuery = `
            SELECT c.*, 
                   s.Id as SupervisorId, s.Name as SupervisorName, s.Email as SupervisorEmail, s.IsOnline as SupervisorOnline, s.LastLogin as SupervisorLastLogin,
                   i.Id as InvestigatorId, i.Name as InvestigatorName, i.Email as InvestigatorEmail
            FROM Claims c
            LEFT JOIN Users s ON c.SupervisorId = s.Id
            LEFT JOIN Users i ON c.InvestigatorId = i.Id
            WHERE c.ClaimNumber LIKE '%${query}%'
            ORDER BY c.CreatedAt DESC
        `;
        
        const claims = await db.sequelize.query(searchQuery, { type: QueryTypes.SELECT });
        
        if (claims.length === 0) {
            return res.json([]);
        }
        
        // Format the claims to match the expected structure
        const formattedClaims = claims.map(claim => {
            // Log the raw claim data to debug
            console.log('Raw claim data:', claim);
            
            return {
                id: claim.Id,
                ClaimId: claim.ClaimId,  // Make sure this is included
                claimNumber: claim.ClaimNumber,
                createdAt: claim.CreatedAt,
                vehicle: {
                    number: claim.VehicleNumber || 'N/A',
                    type: claim.VehicleType || 'N/A'
                },
                policy: {
                    number: claim.PolicyNumber || 'N/A',
                    insuredName: claim.InsuredName || 'N/A'
                },
                incident: {
                    dateOfIncident: claim.IncidentDate,
                    location: claim.IncidentLocation,
                    description: claim.Description,
                    supervisorNotes: claim.SupervisorNotes,
                    investigatorNotes: claim.InvestigatorNotes
                },
                status: claim.ClaimStatus,
                assignedAt: claim.AssignedAt,
                investigationId: claim.InvestigationId,
                investigator: claim.InvestigatorId ? {
                    id: claim.InvestigatorId,
                    name: claim.InvestigatorName,
                    email: claim.InvestigatorEmail
                } : null,
                supervisor: claim.SupervisorId ? {
                    id: claim.SupervisorId,
                    name: claim.SupervisorName,
                    email: claim.SupervisorEmail,
                    isOnline: claim.SupervisorOnline,
                    lastLogin: claim.SupervisorLastLogin,
                    notes: claim.SupervisorNotes
                } : null
            };
        });
        
        console.log(`Found ${formattedClaims.length} claims matching query: ${query}`);
        res.json(formattedClaims);
    } catch (error) {
        console.error('Error searching claims:', error);
        res.status(500).json({ 
            message: 'Error searching claims',
            error: error.message 
        });
    }
});

// Media download endpoint
router.get('/media/download/:mediaId', verifyToken, async (req, res) => {
    try {
        const { mediaId } = req.params;
        const { token } = req.query;
        
        if (!mediaId) {
            return res.status(400).json({ message: 'Media ID is required' });
        }
        
        console.log(`Attempting to download media with ID: ${mediaId}`);
        console.log('AWS Credentials:', {
            region: process.env.AWS_REGION,
            accessKeyId: process.env.AWS_ACCESS_KEY_ID ? 'Set' : 'Not set',
            secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY ? 'Set' : 'Not set',
            bucket: process.env.AWS_S3_BUCKET
        });
        
        // First check if this is a screenshot
        let screenshot;
        try {
            screenshot = await db.sequelize.query(
                `SELECT * FROM Screenshots WHERE MediaId = :mediaId`,
                {
                    replacements: { mediaId },
                    type: QueryTypes.SELECT
                }
            );
            console.log('Screenshot query result:', screenshot);
        } catch (dbError) {
            console.error('Error querying Screenshots table:', dbError);
            // Check if the table exists
            try {
                const tables = await db.sequelize.query(
                    `SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE'`,
                    { type: QueryTypes.SELECT }
                );
                console.log('Available tables:', tables.map(t => t.TABLE_NAME));
                
                // If Screenshots table exists, try to get its columns
                if (tables.some(t => t.TABLE_NAME === 'Screenshots')) {
                    const columns = await db.sequelize.query(
                        `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'Screenshots'`,
                        { type: QueryTypes.SELECT }
                    );
                    console.log('Screenshots table columns:', columns.map(c => c.COLUMN_NAME));
                }
            } catch (schemaError) {
                console.error('Error querying database schema:', schemaError);
            }
            
            // Continue with the flow, we'll check videos next
        }
        
        if (screenshot && screenshot.length > 0) {
            console.log(`Found screenshot with ID: ${mediaId}`);
            
            // Get the S3 URL from the database
            const s3Url = screenshot[0].MediaUrl;
            console.log(`Screenshot S3 URL: ${s3Url}`);
            
            if (!s3Url) {
                return res.status(404).json({ message: 'Screenshot URL not found' });
            }
            
            // Use the AWS SDK to get the file and stream it back
            const { S3Client, GetObjectCommand } = require('@aws-sdk/client-s3');
            
            // Configure AWS from environment variables
            const s3Client = new S3Client({
                region: process.env.AWS_REGION,
                credentials: {
                    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
                    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
                }
            });
            
            // Extract bucket and key from S3 URL
            const s3UrlParts = new URL(s3Url);
            const bucket = s3UrlParts.hostname.split('.')[0];
            const key = s3UrlParts.pathname.substring(1); // Remove leading slash
            
            console.log(`Fetching from S3 - Bucket: ${bucket}, Key: ${key}`);
            
            const params = {
                Bucket: bucket,
                Key: key
            };
            
            // Get the object
            const { Body } = await s3Client.send(new GetObjectCommand(params));
            
            // Set appropriate headers
            res.setHeader('Content-Type', 'image/jpeg');
            res.setHeader('Cache-Control', 'public, max-age=86400');
            
            try {
                // Stream the response
                const chunks = [];
                for await (const chunk of Body) {
                    chunks.push(chunk);
                }
                const buffer = Buffer.concat(chunks);
                res.send(buffer);
            } catch (err) {
                console.error(`Error streaming S3 object: ${err.message}`);
                // If the response hasn't been sent yet
                if (!res.headersSent) {
                    res.status(500).json({ message: 'Error fetching media from storage', error: err.message });
                }
            }
            
            return;
        }
        
        // If not a screenshot, check if it's a video
        let video;
        try {
            video = await db.sequelize.query(
                `SELECT * FROM Videos WHERE MediaId = :mediaId`,
                {
                    replacements: { mediaId },
                    type: QueryTypes.SELECT
                }
            );
            console.log('Video query result:', video);
        } catch (dbError) {
            console.error('Error querying Videos table:', dbError);
            // Check if the table exists
            try {
                const tables = await db.sequelize.query(
                    `SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE'`,
                    { type: QueryTypes.SELECT }
                );
                console.log('Available tables:', tables.map(t => t.TABLE_NAME));
                
                // If Videos table exists, try to get its columns
                if (tables.some(t => t.TABLE_NAME === 'Videos')) {
                    const columns = await db.sequelize.query(
                        `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'Videos'`,
                        { type: QueryTypes.SELECT }
                    );
                    console.log('Videos table columns:', columns.map(c => c.COLUMN_NAME));
                }
            } catch (schemaError) {
                console.error('Error querying database schema:', schemaError);
            }
            
            // If we get here, we couldn't find the media
            return res.status(404).json({ message: 'Media not found or database error', error: dbError.message });
        }
        
        if (video && video.length > 0) {
            console.log(`Found video with ID: ${mediaId}`);
            
            // Get the S3 URL from the database
            const s3Url = video[0].MediaUrl;
            console.log(`Video S3 URL: ${s3Url}`);
            
            if (!s3Url) {
                return res.status(404).json({ message: 'Video URL not found' });
            }
            
            // Use the AWS SDK to get the file and stream it back
            const { S3Client, GetObjectCommand } = require('@aws-sdk/client-s3');
            
            // Configure AWS from environment variables
            const s3Client = new S3Client({
                region: process.env.AWS_REGION,
                credentials: {
                    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
                    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
                }
            });
            
            // Extract bucket and key from S3 URL
            const s3UrlParts = new URL(s3Url);
            const bucket = s3UrlParts.hostname.split('.')[0];
            const key = s3UrlParts.pathname.substring(1); // Remove leading slash
            
            console.log(`Fetching from S3 - Bucket: ${bucket}, Key: ${key}`);
            
            const params = {
                Bucket: bucket,
                Key: key
            };
            
            // Get the object
            const { Body } = await s3Client.send(new GetObjectCommand(params));
            
            // Set appropriate headers
            res.setHeader('Content-Type', 'video/mp4');
            res.setHeader('Cache-Control', 'public, max-age=86400');
            
            try {
                // Stream the response
                const chunks = [];
                for await (const chunk of Body) {
                    chunks.push(chunk);
                }
                const buffer = Buffer.concat(chunks);
                res.send(buffer);
            } catch (err) {
                console.error(`Error streaming S3 object: ${err.message}`);
                // If the response hasn't been sent yet
                if (!res.headersSent) {
                    res.status(500).json({ message: 'Error fetching media from storage', error: err.message });
                }
            }
            
            return;
        }
        
        // If we get here, the media was not found
        return res.status(404).json({ message: 'Media not found' });
        
    } catch (error) {
        console.error('Error downloading media:', error);
        res.status(500).json({ 
            message: 'Error downloading media', 
            error: error.message 
        });
    }
});

// Simple media download endpoint that serves a placeholder image
router.get('/media/download/:mediaId', verifyToken, async (req, res) => {
    try {
        const { mediaId } = req.params;
        console.log(`Simplified media download endpoint called for ID: ${mediaId}`);
        
        // Set headers for image
        res.setHeader('Content-Type', 'image/jpeg');
        res.setHeader('Cache-Control', 'public, max-age=86400');
        
        // Send a simple placeholder image
        // This is a 1x1 transparent pixel in base64
        const base64Image = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=';
        const imageBuffer = Buffer.from(base64Image, 'base64');
        
        // Send the image
        res.send(imageBuffer);
    } catch (error) {
        console.error('Error in simplified media download endpoint:', error);
        res.status(500).json({ 
            message: 'Error serving media', 
            error: error.message 
        });
    }
});

module.exports = router;
