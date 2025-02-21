const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const config = require('../config/auth');
const db = require('../models');
const { QueryTypes } = require('sequelize');
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
        const { status } = req.query;
        const claims = await db.Claim.findAll({
            where: status ? { ClaimStatus: status } : {},
            include: [{
                model: db.User,
                as: 'investigator',
                attributes: ['id', 'name', 'email', 'lastLogin']
            }, {
                model: db.User,
                as: 'supervisor',
                attributes: ['id', 'name', 'email']
            }],
            order: [['CreatedAt', 'DESC']]
        });
        res.json(claims);
    } catch (error) {
        console.error('Get claims error:', error);
        res.status(500).json({ message: error.message });
    }
});

// Get assigned claims for investigator
router.get('/claims/assigned', verifyToken, async (req, res) => {
    try {
        if (!req.user || !req.user.id) {
            return res.status(401).json({ message: 'User not authenticated' });
        }

        const claims = await db.sequelize.query(
            `SELECT c.*, 
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
             AND c.ClaimStatus IN ('Assigned', 'In Progress')
             ORDER BY c.createdAt DESC`,
            {
                replacements: { userId: req.user.id },
                type: QueryTypes.SELECT
            }
        );

        // Log the first raw claim from the database
        console.log('Raw claim from database:');
        console.log(JSON.stringify(claims[0], null, 2));

        const formattedClaims = claims.map(claim => ({
            id: claim.id,
            claimId: claim.ClaimId,
            vehicleInfo: {
                // Change these field names to match what's in your database
                make: claim.VehicleType ? claim.VehicleType.split(' ')[0] : '',
                model: claim.VehicleType ? claim.VehicleType.split(' ').slice(1).join(' ') : '',
                registrationNumber: claim.VehicleNumber
            },
            claimDetails: {
                // Add these fields from your database
                policyNumber: claim.PolicyNumber,
                insuredName: claim.InsuredName,
                // Keep the existing fields
                dateOfIncident: claim.IncidentDate,
                location: claim.IncidentLocation,
                description: claim.Description,
                // Add notes
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
                notes: claim.SupervisorNotes  // Added here as well for easier access
            } : null
        }));

        // Log the first formatted claim
        console.log('Formatted claim:');
        console.log(JSON.stringify(formattedClaims[0], null, 2));

        res.json(formattedClaims);
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
        const { claimNumber } = req.body;
        const supervisorId = req.user.id;

        // Format the date in SQL Server compatible format
        const currentDate = new Date().toISOString().slice(0, 19).replace('T', ' ');

        const [claim] = await db.sequelize.query(
            `INSERT INTO Claims 
             (ClaimNumber, ClaimStatus, SupervisorId, CreatedAt) 
             OUTPUT INSERTED.*
             VALUES (:claimNumber, 'New', :supervisorId, :createdAt)`,
            {
                replacements: {
                    claimNumber,
                    supervisorId,
                    createdAt: currentDate
                },
                type: QueryTypes.INSERT
            }
        );

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
                    c.SupervisorNotes, c.InvestigatorNotes,
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

module.exports = router;
