const { Sequelize, DataTypes } = require('sequelize');
const config = require('../../config/config.json')[process.env.NODE_ENV || 'development'];
const bcrypt = require('bcryptjs');

// Safely extract configuration with environment variable fallback
const dbConfig = {
    database: process.env.DB_NAME || config.database,
    username: process.env.DB_USER || config.username,
    password: process.env.DB_PASSWORD || config.password,
    server: process.env.DB_SERVER || config.server
};

// Initialize SQL Server database
const sequelize = new Sequelize(dbConfig.database, dbConfig.username, dbConfig.password, {
    host: dbConfig.server,
    port: 1433, // Explicitly set port for MSSQL
    dialect: 'mssql',
    dialectOptions: {
        options: {
            encrypt: true, // For Azure SQL
            trustServerCertificate: true,
            enableArithAbort: true,
            validateBulkLoadParameters: true
        }
    },
    pool: {
        max: 5,
        min: 0,
        acquire: 30000,
        idle: 10000
    },
    logging: console.log  // Change logging to log actual database queries for debugging
});

const db = {};

// User Model
db.User = sequelize.define('User', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    name: {
        type: DataTypes.STRING,
        allowNull: false
    },
    email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true
    },
    password: {
        type: DataTypes.STRING,
        allowNull: false
    },
    role: {
        type: DataTypes.STRING,
        allowNull: false
    },
    status: {
        type: DataTypes.STRING,
        allowNull: false,
        defaultValue: 'Active'
    },
    isOnline: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: false
    },
    lastLogin: {
        type: DataTypes.DATE,
        allowNull: true
    },
    createdAt: {
        type: DataTypes.DATE,
        field: 'createdAt',
        get() {
            return this.getDataValue('createdAt');
        },
        set(value) {
            if (value instanceof Date) {
                this.setDataValue('createdAt', value.toISOString().slice(0, 19).replace('T', ' '));
            } else {
                this.setDataValue('createdAt', value);
            }
        }
    },
    updatedAt: {
        type: DataTypes.DATE,
        field: 'updatedAt',
        get() {
            return this.getDataValue('updatedAt');
        },
        set(value) {
            if (value instanceof Date) {
                this.setDataValue('updatedAt', value.toISOString().slice(0, 19).replace('T', ' '));
            } else {
                this.setDataValue('updatedAt', value);
            }
        }
    }
}, {
    tableName: 'Users',
    timestamps: true
});

// Claims Model
db.Claim = sequelize.define('Claim', {
    ClaimId: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    ClaimNumber: {
        type: DataTypes.STRING(50),
        allowNull: false
    },
    VehicleNumber: {
        type: DataTypes.STRING(50)
    },
    VehicleType: {
        type: DataTypes.STRING(50)
    },
    PolicyNumber: {
        type: DataTypes.STRING(50)
    },
    InsuredName: {
        type: DataTypes.STRING(100)
    },
    ClaimStatus: {
        type: DataTypes.STRING(20)
    },
    SupervisorId: {
        type: DataTypes.INTEGER
    },
    InvestigatorId: {
        type: DataTypes.INTEGER
    },
    CreatedAt: {
        type: DataTypes.DATE
    },
    AssignedAt: {
        type: DataTypes.DATE
    },
    CompletedAt: {
        type: DataTypes.DATE
    },
    ClosedAt: {
        type: DataTypes.DATE
    },
    SupervisorNotes: {
        type: DataTypes.TEXT
    },
    InvestigatorNotes: {
        type: DataTypes.TEXT
    }
}, {
    tableName: 'Claims',
    timestamps: false
});

// Relationships
db.Claim.belongsTo(db.User, { as: 'investigator', foreignKey: 'InvestigatorId' });
db.Claim.belongsTo(db.User, { as: 'supervisor', foreignKey: 'SupervisorId' });

// Initialize database
db.initialize = async () => {
    try {
        // Set environment if not set
        process.env.NODE_ENV = process.env.NODE_ENV || 'development';
        
        console.log('Environment:', process.env.NODE_ENV);
        console.log('Database Server:', dbConfig.server);
        console.log('Database Name:', dbConfig.database);
        
        // Test the connection
        await sequelize.authenticate();
        console.log('Database connection established successfully');
        
        // Sync models (this won't recreate tables)
        await sequelize.sync({ alter: false });
        console.log('Models synchronized with database');
        
        // Check if we have any users
        const userCount = await db.User.count();
        if (userCount === 0) {
            // Create test users
            await db.User.bulkCreate([
                {
                    name: 'Supervisor',
                    email: 'supervisor@test.com',
                    password: await bcrypt.hash('password', 10),
                    role: 'SUPERVISOR',
                    status: 'ACTIVE',
                    createdAt: new Date()
                },
                {
                    name: 'Investigator 1',
                    email: 'investigator1@test.com',
                    password: await bcrypt.hash('password', 10),
                    role: 'INVESTIGATOR',
                    status: 'ACTIVE',
                    createdAt: new Date()
                },
                {
                    name: 'Investigator 2',
                    email: 'investigator2@test.com',
                    password: await bcrypt.hash('password', 10),
                    role: 'INVESTIGATOR',
                    status: 'ACTIVE',
                    createdAt: new Date()
                }
            ]);
            console.log('Test users created');
        }
    } catch (error) {
        console.error('Database initialization error:', error);
        throw error;
    }
};

db.sequelize = sequelize;
db.Sequelize = Sequelize;

module.exports = db;
