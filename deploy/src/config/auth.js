// JWT configuration
module.exports = {
    secret: process.env.JWT_SECRET || 'default-secret-key'
};
