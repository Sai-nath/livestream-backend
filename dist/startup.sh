#!/bin/bash

# Navigate to the project directory
cd /home/site/wwwroot

echo "Current directory: $(pwd)"
echo "Listing directory contents:"
ls -la

# Clean install
echo "Cleaning npm cache..."
npm cache clean --force

echo "Removing existing node_modules..."
rm -rf node_modules

echo "Installing dependencies..."
npm install --production

# Set production environment
export NODE_ENV=production

echo "Listing installed dependencies:"
npm list --depth=0

echo "Starting server..."
node src/server.js
