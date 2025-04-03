/**
 * Azure Web App Deployment Script
 * 
 * This script uses the Azure publish profile credentials to deploy the backend application
 * to the Azure Web App service using the Zip Deploy method.
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const { execSync } = require('child_process');

// Azure deployment settings
const deploymentSettings = {
  publishUrl: 'livestreaming-fjghamgvdsdbd7ct.scm.centralindia-01.azurewebsites.net:443',
  userName: '$livestreaming',
  password: 'ErSYZRunEhCTdt4tDuD2fZQdhQmzyPPqZZA1cfMxd7jSNGoK3rhtPdg9XkFf',
  siteName: 'livestreaming',
  deployMethod: 'ZipDeploy'
};

// Create a temporary directory for the deployment package
const tempDir = path.join(__dirname, 'deploy-temp');
if (!fs.existsSync(tempDir)) {
  fs.mkdirSync(tempDir);
}

// Function to create deployment package
async function createDeploymentPackage() {
  console.log('Creating deployment package...');
  
  try {
    // Copy necessary files to temp directory
    const filesToExclude = [
      'node_modules',
      '.git',
      '.github',
      '.vscode',
      'deploy-temp',
      'deploy.js'
    ];
    
    // Copy .env.production to .env
    fs.copyFileSync(
      path.join(__dirname, '.env.production'),
      path.join(tempDir, '.env')
    );
    
    // Copy package.json and package-lock.json
    fs.copyFileSync(
      path.join(__dirname, 'package.json'),
      path.join(tempDir, 'package.json')
    );
    
    if (fs.existsSync(path.join(__dirname, 'package-lock.json'))) {
      fs.copyFileSync(
        path.join(__dirname, 'package-lock.json'),
        path.join(tempDir, 'package-lock.json')
      );
    }
    
    // Copy src directory
    copyDirectory(
      path.join(__dirname, 'src'),
      path.join(tempDir, 'src'),
      filesToExclude
    );
    
    // Create web.config for Azure
    const webConfig = `<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.webServer>
    <webSocket enabled="true" />
    <handlers>
      <add name="iisnode" path="src/server.js" verb="*" modules="iisnode"/>
    </handlers>
    <rewrite>
      <rules>
        <rule name="StaticContent">
          <action type="Rewrite" url="public{REQUEST_URI}"/>
        </rule>
        <rule name="DynamicContent">
          <conditions>
            <add input="{REQUEST_FILENAME}" matchType="IsFile" negate="True"/>
          </conditions>
          <action type="Rewrite" url="src/server.js"/>
        </rule>
      </rules>
    </rewrite>
    <iisnode watchedFiles="web.config;*.js" node_env="production" />
  </system.webServer>
</configuration>`;
    
    fs.writeFileSync(path.join(tempDir, 'web.config'), webConfig);
    
    // Create zip file
    console.log('Creating zip archive...');
    execSync(`cd "${tempDir}" && zip -r ../deploy.zip .`);
    
    console.log('Deployment package created successfully.');
    return path.join(__dirname, 'deploy.zip');
  } catch (error) {
    console.error('Error creating deployment package:', error);
    throw error;
  }
}

// Function to copy directory recursively
function copyDirectory(source, destination, excludes) {
  if (!fs.existsSync(destination)) {
    fs.mkdirSync(destination, { recursive: true });
  }
  
  const files = fs.readdirSync(source);
  
  for (const file of files) {
    if (excludes.includes(file)) continue;
    
    const sourcePath = path.join(source, file);
    const destPath = path.join(destination, file);
    
    const stat = fs.statSync(sourcePath);
    
    if (stat.isDirectory()) {
      copyDirectory(sourcePath, destPath, excludes);
    } else {
      fs.copyFileSync(sourcePath, destPath);
    }
  }
}

// Function to deploy to Azure
async function deployToAzure(zipFilePath) {
  console.log('Deploying to Azure...');
  
  const { publishUrl, userName, password } = deploymentSettings;
  const auth = Buffer.from(`${userName}:${password}`).toString('base64');
  
  const zipContent = fs.readFileSync(zipFilePath);
  
  const options = {
    hostname: publishUrl.split(':')[0],
    port: 443,
    path: '/api/zipdeploy',
    method: 'POST',
    headers: {
      'Content-Type': 'application/zip',
      'Content-Length': zipContent.length,
      'Authorization': `Basic ${auth}`
    }
  };
  
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      console.log(`Status Code: ${res.statusCode}`);
      
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          console.log('Deployment successful!');
          console.log(`Your app is now available at: https://livestreaming-fjghamgvdsdbd7ct.centralindia-01.azurewebsites.net`);
          resolve();
        } else {
          console.error('Deployment failed:', data);
          reject(new Error(`Deployment failed with status code ${res.statusCode}`));
        }
      });
    });
    
    req.on('error', (error) => {
      console.error('Error during deployment:', error);
      reject(error);
    });
    
    req.write(zipContent);
    req.end();
  });
}

// Main function
async function main() {
  try {
    const zipFilePath = await createDeploymentPackage();
    await deployToAzure(zipFilePath);
    
    // Clean up
    console.log('Cleaning up temporary files...');
    fs.rmSync(tempDir, { recursive: true, force: true });
    fs.unlinkSync(zipFilePath);
    
    console.log('Deployment process completed successfully.');
  } catch (error) {
    console.error('Deployment failed:', error);
    process.exit(1);
  }
}

// Run the deployment
main();
