#!/usr/bin/env node
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

// Simple .env loader
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
  const envConfig = fs.readFileSync(envPath, 'utf8');
  envConfig.split('\n').forEach(line => {
    const [key, value] = line.split('=');
    if (key && value) {
      process.env[key.trim()] = value.trim();
    }
  });
}

const pythonScript = path.join(__dirname, 'scanner.py');

function runScanner(args) {
  const pythonExecutable = process.platform === 'win32' ? 'python' : 'python3';
  
  // Combine CLI args with environment variables
  const finalArgs = [pythonScript, ...args];
  
  if (process.env.ROUTER_RSSI_SOURCE && !args.includes('--router-rssi-source')) {
    finalArgs.push('--router-rssi-source', process.env.ROUTER_RSSI_SOURCE);
  }
  if (process.env.ROUTER_RSSI_USER && !args.includes('--router-rssi-user')) {
    finalArgs.push('--router-rssi-user', process.env.ROUTER_RSSI_USER);
  }
  if (process.env.ROUTER_RSSI_PASSWORD && !args.includes('--router-rssi-password')) {
    finalArgs.push('--router-rssi-password', process.env.ROUTER_RSSI_PASSWORD);
  }
  if (process.env.VENDOR_DB && !args.includes('--vendor-db')) {
    finalArgs.push('--vendor-db', process.env.VENDOR_DB);
  }
  if (process.env.KNOWN_DEVICES_FILE && !args.includes('--known-devices-file')) {
    finalArgs.push('--known-devices-file', process.env.KNOWN_DEVICES_FILE);
  }
  if (process.env.HISTORY_FILE && !args.includes('--history-file')) {
    finalArgs.push('--history-file', process.env.HISTORY_FILE);
  }

  const child = spawn(pythonExecutable, finalArgs, {
    stdio: 'inherit'
  });

  child.on('close', (code) => {
    if (code !== 0 && code !== 130) {
      console.error(`Scanner exited with code ${code}`);
    }
    process.exit(code);
  });

  // Handle Ctrl+C
  process.on('SIGINT', () => {
    child.kill('SIGINT');
  });
}

const userArgs = process.argv.slice(2);
runScanner(userArgs);
