#!/usr/bin/env node

/**
 * Quick test script to verify API upload functionality
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const { URL } = require('url');

const API_URL = process.argv[2] || 'https://api.unknowncyber.com';
const API_KEY = process.argv[3] || '';

// Test file - first .exe we find
const testFile = 'node_modules/@esbuild/win32-x64/esbuild.exe';

if (!API_KEY) {
  console.log('Usage: node test-upload.js <api-url> <api-key>');
  process.exit(1);
}

if (!fs.existsSync(testFile)) {
  console.log(`Test file not found: ${testFile}`);
  process.exit(1);
}

console.log('Testing UnknownCyber API upload...');
console.log(`API URL: ${API_URL}`);
console.log(`Test file: ${testFile}`);
console.log(`File size: ${fs.statSync(testFile).size} bytes`);
console.log('');

function generateBoundary() {
  return '----FormBoundary' + Math.random().toString(36).substring(2);
}

function buildMultipartBody(boundary, fields, fileField) {
  const parts = [];
  
  for (const [name, value] of Object.entries(fields)) {
    parts.push(
      `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="${name}"\r\n\r\n` +
      `${value}\r\n`
    );
  }
  
  if (fileField) {
    const fileContent = fs.readFileSync(fileField.path);
    parts.push(
      `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="${fileField.name}"; filename="${fileField.filename}"\r\n` +
      `Content-Type: application/octet-stream\r\n\r\n`
    );
    parts.push(fileContent);
    parts.push('\r\n');
  }
  
  parts.push(`--${boundary}--\r\n`);
  
  return Buffer.concat(parts.map(part => 
    typeof part === 'string' ? Buffer.from(part) : part
  ));
}

const boundary = generateBoundary();

const queryParams = new URLSearchParams({
  key: API_KEY,
  skip_unpack: 'false',
  extract: 'true',
  recursive: 'true',
  retain_wrapper: 'true',
  no_links: 'true'
});

const url = new URL(`${API_URL}/v2/files?${queryParams.toString()}`);

const fields = {
  filename: '@esbuild/win32-x64/esbuild.exe',
  tags: 'SW_@esbuild/win32-x64@0.20.2',
  notes: 'Test upload from npm-binary-scanner',
  password: ''
};

console.log('Form fields:');
console.log(JSON.stringify(fields, null, 2));
console.log('');

const body = buildMultipartBody(boundary, fields, {
  name: 'filedata',
  filename: 'esbuild.exe',
  path: testFile
});

console.log(`Request URL: ${url.href}`);
console.log(`Body size: ${body.length} bytes`);
console.log('');

const options = {
  hostname: url.hostname,
  port: 443,
  path: url.pathname + url.search,
  method: 'POST',
  headers: {
    'Content-Type': `multipart/form-data; boundary=${boundary}`,
    'Content-Length': body.length
  }
};

console.log('Sending request...');

const req = https.request(options, (res) => {
  console.log(`\nResponse status: ${res.statusCode} ${res.statusMessage}`);
  console.log('Response headers:', JSON.stringify(res.headers, null, 2));
  
  let data = '';
  res.on('data', chunk => data += chunk);
  res.on('end', () => {
    console.log('\nResponse body:');
    try {
      console.log(JSON.stringify(JSON.parse(data), null, 2));
    } catch {
      console.log(data);
    }
  });
});

req.on('error', (err) => {
  console.error('Request error:', err);
});

req.write(body);
req.end();

