#!/usr/bin/env node
/**
 * Upload files that matched YARA rules to UnknownCyber
 * This ensures all security-relevant files are available in UC for detailed analysis
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');
const http = require('http');

const UC_REPORT_BASE = 'https://unknowncyber.com/files';

/**
 * Compute SHA256 hash of a file
 */
function computeHash(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', data => hash.update(data));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

/**
 * Check if file exists in UnknownCyber
 */
async function checkFileExists(apiUrl, apiKey, sha256) {
  return new Promise((resolve) => {
    const url = new URL(`${apiUrl}/files/${sha256}/?key=${apiKey}`);
    const client = url.protocol === 'https:' ? https : http;
    
    const req = client.request(url, { method: 'GET' }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        resolve(res.statusCode === 200);
      });
    });
    
    req.on('error', () => resolve(false));
    req.end();
  });
}

/**
 * Upload file to UnknownCyber
 */
async function uploadFile(apiUrl, apiKey, filePath, tags) {
  return new Promise((resolve, reject) => {
    const boundary = '----FormBoundary' + crypto.randomBytes(16).toString('hex');
    const filename = path.basename(filePath);
    const fileContent = fs.readFileSync(filePath);
    
    // Build URL with tags
    const url = new URL(`${apiUrl}/files/?key=${apiKey}`);
    tags.forEach(tag => url.searchParams.append('tags[]', tag));
    
    // Build multipart form data
    let body = '';
    
    // File part
    body += `--${boundary}\r\n`;
    body += `Content-Disposition: form-data; name="filedata"; filename="${filename}"\r\n`;
    body += 'Content-Type: application/octet-stream\r\n\r\n';
    
    const bodyStart = Buffer.from(body, 'utf-8');
    const bodyEnd = Buffer.from(`\r\n`, 'utf-8');
    
    // Tag parts
    let tagParts = '';
    tags.forEach(tag => {
      tagParts += `--${boundary}\r\n`;
      tagParts += `Content-Disposition: form-data; name="tags"\r\n\r\n`;
      tagParts += `${tag}\r\n`;
    });
    
    const tagBuffer = Buffer.from(tagParts, 'utf-8');
    const endBoundary = Buffer.from(`--${boundary}--\r\n`, 'utf-8');
    
    const fullBody = Buffer.concat([bodyStart, fileContent, bodyEnd, tagBuffer, endBoundary]);
    
    const client = url.protocol === 'https:' ? https : http;
    
    const req = client.request(url, {
      method: 'POST',
      headers: {
        'Content-Type': `multipart/form-data; boundary=${boundary}`,
        'Content-Length': fullBody.length
      }
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve({ success: true, status: res.statusCode });
        } else {
          resolve({ success: false, status: res.statusCode, error: data });
        }
      });
    });
    
    req.on('error', (err) => {
      resolve({ success: false, error: err.message });
    });
    
    req.write(fullBody);
    req.end();
  });
}

/**
 * Add tags to existing file
 */
async function addTagsToFile(apiUrl, apiKey, sha256, tags) {
  const results = [];
  
  for (const tag of tags) {
    const result = await new Promise((resolve) => {
      const boundary = '----FormBoundary' + crypto.randomBytes(16).toString('hex');
      const url = new URL(`${apiUrl}/files/${sha256}/tags/?key=${apiKey}`);
      
      let body = `--${boundary}\r\n`;
      body += `Content-Disposition: form-data; name="name"\r\n\r\n`;
      body += `${tag}\r\n`;
      body += `--${boundary}--\r\n`;
      
      const client = url.protocol === 'https:' ? https : http;
      
      const req = client.request(url, {
        method: 'POST',
        headers: {
          'Content-Type': `multipart/form-data; boundary=${boundary}`,
          'Content-Length': Buffer.byteLength(body)
        }
      }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          resolve({ success: res.statusCode >= 200 && res.statusCode < 300 });
        });
      });
      
      req.on('error', () => resolve({ success: false }));
      req.write(body);
      req.end();
    });
    
    results.push(result);
  }
  
  return results.every(r => r.success);
}

async function main() {
  const args = process.argv.slice(2);
  
  // Parse arguments
  let yaraResultsPath = 'yara-results.json';
  let binaryResultsPath = 'binary-scan-results.json';
  let nodeModulesPath = 'node_modules';
  let apiUrl = process.env.UC_API_URL || 'https://api.unknowncyber.com/v2';
  let apiKey = process.env.UC_API_KEY || '';
  let repo = process.env.UC_REPO || '';
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--yara-results') yaraResultsPath = args[++i];
    else if (args[i] === '--binary-results') binaryResultsPath = args[++i];
    else if (args[i] === '--node-modules') nodeModulesPath = args[++i];
    else if (args[i] === '--api-url') apiUrl = args[++i];
    else if (args[i] === '--api-key') apiKey = args[++i];
    else if (args[i] === '--repo') repo = args[++i];
  }
  
  // Read YARA results
  if (!fs.existsSync(yaraResultsPath)) {
    console.log('No YARA results found, nothing to upload');
    process.exit(0);
  }
  
  const yaraResults = JSON.parse(fs.readFileSync(yaraResultsPath, 'utf-8'));
  
  if (!yaraResults.results || yaraResults.results.length === 0) {
    console.log('No YARA matches found, nothing to upload');
    process.exit(0);
  }
  
  console.log(`\n=== Uploading YARA-matched files ===`);
  console.log(`Files with YARA matches: ${yaraResults.results.length}`);
  
  if (!apiKey) {
    console.log('No API key provided, skipping uploads');
    // Still add hashes for linking
    await addHashesToResults(yaraResults, nodeModulesPath);
    fs.writeFileSync(yaraResultsPath, JSON.stringify(yaraResults, null, 2));
    process.exit(0);
  }
  
  // Read existing binary results to avoid re-uploading
  let existingHashes = new Set();
  if (fs.existsSync(binaryResultsPath)) {
    const binaryResults = JSON.parse(fs.readFileSync(binaryResultsPath, 'utf-8'));
    if (binaryResults.files) {
      binaryResults.files.forEach(f => {
        if (f.sha256) existingHashes.add(f.sha256);
      });
    }
    if (binaryResults.uploadResults?.uploaded) {
      binaryResults.uploadResults.uploaded.forEach(u => {
        if (u.sha256) existingHashes.add(u.sha256);
      });
    }
  }
  
  let uploaded = 0;
  let tagged = 0;
  let failed = 0;
  
  for (const result of yaraResults.results) {
    const filePath = path.join(nodeModulesPath, result.file);
    
    if (!fs.existsSync(filePath)) {
      console.log(`  [!] File not found: ${result.file}`);
      failed++;
      continue;
    }
    
    // Compute hash
    const sha256 = await computeHash(filePath);
    result.sha256 = sha256;
    result.reportUrl = `${UC_REPORT_BASE}/${sha256}/report/`;
    
    // Determine package info from path
    const pathParts = result.file.split(/[\/\\]/);
    let packageName = pathParts[0];
    let packageVersion = 'unknown';
    
    // Handle scoped packages
    if (packageName.startsWith('@') && pathParts.length > 1) {
      packageName = `${pathParts[0]}/${pathParts[1]}`;
    }
    
    // Try to get version from package.json
    const packageJsonPath = path.join(nodeModulesPath, packageName, 'package.json');
    if (fs.existsSync(packageJsonPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
        packageVersion = pkg.version || 'unknown';
      } catch (e) {}
    }
    
    // Build tags
    const tags = [`SW_npm/${packageName}_${packageVersion}`];
    if (repo) {
      tags.push(`REPO_${repo}`);
    }
    tags.push('YARA_MATCH');
    
    result.tags = tags;
    
    // Check if already uploaded
    if (existingHashes.has(sha256)) {
      console.log(`  [=] Already uploaded: ${result.file}`);
      // Still try to add YARA_MATCH tag
      await addTagsToFile(apiUrl, apiKey, sha256, ['YARA_MATCH']);
      tagged++;
      continue;
    }
    
    // Check if exists in UC
    const exists = await checkFileExists(apiUrl, apiKey, sha256);
    
    if (exists) {
      console.log(`  [+] Tagging existing: ${result.file}`);
      const tagResult = await addTagsToFile(apiUrl, apiKey, sha256, tags);
      if (tagResult) {
        tagged++;
      } else {
        failed++;
      }
    } else {
      console.log(`  [↑] Uploading: ${result.file}`);
      const uploadResult = await uploadFile(apiUrl, apiKey, filePath, tags);
      if (uploadResult.success) {
        uploaded++;
      } else {
        console.log(`      Failed: ${uploadResult.error || uploadResult.status}`);
        failed++;
      }
    }
  }
  
  // Save updated YARA results with hashes
  fs.writeFileSync(yaraResultsPath, JSON.stringify(yaraResults, null, 2));
  
  console.log(`\n=== YARA Upload Summary ===`);
  console.log(`Uploaded: ${uploaded}`);
  console.log(`Tagged existing: ${tagged}`);
  console.log(`Failed: ${failed}`);
  
  // Output for GitHub Actions
  console.log(`\nyara-uploaded=${uploaded}`);
  console.log(`yara-tagged=${tagged}`);
}

async function addHashesToResults(yaraResults, nodeModulesPath) {
  for (const result of yaraResults.results) {
    const filePath = path.join(nodeModulesPath, result.file);
    if (fs.existsSync(filePath)) {
      result.sha256 = await computeHash(filePath);
      result.reportUrl = `${UC_REPORT_BASE}/${result.sha256}/report/`;
    }
  }
}

main().catch(err => {
  console.error('Error:', err);
  process.exit(1);
});
