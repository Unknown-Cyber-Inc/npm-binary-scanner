#!/usr/bin/env node
/**
 * Generate GitHub Actions summary report for npm-package-scanner
 * Outputs to GITHUB_STEP_SUMMARY with links to UnknownCyber reports
 */

const fs = require('fs');
const path = require('path');

const UC_BASE = 'https://unknowncyber.com/files';

function makeLink(file, sha256) {
  if (sha256) {
    return `[${file}](${UC_BASE}/${sha256}/report/)`;
  }
  return file;
}

function generateBinarySummary(results) {
  let output = '';
  
  // Header
  output += '## 🔍 NPM Package Scan Results\n\n';
  
  // Packages scanned
  output += '### 📦 Packages Scanned\n';
  output += '| Metric | Count |\n';
  output += '|--------|-------|\n';
  output += `| Packages with binaries | ${results.totalPackages || 0} |\n`;
  output += `| Binary files found | ${results.totalBinaries || 0} |\n`;
  output += '\n';
  
  // Upload results
  if (results.uploadResults) {
    const ur = results.uploadResults;
    output += '### ☁️ Upload Results\n';
    output += '| Status | Count |\n';
    output += '|--------|-------|\n';
    output += `| ✅ Uploaded | ${ur.successful?.length || 0} |\n`;
    output += `| ⏭️ Skipped (existing) | ${ur.skipped?.length || 0} |\n`;
    output += `| ❌ Failed | ${ur.failed?.length || 0} |\n`;
    output += '\n';
    
    // Security findings
    const reps = ur.reputations || [];
    const high = reps.filter(r => r.reputation?.overallThreatLevel === 'high');
    const medium = reps.filter(r => r.reputation?.overallThreatLevel === 'medium');
    const caution = reps.filter(r => r.reputation?.overallThreatLevel === 'caution');
    
    if (high.length > 0 || medium.length > 0 || caution.length > 0) {
      output += '### 🛡️ Security Findings\n\n';
      
      if (high.length > 0) {
        output += '#### 🔴 High Severity\n';
        output += '| File | Issue |\n|------|-------|\n';
        high.forEach(r => {
          const issues = [];
          if (r.reputation?.av?.threatLevel === 'high') {
            issues.push(`AV: ${r.reputation.av.detected}/${r.reputation.av.total}`);
          }
          if (r.reputation?.similarity?.threatLevel === 'high') {
            issues.push(`Similarity: ${r.reputation.similarity.score}`);
          }
          output += `| ${makeLink(r.file, r.sha256)} | ${issues.join(', ')} |\n`;
        });
        output += '\n';
      }
      
      if (medium.length > 0) {
        output += '#### 🟠 Medium Severity\n';
        output += '| File | Issue |\n|------|-------|\n';
        medium.forEach(r => {
          const issues = [];
          if (r.reputation?.av?.threatLevel === 'medium') {
            issues.push(`AV: ${r.reputation.av.detected}/${r.reputation.av.total}`);
          }
          if (r.reputation?.similarity?.threatLevel === 'medium') {
            issues.push(`Similarity: ${r.reputation.similarity.score}`);
          }
          output += `| ${makeLink(r.file, r.sha256)} | ${issues.join(', ')} |\n`;
        });
        output += '\n';
      }
      
      if (caution.length > 0) {
        output += '#### 🟡 Caution\n';
        output += '| File | Issue |\n|------|-------|\n';
        caution.forEach(r => {
          const issues = [];
          if (r.reputation?.signature?.threatLevel === 'caution') {
            issues.push('Unsigned binary');
          }
          if (r.reputation?.av?.threatLevel === 'caution') {
            issues.push(`AV: ${r.reputation.av.detected}/${r.reputation.av.total}`);
          }
          output += `| ${makeLink(r.file, r.sha256)} | ${issues.join(', ')} |\n`;
        });
        output += '\n';
      }
    } else if (reps.length > 0) {
      output += '### 🛡️ Security Findings\n\n';
      output += '✅ No security issues detected\n\n';
    }
  }
  
  return output;
}

function generateYaraSummary(yaraResults) {
  let output = '';
  
  if (!yaraResults.results || yaraResults.results.length === 0) {
    return output;
  }
  
  output += '### 🔎 YARA Matches\n';
  output += '| File | Rule | Severity |\n';
  output += '|------|------|----------|\n';
  
  yaraResults.results.forEach(r => {
    const fileName = r.file.split('/').slice(-2).join('/');
    const fileLink = r.sha256 ? makeLink(fileName, r.sha256) : fileName;
    
    r.matches.forEach(m => {
      const sev = m.meta?.severity || 'unknown';
      const icon = (sev === 'critical' || sev === 'high') ? '🔴' : sev === 'medium' ? '🟠' : '🟡';
      output += `| ${fileLink} | ${m.rule} | ${icon} ${sev} |\n`;
    });
  });
  
  output += '\n';
  return output;
}

function main() {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  
  if (!summaryPath) {
    console.log('GITHUB_STEP_SUMMARY not set, outputting to console');
  }
  
  let output = '';
  
  // Binary scan results
  const binaryResultsPath = 'binary-scan-results.json';
  if (fs.existsSync(binaryResultsPath)) {
    try {
      const results = JSON.parse(fs.readFileSync(binaryResultsPath, 'utf8'));
      output += generateBinarySummary(results);
    } catch (e) {
      console.error('Error parsing binary-scan-results.json:', e.message);
    }
  }
  
  // YARA results
  const yaraResultsPath = 'yara-results.json';
  if (fs.existsSync(yaraResultsPath)) {
    try {
      const yaraResults = JSON.parse(fs.readFileSync(yaraResultsPath, 'utf8'));
      output += generateYaraSummary(yaraResults);
    } catch (e) {
      console.error('Error parsing yara-results.json:', e.message);
    }
  }
  
  // Output
  if (summaryPath) {
    fs.appendFileSync(summaryPath, output);
    console.log('Summary written to GITHUB_STEP_SUMMARY');
  } else {
    console.log('\n--- Summary Output ---\n');
    console.log(output);
  }
}

main();
