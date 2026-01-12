#!/usr/bin/env node
/**
 * Create a demo repository showing npm-package-scanner evolution
 * Simulates package evolution over 6 time periods with backdated commits
 * 
 * Usage:
 *   node create-demo.js [target-dir] [--repo-name=<name>]
 * 
 * Examples:
 *   node create-demo.js ../my-demo
 *   node create-demo.js ../my-demo --repo-name=my-scanner-demo
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Parse command line arguments
function parseArgs() {
  const args = process.argv.slice(2);
  let targetDir = '../npm-scanner-demo';
  let repoName = 'npm-scanner-demo';
  let githubOrg = 'Unknown-Cyber-Inc';
  
  for (const arg of args) {
    if (arg.startsWith('--repo-name=')) {
      repoName = arg.split('=')[1];
    } else if (arg.startsWith('--org=')) {
      githubOrg = arg.split('=')[1];
    } else if (!arg.startsWith('--')) {
      targetDir = arg;
    }
  }
  
  return { targetDir, repoName, githubOrg };
}

const CONFIG = parseArgs();

// Demo releases - each represents a point in time
const RELEASES = [
  {
    date: '2025-01-15',
    tag: 'v1.0.0',
    message: 'Initial release - basic tooling setup',
    packages: {
      'esbuild': '0.24.2',           // Version from late 2024
      'lodash': '4.17.21',           // Stable, no known vulns
      'source-map': '0.7.4',         // Stable
    }
  },
  {
    date: '2025-03-01',
    tag: 'v1.1.0',
    message: 'Add rollup for bundling',
    packages: {
      'esbuild': '0.25.0',
      'rollup': '4.12.0',
      'lodash': '4.17.21',
      'source-map': '0.7.4',
    }
  },
  {
    date: '2025-05-01',
    tag: 'v1.2.0',
    message: 'Add SWC compiler and eslint-config-prettier',
    packages: {
      'esbuild': '0.25.4',
      'rollup': '4.18.0',
      '@swc/core': '1.5.0',
      'eslint-config-prettier': '10.1.2',
      'lodash': '4.17.21',
      'source-map': '0.7.4',
    }
  },
  {
    date: '2025-07-01',
    tag: 'v1.3.0',
    message: 'Add Sentry CLI, update eslint-config-prettier',
    packages: {
      'esbuild': '0.25.8',
      'rollup': '4.18.0',
      '@swc/core': '1.6.0',
      '@sentry/cli': '2.41.1',
      'eslint-config-prettier': '10.1.5',
      'lodash': '4.17.21',
      'source-map': '0.7.4',
    }
  },
  {
    date: '2025-09-01',
    tag: 'v1.4.0',
    message: 'Add minimist (vulnerable version for demo)',
    packages: {
      'esbuild': '0.25.10',
      'rollup': '4.18.0',
      '@swc/core': '1.7.0',
      '@sentry/cli': '2.41.1',
      'eslint-config-prettier': '10.1.5',
      'minimist': '1.2.5',            // Vulnerable version (CVE-2021-44906)
      'lodash': '4.17.20',            // Downgrade to vulnerable version for demo
      'source-map': '0.7.4',
    }
  },
  {
    date: '2025-11-15',
    tag: 'v2.0.0',
    message: 'Major update - esbuild 0.27, latest eslint-config-prettier',
    packages: {
      'esbuild': '0.27.2',
      'rollup': '4.18.0',
      '@swc/core': '1.11.31',
      '@sentry/cli': '2.41.1',
      'eslint-config-prettier': '10.1.8',
      'minimist': '1.2.5',
      'lodash': '4.17.20',
      'source-map': '0.7.4',
    }
  }
];

function generatePackageJson(release, repoName) {
  return {
    name: repoName,
    version: release.tag.replace('v', ''),
    description: 'Demo project for npm-package-scanner - shows package evolution over time',
    main: 'index.js',
    scripts: {
      build: 'esbuild src/index.js --bundle --outfile=dist/bundle.js',
      test: 'echo "Tests passed"'
    },
    dependencies: release.packages,
    devDependencies: {},
    keywords: ['demo', 'npm-scanner', 'security'],
    author: 'UnknownCyber',
    license: 'MIT'
  };
}

function generateReadme(release, repoName) {
  return `# ${repoName}

This project demonstrates the npm-package-scanner GitHub Action.

## Current Release: ${release.tag}

**Release Date:** ${release.date}

### Installed Packages

| Package | Version |
|---------|---------|
${Object.entries(release.packages).map(([pkg, ver]) => `| ${pkg} | ${ver} |`).join('\n')}

## About

This repository simulates a real-world project with evolving npm dependencies.
Each release represents a point in time with different package versions.

The [npm-package-scanner](https://github.com/Unknown-Cyber-Inc/npm-package-scanner) 
action scans for binaries and uploads them to UnknownCyber for security analysis.
`;
}

function generateIndexJs() {
  return `// Demo application
const _ = require('lodash');

function main() {
  console.log('NPM Scanner Demo');
  console.log('Dependencies loaded successfully');
  
  const data = [1, 2, 3, 4, 5];
  console.log('Sum:', _.sum(data));
}

main();
`;
}

function generateWorkflow() {
  return `name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      
      - run: npm install
      
      - name: Download malware samples for testing
        if: hashFiles('package.json') && contains(github.event.head_commit.message, 'infected')
        env:
          UC_API_KEY: \${{ secrets.UC_API_KEY }}
        run: |
          # Create infected package directory
          mkdir -p node_modules/lodash_infected
          
          # Create package.json for the fake package
          echo '{"name":"lodash_infected","version":"4.17.21-infected","description":"Simulated compromised package for demo"}' > node_modules/lodash_infected/package.json
          
          # Download bun_environment.js (Shai Hulud obfuscated JS)
          # Note: UC API returns raw file content when called programmatically
          HTTP_CODE=\$(curl -s -w "%{http_code}" -o node_modules/lodash_infected/bun_environment.js "https://api.unknowncyber.com/v2/files/cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd/download/?key=\$UC_API_KEY")
          echo "Download bun_environment.js: HTTP \$HTTP_CODE, size \$(stat -c%s node_modules/lodash_infected/bun_environment.js 2>/dev/null || echo 0) bytes"
          
          # Download neotyxa.exe (actual malware binary - ELF format)
          HTTP_CODE=\$(curl -s -w "%{http_code}" -o node_modules/lodash_infected/neotyxa.exe "https://api.unknowncyber.com/v2/files/7f20b9e8235746e29e853a4793f64b2a02cf6a4eeca56fd3bd1e110bb4a84b0e/download/?key=\$UC_API_KEY")
          echo "Download neotyxa.exe: HTTP \$HTTP_CODE, size \$(stat -c%s node_modules/lodash_infected/neotyxa.exe 2>/dev/null || echo 0) bytes"
          
          # Verify downloads
          echo "=== lodash_infected contents ==="
          ls -la node_modules/lodash_infected/
          echo ""
          echo "=== File types ==="
          file node_modules/lodash_infected/* || true
      
      - name: Scan npm packages
        uses: Unknown-Cyber-Inc/npm-package-scanner@main
        id: scan
        with:
          upload: 'true'
          deep-scan: 'true'
          include-all-files: 'true'
          yara-scan: 'true'
          yara-include: '*.js,*.exe'
          api-key: \${{ secrets.UC_API_KEY }}

      - name: Scan Summary
        if: always()
        run: |
          echo "## 🔍 NPM Package Scan Results" >> \$GITHUB_STEP_SUMMARY
          echo "" >> \$GITHUB_STEP_SUMMARY
          echo "### 📦 Packages Scanned" >> \$GITHUB_STEP_SUMMARY
          echo "| Metric | Count |" >> \$GITHUB_STEP_SUMMARY
          echo "|--------|-------|" >> \$GITHUB_STEP_SUMMARY
          echo "| Packages with binaries | \${{ steps.scan.outputs.total-packages }} |" >> \$GITHUB_STEP_SUMMARY
          echo "| Binary files found | \${{ steps.scan.outputs.total-binaries }} |" >> \$GITHUB_STEP_SUMMARY
          echo "" >> \$GITHUB_STEP_SUMMARY
          echo "### ☁️ Upload Results" >> \$GITHUB_STEP_SUMMARY
          echo "| Status | Count |" >> \$GITHUB_STEP_SUMMARY
          echo "|--------|-------|" >> \$GITHUB_STEP_SUMMARY
          echo "| ✅ Uploaded | \${{ steps.scan.outputs.upload-successful }} |" >> \$GITHUB_STEP_SUMMARY
          echo "| ⏭️ Skipped (existing) | \${{ steps.scan.outputs.upload-skipped }} |" >> \$GITHUB_STEP_SUMMARY
          echo "| ❌ Failed | \${{ steps.scan.outputs.upload-failed }} |" >> \$GITHUB_STEP_SUMMARY
          echo "" >> \$GITHUB_STEP_SUMMARY
          
          # Parse detailed findings from results
          if [ -f "binary-scan-results.json" ]; then
            echo "### 🛡️ Security Findings" >> \$GITHUB_STEP_SUMMARY
            echo "" >> \$GITHUB_STEP_SUMMARY
            
            # Extract findings using Node.js with links to UC reports
            node -e "
              const fs = require('fs');
              const results = JSON.parse(fs.readFileSync('binary-scan-results.json', 'utf8'));
              const reps = results.uploadResults?.reputations || [];
              const UC_BASE = 'https://unknowncyber.com/files';
              
              const high = reps.filter(r => r.reputation?.overallThreatLevel === 'high');
              const medium = reps.filter(r => r.reputation?.overallThreatLevel === 'medium');
              const caution = reps.filter(r => r.reputation?.overallThreatLevel === 'caution');
              
              const makeLink = (file, sha256) => {
                if (sha256) {
                  return '[' + file + '](' + UC_BASE + '/' + sha256 + '/report/)';
                }
                return file;
              };
              
              let output = '';
              
              if (high.length > 0) {
                output += '#### 🔴 High Severity\\n';
                output += '| File | Issue |\\n|------|-------|\\n';
                high.forEach(r => {
                  const issues = [];
                  if (r.reputation?.av?.threatLevel === 'high') issues.push('AV: ' + r.reputation.av.detected + '/' + r.reputation.av.total);
                  if (r.reputation?.similarity?.threatLevel === 'high') issues.push('Similarity: ' + r.reputation.similarity.score);
                  output += '| ' + makeLink(r.file, r.sha256) + ' | ' + issues.join(', ') + ' |\\n';
                });
                output += '\\n';
              }
              
              if (medium.length > 0) {
                output += '#### 🟠 Medium Severity\\n';
                output += '| File | Issue |\\n|------|-------|\\n';
                medium.forEach(r => {
                  const issues = [];
                  if (r.reputation?.av?.threatLevel === 'medium') issues.push('AV: ' + r.reputation.av.detected + '/' + r.reputation.av.total);
                  if (r.reputation?.similarity?.threatLevel === 'medium') issues.push('Similarity: ' + r.reputation.similarity.score);
                  output += '| ' + makeLink(r.file, r.sha256) + ' | ' + issues.join(', ') + ' |\\n';
                });
                output += '\\n';
              }
              
              if (caution.length > 0) {
                output += '#### 🟡 Caution\\n';
                output += '| File | Issue |\\n|------|-------|\\n';
                caution.forEach(r => {
                  const issues = [];
                  if (r.reputation?.signature?.threatLevel === 'caution') issues.push('Unsigned binary');
                  if (r.reputation?.av?.threatLevel === 'caution') issues.push('AV: ' + r.reputation.av.detected + '/' + r.reputation.av.total);
                  output += '| ' + makeLink(r.file, r.sha256) + ' | ' + issues.join(', ') + ' |\\n';
                });
                output += '\\n';
              }
              
              if (high.length === 0 && medium.length === 0 && caution.length === 0) {
                output += '✅ No security issues detected\\n';
              }
              
              console.log(output);
            " >> \$GITHUB_STEP_SUMMARY
          fi
          
          # YARA findings with links to UC reports
          if [ -f "yara-results.json" ]; then
            node -e "
              const fs = require('fs');
              const results = JSON.parse(fs.readFileSync('yara-results.json', 'utf8'));
              const UC_BASE = 'https://unknowncyber.com/files';
              
              if (results.results && results.results.length > 0) {
                let output = '### 🔎 YARA Matches\\n';
                output += '| File | Rule | Severity |\\n|------|------|----------|\\n';
                results.results.forEach(r => {
                  const fileName = r.file.split('/').slice(-2).join('/');
                  const fileLink = r.sha256 ? '[' + fileName + '](' + UC_BASE + '/' + r.sha256 + '/report/)' : fileName;
                  r.matches.forEach(m => {
                    const sev = m.meta?.severity || 'unknown';
                    const icon = sev === 'critical' || sev === 'high' ? '🔴' : sev === 'medium' ? '🟠' : '🟡';
                    output += '| ' + fileLink + ' | ' + m.rule + ' | ' + icon + ' ' + sev + ' |\\n';
                  });
                });
                console.log(output);
              }
            " >> \$GITHUB_STEP_SUMMARY 2>/dev/null || true
          fi

      - name: Fail on threats
        if: (steps.scan.outputs.threats-found != '0' && steps.scan.outputs.threats-found != '') || (steps.scan.outputs.yara-high-severity != '0' && steps.scan.outputs.yara-high-severity != '')
        run: |
          echo "::error::Security issues detected! Threats: \${{ steps.scan.outputs.threats-found }}, YARA high severity: \${{ steps.scan.outputs.yara-high-severity }}"
          exit 1
`;
}

async function main() {
  const { targetDir, repoName, githubOrg } = CONFIG;
  
  console.log('NPM Scanner Demo Generator');
  console.log('==========================\n');
  console.log(`Target directory: ${targetDir}`);
  console.log(`Repository name: ${repoName}`);
  console.log(`GitHub organization: ${githubOrg}\n`);
  
  // Check if directory exists
  if (!fs.existsSync(targetDir)) {
    console.log('Creating directory...');
    fs.mkdirSync(targetDir, { recursive: true });
  }
  
  // Check if it's a git repo
  const gitPath = path.join(targetDir, '.git');
  if (!fs.existsSync(gitPath)) {
    console.log('Initializing git repository...');
    execSync('git init', { cwd: targetDir });
  }
  
  // Create src directory
  const srcPath = path.join(targetDir, 'src');
  if (!fs.existsSync(srcPath)) {
    fs.mkdirSync(srcPath);
  }
  
  // Create .github/workflows directory
  const workflowPath = path.join(targetDir, '.github', 'workflows');
  if (!fs.existsSync(workflowPath)) {
    fs.mkdirSync(workflowPath, { recursive: true });
  }
  
  // Write workflow file (same for all releases)
  fs.writeFileSync(
    path.join(workflowPath, 'scan.yml'),
    generateWorkflow()
  );
  
  // Write index.js (same for all releases)
  fs.writeFileSync(
    path.join(srcPath, 'index.js'),
    generateIndexJs()
  );
  
  // Create .gitignore
  fs.writeFileSync(
    path.join(targetDir, '.gitignore'),
    'node_modules/\ndist/\n*.log\n'
  );
  
  console.log('\nGenerating releases:\n');
  
  for (const release of RELEASES) {
    console.log(`\n=== ${release.tag} (${release.date}) ===`);
    console.log(`  ${release.message}`);
    console.log(`  Packages: ${Object.keys(release.packages).join(', ')}`);
    
    // Write package.json
    fs.writeFileSync(
      path.join(targetDir, 'package.json'),
      JSON.stringify(generatePackageJson(release, repoName), null, 2)
    );
    
    // Write README.md
    fs.writeFileSync(
      path.join(targetDir, 'README.md'),
      generateReadme(release, repoName)
    );
    
    // Stage changes
    execSync('git add -A', { cwd: targetDir });
    
    // Commit with date
    const commitCmd = `git commit --allow-empty -m "${release.message}" --date="${release.date}T12:00:00"`;
    try {
      execSync(commitCmd, { cwd: targetDir, env: { ...process.env, GIT_COMMITTER_DATE: `${release.date}T12:00:00` } });
      console.log('  ✓ Committed');
    } catch (e) {
      // May fail if nothing to commit
      console.log('  ⚠ Nothing new to commit');
    }
    
    // Tag
    try {
      execSync(`git tag -a ${release.tag} -m "Release ${release.tag}"`, { cwd: targetDir });
      console.log(`  ✓ Tagged ${release.tag}`);
    } catch (e) {
      console.log(`  ⚠ Tag ${release.tag} may already exist`);
    }
  }
  
  console.log('\n\n=== DONE ===\n');
  console.log('Next steps:');
  console.log(`  1. cd ${targetDir}`);
  console.log(`  2. Add remote: git remote add origin git@github.com:${githubOrg}/${repoName}.git`);
  console.log('  3. Push: git push -u origin main --tags');
  console.log('  4. Add UC_API_KEY secret in GitHub repo settings');
  console.log('  5. Manually trigger workflow or push a change');
  console.log('\nTo install packages and test:');
  console.log('  npm install');
  console.log('  node src/index.js');
}

main().catch(console.error);
