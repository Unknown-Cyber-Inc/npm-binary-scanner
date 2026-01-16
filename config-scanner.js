#!/usr/bin/env node
/**
 * Configuration Misconfiguration Scanner - Phase 1 Universal Detectors
 * 
 * Scans configuration files for security issues using regex-based pattern matching.
 * This is a format-agnostic scanner that works on any text file.
 * 
 * Detectors:
 *   1. Secrets Scanner - Hardcoded credentials, API keys, tokens
 *   2. Network Exposure Scanner - 0.0.0.0 bindings, permissive CIDRs
 *   3. TLS Weakness Scanner - Weak TLS versions, insecure ciphers
 *   4. Debug Mode Scanner - Debug enabled, development settings
 * 
 * Usage:
 *   node config-scanner.js <path> [options]
 *   node config-scanner.js test-configs/secrets/bad/
 *   node config-scanner.js nginx.conf --json
 * 
 * Options:
 *   --json          Output as JSON
 *   --scanners=...  Comma-separated list of scanners (secrets,network,tls,debug)
 *   --severity=...  Minimum severity to report (critical,high,medium,low)
 */

const fs = require('fs');
const path = require('path');

// =============================================================================
// SCANNER DEFINITIONS
// =============================================================================

const SCANNERS = {
  secrets: {
    name: 'Secrets Scanner',
    description: 'Detects hardcoded credentials and API keys',
    rules: [
      {
        id: 'secrets/hardcoded-password',
        // Match password followed by = or : and a quoted or unquoted value (not just whitespace)
        pattern: /(?:password|passwd|pwd)\s*[=:]\s*["']([^"'\n]{4,})["']|(?:password|passwd|pwd)\s*=\s*([^\s\n"']{4,})/gi,
        severity: 'critical',
        message: 'Hardcoded password detected',
        remediation: 'Use environment variables or a secrets manager',
        // Exclude obvious placeholders and env var references
        exclude: /(\$\{|\$[A-Z_]|CHANGE_ME|your[-_]?password|xxxxxxx|\*\*\*|<.*>|\[.*\]|TODO|external)/i
      },
      {
        id: 'secrets/hardcoded-secret',
        // Match secret/private key with actual values
        pattern: /(?:secret|private)[-_]?(?:key|token)\s*[=:]\s*["']([^"'\n]{8,})["']|(?:secret|private)[-_]?(?:key|token)\s*=\s*([^\s\n"']{8,})/gi,
        severity: 'critical',
        message: 'Hardcoded secret or private key detected',
        remediation: 'Use environment variables or a secrets manager',
        exclude: /(\$\{|\$[A-Z_]|CHANGE_ME|your[-_]?|xxxxxxx|\*\*\*|<.*>|\[.*\]|TODO|fake|test|example|external)/i
      },
      {
        id: 'secrets/api-key',
        // Match api_key/apikey with actual values
        pattern: /(?:api[-_]?key|apikey)\s*[=:]\s*["']([^"'\n]{8,})["']|(?:api[-_]?key|apikey)\s*=\s*([^\s\n"']{8,})/gi,
        severity: 'high',
        message: 'Hardcoded API key detected',
        remediation: 'Use environment variables or a secrets manager',
        exclude: /(\$\{|\$[A-Z_]|CHANGE_ME|your[-_]?|xxxxxxx|\*\*\*|<.*>|\[.*\]|TODO|fake|test|example|external)/i
      },
      {
        id: 'secrets/aws-access-key',
        pattern: /AKIA[0-9A-Z]{16}/g,
        severity: 'critical',
        message: 'AWS Access Key ID detected',
        remediation: 'Use IAM roles or environment variables instead of hardcoded keys',
        // AWS example key from documentation
        exclude: /AKIAIOSFODNN7EXAMPLE/
      },
      {
        id: 'secrets/bearer-token',
        pattern: /["']Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+["']/g,
        severity: 'high',
        message: 'Hardcoded Bearer/JWT token detected',
        remediation: 'Use environment variables for tokens'
      },
      {
        id: 'secrets/connection-string',
        pattern: /(?:mongodb|postgresql|mysql|redis|amqp):\/\/[^:]+:[^@]+@[^\s"']+/gi,
        severity: 'critical',
        message: 'Database connection string with credentials detected',
        remediation: 'Use environment variables for connection strings'
      }
    ]
  },

  network: {
    name: 'Network Exposure Scanner',
    description: 'Detects dangerous network bindings and exposure',
    rules: [
      {
        id: 'network/bind-all-interfaces',
        pattern: /(?:listen|bind[-_]?address|host)\s*[=:]\s*["']?(?:0\.0\.0\.0|\*)["']?/gi,
        severity: 'high',
        message: 'Service bound to all interfaces (0.0.0.0)',
        remediation: 'Bind to specific interface or 127.0.0.1 if not public'
      },
      {
        id: 'network/bind-all-interfaces-port',
        pattern: /(?:listen|ports)\s*[=:\-]\s*["']?(?:0\.0\.0\.0|\*)[:\s]*\d+/gi,
        severity: 'high',
        message: 'Port exposed on all interfaces',
        remediation: 'Bind to 127.0.0.1 or specific interface'
      },
      {
        id: 'network/permissive-cidr',
        pattern: /0\.0\.0\.0\/0/g,
        severity: 'high',
        message: 'Permissive CIDR (0.0.0.0/0) allows traffic from anywhere',
        remediation: 'Restrict to specific IP ranges'
      },
      {
        id: 'network/database-port-exposed',
        pattern: /(?:0\.0\.0\.0|\*)[:\s]*(?:3306|5432|27017|6379|9200|9300)/g,
        severity: 'critical',
        message: 'Database/cache port exposed on all interfaces',
        remediation: 'Database ports should only be accessible internally'
      },
      {
        id: 'network/host-network-enabled',
        pattern: /hostNetwork\s*:\s*true/gi,
        severity: 'high',
        message: 'Kubernetes hostNetwork enabled - container shares host network',
        remediation: 'Avoid hostNetwork unless absolutely necessary'
      },
      {
        id: 'network/host-port-exposed',
        pattern: /hostPort\s*:\s*\d+/gi,
        severity: 'medium',
        message: 'Kubernetes hostPort exposes container port directly on host',
        remediation: 'Use Services instead of hostPort for exposure'
      }
    ]
  },

  tls: {
    name: 'TLS Weakness Scanner',
    description: 'Detects weak TLS/SSL configurations',
    rules: [
      {
        id: 'tls/sslv2-enabled',
        pattern: /SSLv2/gi,
        severity: 'critical',
        message: 'SSLv2 is critically insecure',
        remediation: 'Use TLSv1.2 or TLSv1.3 only',
        // Exclude if it's being disabled (e.g., -SSLv2)
        excludeContext: /-SSLv2|!SSLv2/i
      },
      {
        id: 'tls/sslv3-enabled',
        pattern: /SSLv3/gi,
        severity: 'critical',
        message: 'SSLv3 is vulnerable to POODLE attack',
        remediation: 'Use TLSv1.2 or TLSv1.3 only',
        excludeContext: /-SSLv3|!SSLv3/i
      },
      {
        id: 'tls/tlsv1-enabled',
        pattern: /TLSv1(?:\.0)?(?![.\d])/gi,
        severity: 'high',
        message: 'TLS 1.0 is deprecated and insecure',
        remediation: 'Use TLSv1.2 or TLSv1.3 only',
        excludeContext: /-TLSv1(?:\.0)?|!TLSv1/i
      },
      {
        id: 'tls/tlsv11-enabled',
        pattern: /TLSv1\.1/gi,
        severity: 'high',
        message: 'TLS 1.1 is deprecated and insecure',
        remediation: 'Use TLSv1.2 or TLSv1.3 only',
        excludeContext: /-TLSv1\.1|!TLSv1\.1/i
      },
      {
        id: 'tls/weak-cipher-rc4',
        pattern: /\bRC4\b/gi,
        severity: 'high',
        message: 'RC4 cipher is broken',
        remediation: 'Use modern ciphers like AES-GCM',
        excludeContext: /!RC4|:!RC4|-RC4/i
      },
      {
        id: 'tls/weak-cipher-des',
        pattern: /\b(?:DES|3DES)\b/gi,
        severity: 'high',
        message: 'DES/3DES ciphers are weak',
        remediation: 'Use modern ciphers like AES-GCM',
        excludeContext: /!DES|!3DES|:!DES|:!3DES/i
      },
      {
        id: 'tls/weak-cipher-null',
        pattern: /\bNULL\b/gi,
        severity: 'critical',
        message: 'NULL cipher provides no encryption',
        remediation: 'Remove NULL from cipher list',
        excludeContext: /!NULL|:!NULL/i
      },
      {
        id: 'tls/weak-cipher-export',
        pattern: /\bEXPORT\b/gi,
        severity: 'critical',
        message: 'EXPORT ciphers are extremely weak',
        remediation: 'Remove EXPORT from cipher list',
        excludeContext: /!EXPORT|:!EXPORT/i
      },
      {
        id: 'tls/ssl-min-ver-weak',
        pattern: /ssl[-_]min[-_]ver\s*[=:\s]+TLSv1(?:\.0|\.1)?(?!\.[23])/gi,
        severity: 'high',
        message: 'Minimum TLS version set to insecure version',
        remediation: 'Set minimum TLS version to 1.2 or higher'
      }
    ]
  },

  debug: {
    name: 'Debug Mode Scanner',
    description: 'Detects debug/development settings in production configs',
    rules: [
      {
        id: 'debug/debug-enabled',
        pattern: /\bdebug\s*[=:]\s*["']?(?:true|1|yes|on)["']?/gi,
        severity: 'medium',
        message: 'Debug mode is enabled',
        remediation: 'Disable debug mode in production'
      },
      {
        id: 'debug/debug-mode-enabled',
        pattern: /DEBUG[-_]?MODE\s*[=:]\s*["']?(?:true|1|yes|on)["']?/gi,
        severity: 'medium',
        message: 'Debug mode is enabled',
        remediation: 'Disable debug mode in production'
      },
      {
        id: 'debug/development-environment',
        pattern: /(?:NODE_ENV|ENVIRONMENT|ENV)\s*[=:]\s*["']?development["']?/gi,
        severity: 'medium',
        message: 'Environment set to development',
        remediation: 'Use production environment in production'
      },
      {
        id: 'debug/flask-debug',
        pattern: /FLASK[-_]?DEBUG\s*[=:]\s*["']?(?:true|1|yes|on)["']?/gi,
        severity: 'high',
        message: 'Flask debug mode enables code execution',
        remediation: 'Never enable Flask debug in production'
      },
      {
        id: 'debug/django-debug',
        pattern: /DJANGO[-_]?DEBUG\s*[=:]\s*["']?(?:True|true|1|yes|on)["']?/gi,
        severity: 'high',
        message: 'Django debug mode exposes sensitive information',
        remediation: 'Set DEBUG=False in production'
      },
      {
        id: 'debug/display-errors',
        pattern: /display[-_]?errors\s*[=:]\s*["']?(?:On|1|true|yes)["']?/gi,
        severity: 'high',
        message: 'PHP display_errors exposes sensitive information',
        remediation: 'Set display_errors=Off in production'
      },
      {
        id: 'debug/server-tokens',
        pattern: /server[-_]?tokens\s+on/gi,
        severity: 'low',
        message: 'Server version disclosure enabled',
        remediation: 'Set server_tokens off to hide version'
      },
      {
        id: 'debug/autoindex-enabled',
        pattern: /autoindex\s+on/gi,
        severity: 'medium',
        message: 'Directory listing is enabled',
        remediation: 'Set autoindex off unless needed'
      },
      {
        id: 'debug/expose-php',
        pattern: /expose[-_]?php\s*[=:]\s*["']?(?:On|1|true|yes)["']?/gi,
        severity: 'low',
        message: 'PHP version exposure enabled',
        remediation: 'Set expose_php=Off'
      }
    ]
  }
};

// =============================================================================
// SCANNER IMPLEMENTATION
// =============================================================================

/**
 * Check if a line is a comment
 */
function isComment(line) {
  const trimmed = line.trim();
  return trimmed.startsWith('#') || 
         trimmed.startsWith('//') || 
         trimmed.startsWith(';') ||
         trimmed.startsWith('/*') ||
         trimmed.startsWith('*') ||
         trimmed.startsWith('<!--');
}

/**
 * Scan a single file for misconfigurations
 */
function scanFile(filePath, enabledScanners = Object.keys(SCANNERS)) {
  const findings = [];
  
  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch (err) {
    return { file: filePath, error: err.message, findings: [] };
  }

  const lines = content.split('\n');

  for (const scannerName of enabledScanners) {
    const scanner = SCANNERS[scannerName];
    if (!scanner) continue;

    for (const rule of scanner.rules) {
      // Reset regex lastIndex for global patterns
      rule.pattern.lastIndex = 0;
      
      let match;
      while ((match = rule.pattern.exec(content)) !== null) {
        // Find line number
        const beforeMatch = content.substring(0, match.index);
        const lineNumber = (beforeMatch.match(/\n/g) || []).length + 1;
        const line = lines[lineNumber - 1] || '';

        // Skip if line is a comment
        if (isComment(line)) {
          continue;
        }

        // Skip if matches exclude pattern (for placeholders, etc.)
        if (rule.exclude && rule.exclude.test(match[0])) {
          continue;
        }

        // Skip if context excludes it (e.g., -SSLv3 means disabled)
        if (rule.excludeContext) {
          // Get surrounding context (the whole line)
          if (rule.excludeContext.test(line)) {
            continue;
          }
        }

        findings.push({
          rule: rule.id,
          severity: rule.severity,
          line: lineNumber,
          message: rule.message,
          match: match[0].substring(0, 100), // Truncate long matches
          remediation: rule.remediation,
          scanner: scannerName
        });
      }
    }
  }

  return { file: filePath, findings };
}

/**
 * Scan a directory recursively
 */
function scanDirectory(dirPath, enabledScanners = Object.keys(SCANNERS)) {
  const results = [];
  
  function walkDir(dir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      
      if (entry.isDirectory()) {
        // Skip common non-config directories
        if (['node_modules', '.git', '__pycache__', 'vendor'].includes(entry.name)) {
          continue;
        }
        walkDir(fullPath);
      } else if (entry.isFile()) {
        // Scan text files that might be configs
        const ext = path.extname(entry.name).toLowerCase();
        const configExtensions = [
          '.conf', '.cfg', '.ini', '.yaml', '.yml', '.json', '.toml',
          '.env', '.properties', '.xml', '.htaccess', '.config'
        ];
        const configNames = [
          'dockerfile', '.env', 'docker-compose', 'nginx', 'httpd',
          'my.cnf', 'pg_hba.conf', 'redis.conf', 'sshd_config'
        ];
        
        const isConfig = configExtensions.includes(ext) ||
                        configNames.some(n => entry.name.toLowerCase().includes(n)) ||
                        entry.name.startsWith('.');
        
        if (isConfig) {
          const result = scanFile(fullPath, enabledScanners);
          results.push(result);
        }
      }
    }
  }

  walkDir(dirPath);
  return results;
}

/**
 * Scan a path (file or directory)
 */
function scan(targetPath, enabledScanners = Object.keys(SCANNERS)) {
  const stats = fs.statSync(targetPath);
  
  if (stats.isFile()) {
    return [scanFile(targetPath, enabledScanners)];
  } else if (stats.isDirectory()) {
    return scanDirectory(targetPath, enabledScanners);
  }
  
  throw new Error(`Invalid path: ${targetPath}`);
}

// =============================================================================
// CLI
// =============================================================================

function printUsage() {
  console.log(`
Configuration Misconfiguration Scanner - Phase 1 Universal Detectors

Usage:
  node config-scanner.js <path> [options]

Options:
  --json              Output as JSON
  --scanners=<list>   Comma-separated scanners (secrets,network,tls,debug)
  --severity=<level>  Minimum severity (critical,high,medium,low)
  --help              Show this help

Examples:
  node config-scanner.js nginx.conf
  node config-scanner.js test-configs/secrets/bad/ --json
  node config-scanner.js . --scanners=secrets,network --severity=high
`);
}

function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args.includes('--help')) {
    printUsage();
    process.exit(0);
  }

  // Parse arguments
  let targetPath = null;
  let jsonOutput = false;
  let enabledScanners = Object.keys(SCANNERS);
  let minSeverity = 'low';

  const severityLevels = { critical: 4, high: 3, medium: 2, low: 1 };

  for (const arg of args) {
    if (arg === '--json') {
      jsonOutput = true;
    } else if (arg.startsWith('--scanners=')) {
      enabledScanners = arg.split('=')[1].split(',');
    } else if (arg.startsWith('--severity=')) {
      minSeverity = arg.split('=')[1].toLowerCase();
    } else if (!arg.startsWith('--')) {
      targetPath = arg;
    }
  }

  if (!targetPath) {
    console.error('Error: No path specified');
    printUsage();
    process.exit(1);
  }

  // Run scan
  let results;
  try {
    results = scan(targetPath, enabledScanners);
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }

  // Filter by severity
  const minLevel = severityLevels[minSeverity] || 1;
  for (const result of results) {
    result.findings = result.findings.filter(f => 
      severityLevels[f.severity] >= minLevel
    );
  }

  // Calculate totals
  const totalFindings = results.reduce((sum, r) => sum + r.findings.length, 0);
  const filesWithFindings = results.filter(r => r.findings.length > 0).length;

  // Output
  if (jsonOutput) {
    const output = {
      scanPath: targetPath,
      scanners: enabledScanners,
      totalFiles: results.length,
      filesWithFindings,
      totalFindings,
      results: results.filter(r => r.findings.length > 0 || r.error)
    };
    console.log(JSON.stringify(output, null, 2));
  } else {
    console.log(`\n🔍 Configuration Scanner Results`);
    console.log(`${'='.repeat(50)}`);
    console.log(`Path: ${targetPath}`);
    console.log(`Files scanned: ${results.length}`);
    console.log(`Files with issues: ${filesWithFindings}`);
    console.log(`Total findings: ${totalFindings}`);
    console.log(`${'='.repeat(50)}\n`);

    for (const result of results) {
      if (result.error) {
        console.log(`❌ ${result.file}: ${result.error}`);
        continue;
      }

      if (result.findings.length === 0) continue;

      console.log(`📄 ${result.file}`);
      for (const finding of result.findings) {
        const icon = {
          critical: '🔴',
          high: '🟠',
          medium: '🟡',
          low: '🔵'
        }[finding.severity] || '⚪';

        console.log(`   ${icon} [${finding.severity.toUpperCase()}] Line ${finding.line}: ${finding.message}`);
        console.log(`      Rule: ${finding.rule}`);
        console.log(`      Match: ${finding.match}`);
        console.log(`      Fix: ${finding.remediation}`);
        console.log();
      }
    }

    if (totalFindings === 0) {
      console.log('✅ No issues found!');
    }
  }

  // Exit with error code if findings
  process.exit(totalFindings > 0 ? 1 : 0);
}

// Export for use as module
module.exports = { scan, scanFile, scanDirectory, SCANNERS };

// Run CLI if executed directly
if (require.main === module) {
  main();
}
