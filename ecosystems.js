/**
 * Ecosystem Configuration Module
 * 
 * Defines package manager ecosystems and their metadata extraction strategies.
 * Each ecosystem specifies:
 * - directories: where packages are installed
 * - tagPrefix: tag prefix for UnknownCyber (SW_<pm>/)
 * - findPackageInfo: function to extract package name/version from file path
 */

const fs = require('fs');
const path = require('path');

/**
 * NPM/Node.js ecosystem
 * Packages in node_modules/, metadata in package.json
 */
function findNpmPackageInfo(filePath, rootDir) {
  let dir = path.dirname(filePath);
  
  while (dir.length >= rootDir.length) {
    const packageJsonPath = path.join(dir, 'package.json');
    
    if (fs.existsSync(packageJsonPath)) {
      try {
        const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
        const relativePath = path.relative(rootDir, dir);
        
        return {
          name: packageJson.name || path.basename(dir),
          version: packageJson.version || 'unknown',
          path: dir,
          relativePath: relativePath
        };
      } catch (err) {
        // Continue searching up
      }
    }
    
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  
  return null;
}

/**
 * Python/pip ecosystem
 * Packages in site-packages/ or dist-packages/
 * Metadata in *.dist-info/METADATA or *.egg-info/PKG-INFO
 */
function findPipPackageInfo(filePath, rootDir) {
  // Get the relative path from root
  const relativePath = path.relative(rootDir, filePath);
  const parts = relativePath.split(path.sep);
  
  if (parts.length < 1) return null;
  
  // Find the site-packages or dist-packages directory that contains this file
  // This is where dist-info directories are located
  let pkgRoot = rootDir;
  for (let i = 0; i < parts.length; i++) {
    if (parts[i] === 'site-packages' || parts[i] === 'dist-packages' || parts[i] === 'Lib') {
      // The package root is the site-packages directory
      pkgRoot = path.join(rootDir, ...parts.slice(0, i + 1));
      // Adjust parts to be relative to site-packages
      parts.splice(0, i + 1);
      break;
    }
  }
  
  // If we didn't find a site-packages, the rootDir might already be it
  if (pkgRoot === rootDir && path.basename(rootDir).includes('site-packages')) {
    // Already at site-packages level
  }
  
  let entries;
  try {
    entries = fs.readdirSync(pkgRoot);
  } catch (err) {
    return null;
  }
  
  // The first part after site-packages is the package directory (e.g., 'cryptography')
  const packageDir = parts.length > 0 ? parts[0] : '';
  
  // First, try to find which package this file belongs to by checking dist-info
  for (const entry of entries) {
    const entryPath = path.join(pkgRoot, entry);
    let stat;
    try {
      stat = fs.statSync(entryPath);
    } catch (err) {
      continue;
    }
    
    if (stat.isDirectory()) {
      // Check if this is a dist-info directory
      if (entry.endsWith('.dist-info')) {
        const metadataPath = path.join(entryPath, 'METADATA');
        const recordPath = path.join(entryPath, 'RECORD');
        
        // Check if this dist-info owns the file by looking at RECORD
        if (fs.existsSync(recordPath)) {
          try {
            const record = fs.readFileSync(recordPath, 'utf8');
            // For record matching, use the relative path from pkgRoot
            const fileRelFromPkgRoot = parts.join('/');
            
            if (record.includes(fileRelFromPkgRoot) || (packageDir && record.includes(packageDir + '/'))) {
              // This dist-info owns this file, parse METADATA
              if (fs.existsSync(metadataPath)) {
                const metadata = fs.readFileSync(metadataPath, 'utf8');
                const nameMatch = metadata.match(/^Name:\s*(.+)$/m);
                const versionMatch = metadata.match(/^Version:\s*(.+)$/m);
                
                return {
                  name: nameMatch ? nameMatch[1].trim() : entry.replace('.dist-info', ''),
                  version: versionMatch ? versionMatch[1].trim() : 'unknown',
                  path: entryPath,
                  relativePath: packageDir || parts[0]
                };
              }
            }
          } catch (err) {
            // Continue
          }
        }
        
        // Fallback: match by directory name prefix
        const distInfoName = entry.replace('.dist-info', '').split('-')[0].toLowerCase();
        if (packageDir && (packageDir.toLowerCase() === distInfoName || 
            packageDir.toLowerCase().replace(/_/g, '-') === distInfoName)) {
          if (fs.existsSync(metadataPath)) {
            try {
              const metadata = fs.readFileSync(metadataPath, 'utf8');
              const nameMatch = metadata.match(/^Name:\s*(.+)$/m);
              const versionMatch = metadata.match(/^Version:\s*(.+)$/m);
              
              return {
                name: nameMatch ? nameMatch[1].trim() : distInfoName,
                version: versionMatch ? versionMatch[1].trim() : 'unknown',
                path: path.join(pkgRoot, packageDir),
                relativePath: packageDir
              };
            } catch (err) {
              // Continue
            }
          }
        }
      }
      
      // Check for egg-info
      if (entry.endsWith('.egg-info')) {
        const pkgInfoPath = path.join(entryPath, 'PKG-INFO');
        const eggName = entry.replace('.egg-info', '').split('-')[0].toLowerCase();
        
        if (packageDir && (packageDir.toLowerCase() === eggName ||
            packageDir.toLowerCase().replace(/_/g, '-') === eggName)) {
          if (fs.existsSync(pkgInfoPath)) {
            try {
              const pkgInfo = fs.readFileSync(pkgInfoPath, 'utf8');
              const nameMatch = pkgInfo.match(/^Name:\s*(.+)$/m);
              const versionMatch = pkgInfo.match(/^Version:\s*(.+)$/m);
              
              return {
                name: nameMatch ? nameMatch[1].trim() : eggName,
                version: versionMatch ? versionMatch[1].trim() : 'unknown',
                path: path.join(pkgRoot, packageDir),
                relativePath: packageDir
              };
            } catch (err) {
              // Continue
            }
          }
        }
      }
    }
  }
  
  // Fallback: use the package directory name as package name
  if (packageDir && !packageDir.endsWith('.dist-info') && !packageDir.endsWith('.egg-info')) {
    return {
      name: packageDir,
      version: 'unknown',
      path: path.join(pkgRoot, packageDir),
      relativePath: packageDir
    };
  }
  
  return null;
}

/**
 * Maven/Java ecosystem
 * Packages typically in .m2/repository/ or lib/
 * Structure: groupId/artifactId/version/artifactId-version.jar
 */
function findMavenPackageInfo(filePath, rootDir) {
  const relativePath = path.relative(rootDir, filePath);
  const parts = relativePath.split(path.sep);
  
  // Maven repository structure: groupId.parts/artifactId/version/file
  // e.g., org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar
  
  if (parts.length >= 3) {
    // Try to find version directory (usually contains numbers and dots)
    for (let i = parts.length - 2; i >= 0; i--) {
      if (/^\d+(\.\d+)*/.test(parts[i])) {
        // Found version, artifact is previous, group is everything before
        const version = parts[i];
        const artifactId = parts[i - 1] || 'unknown';
        const groupId = parts.slice(0, i - 1).join('.');
        
        return {
          name: groupId ? `${groupId}:${artifactId}` : artifactId,
          version: version,
          path: path.join(rootDir, ...parts.slice(0, i + 1)),
          relativePath: parts.slice(0, i + 1).join(path.sep)
        };
      }
    }
  }
  
  // Fallback: check for pom.xml in directory
  let dir = path.dirname(filePath);
  while (dir.length >= rootDir.length) {
    const pomPath = path.join(dir, 'pom.xml');
    if (fs.existsSync(pomPath)) {
      try {
        const pom = fs.readFileSync(pomPath, 'utf8');
        const artifactMatch = pom.match(/<artifactId>([^<]+)<\/artifactId>/);
        const versionMatch = pom.match(/<version>([^<]+)<\/version>/);
        const groupMatch = pom.match(/<groupId>([^<]+)<\/groupId>/);
        
        const artifactId = artifactMatch ? artifactMatch[1] : path.basename(dir);
        const groupId = groupMatch ? groupMatch[1] : '';
        
        return {
          name: groupId ? `${groupId}:${artifactId}` : artifactId,
          version: versionMatch ? versionMatch[1] : 'unknown',
          path: dir,
          relativePath: path.relative(rootDir, dir)
        };
      } catch (err) {
        // Continue
      }
    }
    
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  
  // Final fallback
  return {
    name: parts[0] || 'unknown',
    version: 'unknown',
    path: path.join(rootDir, parts[0] || ''),
    relativePath: parts[0] || ''
  };
}

/**
 * Cargo/Rust ecosystem
 * Packages in target/release/ or target/debug/
 * Metadata in Cargo.toml
 */
function findCargoPackageInfo(filePath, rootDir) {
  // Look for Cargo.toml in parent directories
  let dir = path.dirname(filePath);
  
  // First check the root for Cargo.toml
  const rootCargoPath = path.join(rootDir, '..', 'Cargo.toml');
  if (fs.existsSync(rootCargoPath)) {
    try {
      const cargo = fs.readFileSync(rootCargoPath, 'utf8');
      const nameMatch = cargo.match(/^\s*name\s*=\s*"([^"]+)"/m);
      const versionMatch = cargo.match(/^\s*version\s*=\s*"([^"]+)"/m);
      
      return {
        name: nameMatch ? nameMatch[1] : 'unknown',
        version: versionMatch ? versionMatch[1] : 'unknown',
        path: path.dirname(rootCargoPath),
        relativePath: path.relative(rootDir, filePath)
      };
    } catch (err) {
      // Continue
    }
  }
  
  while (dir.length >= rootDir.length) {
    const cargoPath = path.join(dir, 'Cargo.toml');
    if (fs.existsSync(cargoPath)) {
      try {
        const cargo = fs.readFileSync(cargoPath, 'utf8');
        const nameMatch = cargo.match(/^\s*name\s*=\s*"([^"]+)"/m);
        const versionMatch = cargo.match(/^\s*version\s*=\s*"([^"]+)"/m);
        
        return {
          name: nameMatch ? nameMatch[1] : path.basename(dir),
          version: versionMatch ? versionMatch[1] : 'unknown',
          path: dir,
          relativePath: path.relative(rootDir, dir)
        };
      } catch (err) {
        // Continue
      }
    }
    
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  
  // Fallback: use filename as package name (common for Rust binaries)
  const filename = path.basename(filePath);
  const name = filename.replace(/\.(exe|dll|so|dylib)$/i, '');
  
  return {
    name: name,
    version: 'unknown',
    path: path.dirname(filePath),
    relativePath: path.relative(rootDir, filePath)
  };
}

/**
 * Go modules ecosystem
 * Packages in vendor/ or Go module cache
 * Metadata in go.mod
 */
function findGoPackageInfo(filePath, rootDir) {
  const relativePath = path.relative(rootDir, filePath);
  const parts = relativePath.split(path.sep);
  
  // Go vendor structure: vendor/github.com/user/repo/...
  // or module cache: pkg/mod/github.com/user/repo@v1.2.3/...
  
  // Check for version in path (e.g., @v1.2.3)
  for (let i = 0; i < parts.length; i++) {
    if (parts[i].includes('@v')) {
      const [name, version] = parts[i].split('@');
      const modulePath = parts.slice(0, i).join('/') + '/' + name;
      
      return {
        name: modulePath,
        version: version.replace(/^v/, ''),
        path: path.join(rootDir, ...parts.slice(0, i + 1)),
        relativePath: parts.slice(0, i + 1).join(path.sep)
      };
    }
  }
  
  // Look for go.mod
  let dir = path.dirname(filePath);
  while (dir.length >= rootDir.length) {
    const goModPath = path.join(dir, 'go.mod');
    if (fs.existsSync(goModPath)) {
      try {
        const goMod = fs.readFileSync(goModPath, 'utf8');
        const moduleMatch = goMod.match(/^module\s+(.+)$/m);
        
        return {
          name: moduleMatch ? moduleMatch[1].trim() : path.basename(dir),
          version: 'unknown',
          path: dir,
          relativePath: path.relative(rootDir, dir)
        };
      } catch (err) {
        // Continue
      }
    }
    
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  
  // Fallback: construct module path from directory structure
  // vendor/github.com/user/repo -> github.com/user/repo
  if (parts.length >= 3 && (parts[0].includes('.') || parts[1]?.includes('.'))) {
    return {
      name: parts.slice(0, Math.min(3, parts.length)).join('/'),
      version: 'unknown',
      path: path.join(rootDir, ...parts.slice(0, 3)),
      relativePath: parts.slice(0, 3).join(path.sep)
    };
  }
  
  return {
    name: parts[0] || 'unknown',
    version: 'unknown',
    path: path.join(rootDir, parts[0] || ''),
    relativePath: parts[0] || ''
  };
}

/**
 * Ruby gems ecosystem
 * Packages in vendor/bundle/ or gems directory
 * Metadata in *.gemspec
 */
function findRubyPackageInfo(filePath, rootDir) {
  const relativePath = path.relative(rootDir, filePath);
  const parts = relativePath.split(path.sep);
  
  // Ruby bundle structure: ruby/3.0.0/gems/gemname-1.2.3/...
  for (let i = 0; i < parts.length; i++) {
    if (parts[i] === 'gems' && i + 1 < parts.length) {
      const gemDir = parts[i + 1];
      // Parse gemname-version format
      const match = gemDir.match(/^(.+?)-(\d+\.\d+.*)$/);
      if (match) {
        return {
          name: match[1],
          version: match[2],
          path: path.join(rootDir, ...parts.slice(0, i + 2)),
          relativePath: parts.slice(0, i + 2).join(path.sep)
        };
      }
    }
  }
  
  // Look for gemspec files
  let dir = path.dirname(filePath);
  while (dir.length >= rootDir.length) {
    try {
      const entries = fs.readdirSync(dir);
      const gemspec = entries.find(e => e.endsWith('.gemspec'));
      if (gemspec) {
        const gemspecPath = path.join(dir, gemspec);
        const content = fs.readFileSync(gemspecPath, 'utf8');
        const nameMatch = content.match(/\.name\s*=\s*['"]([^'"]+)['"]/);
        const versionMatch = content.match(/\.version\s*=\s*['"]([^'"]+)['"]/);
        
        return {
          name: nameMatch ? nameMatch[1] : gemspec.replace('.gemspec', ''),
          version: versionMatch ? versionMatch[1] : 'unknown',
          path: dir,
          relativePath: path.relative(rootDir, dir)
        };
      }
    } catch (err) {
      // Continue
    }
    
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  
  return {
    name: parts[0] || 'unknown',
    version: 'unknown',
    path: path.join(rootDir, parts[0] || ''),
    relativePath: parts[0] || ''
  };
}

/**
 * NuGet/.NET ecosystem
 * Packages in packages/ or ~/.nuget/packages/
 * Metadata in *.nuspec files
 */
function findNugetPackageInfo(filePath, rootDir) {
  const relativePath = path.relative(rootDir, filePath);
  const parts = relativePath.split(path.sep);
  
  // NuGet structure: packagename/version/... or packagename.version/...
  // e.g., newtonsoft.json/13.0.1/lib/net6.0/Newtonsoft.Json.dll
  
  if (parts.length >= 2) {
    // Check if second part looks like a version
    if (/^\d+(\.\d+)*/.test(parts[1])) {
      return {
        name: parts[0],
        version: parts[1],
        path: path.join(rootDir, parts[0], parts[1]),
        relativePath: path.join(parts[0], parts[1])
      };
    }
  }
  
  // Look for .nuspec files
  let dir = path.dirname(filePath);
  while (dir.length >= rootDir.length) {
    try {
      const entries = fs.readdirSync(dir);
      const nuspec = entries.find(e => e.endsWith('.nuspec'));
      if (nuspec) {
        const nuspecPath = path.join(dir, nuspec);
        const content = fs.readFileSync(nuspecPath, 'utf8');
        const idMatch = content.match(/<id>([^<]+)<\/id>/i);
        const versionMatch = content.match(/<version>([^<]+)<\/version>/i);
        
        return {
          name: idMatch ? idMatch[1] : nuspec.replace('.nuspec', ''),
          version: versionMatch ? versionMatch[1] : 'unknown',
          path: dir,
          relativePath: path.relative(rootDir, dir)
        };
      }
    } catch (err) {
      // Continue
    }
    
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  
  // Parse from directory name (e.g., Newtonsoft.Json.13.0.1)
  if (parts[0]) {
    const match = parts[0].match(/^(.+?)\.(\d+\.\d+.*)$/);
    if (match) {
      return {
        name: match[1],
        version: match[2],
        path: path.join(rootDir, parts[0]),
        relativePath: parts[0]
      };
    }
  }
  
  return {
    name: parts[0] || 'unknown',
    version: 'unknown',
    path: path.join(rootDir, parts[0] || ''),
    relativePath: parts[0] || ''
  };
}

/**
 * Debian/Ubuntu (dpkg) ecosystem
 * System packages in /var/lib/dpkg/
 * Libraries in /usr/lib/, /lib/
 * Package info in /var/lib/dpkg/status
 */
function findDpkgPackageInfo(filePath, rootDir) {
  const relativePath = path.relative(rootDir, filePath);
  
  // Try to find package from dpkg status file
  const statusPath = path.join(rootDir, 'var/lib/dpkg/status');
  if (fs.existsSync(statusPath)) {
    try {
      const status = fs.readFileSync(statusPath, 'utf8');
      const packages = status.split('\n\n');
      
      // Build a map of installed files to packages (simplified)
      // In real dpkg, this would use /var/lib/dpkg/info/*.list files
      for (const pkg of packages) {
        const nameMatch = pkg.match(/^Package:\s*(.+)$/m);
        const versionMatch = pkg.match(/^Version:\s*(.+)$/m);
        
        if (nameMatch) {
          const pkgName = nameMatch[1].trim();
          // Check if file path contains the package name (heuristic)
          if (relativePath.toLowerCase().includes(pkgName.toLowerCase().replace(/-/g, ''))) {
            return {
              name: pkgName,
              version: versionMatch ? versionMatch[1].trim() : 'unknown',
              path: path.dirname(filePath),
              relativePath: relativePath
            };
          }
        }
      }
    } catch (err) {
      // Continue with fallback
    }
  }
  
  // Try to read package info from /var/lib/dpkg/info/*.list files
  const dpkgInfoDir = path.join(rootDir, 'var/lib/dpkg/info');
  if (fs.existsSync(dpkgInfoDir)) {
    try {
      const infoFiles = fs.readdirSync(dpkgInfoDir).filter(f => f.endsWith('.list'));
      
      // Convert our file's relative path to the format used in .list files (absolute Unix path)
      // e.g., "usr\lib\x86_64-linux-gnu\libssl.so.1.1" -> "/usr/lib/x86_64-linux-gnu/libssl.so.1.1"
      const searchPath = '/' + relativePath.replace(/\\/g, '/');
      
      for (const listFile of infoFiles) {
        const listPath = path.join(dpkgInfoDir, listFile);
        const fileList = fs.readFileSync(listPath, 'utf8').split('\n').map(f => f.trim()).filter(f => f);
        
        // Check if our file is in this package's file list
        if (fileList.includes(searchPath)) {
          // Extract package name: remove :arch suffix and .list extension
          // e.g., "libssl1.1:amd64.list" -> "libssl1.1" or "libssl1.1.list" -> "libssl1.1"
          const pkgName = listFile.replace(/(:.*)?\.list$/, '');
          
          // Try to get version from status
          let version = 'unknown';
          if (fs.existsSync(statusPath)) {
            try {
              const status = fs.readFileSync(statusPath, 'utf8');
              // Match package block and extract version
              const pkgRegex = new RegExp(`Package:\\s*${pkgName}\\s*\\n([\\s\\S]*?)(?=\\n\\nPackage:|$)`, 'i');
              const pkgBlock = status.match(pkgRegex);
              if (pkgBlock) {
                const versionMatch = pkgBlock[1].match(/^Version:\s*(.+)$/m);
                if (versionMatch) version = versionMatch[1].trim();
              }
            } catch (e) {
              // Continue with unknown version
            }
          }
          
          return {
            name: pkgName,
            version: version,
            path: path.dirname(filePath),
            relativePath: relativePath
          };
        }
      }
    } catch (err) {
      // Continue with fallback
    }
  }
  
  // Fallback: extract from library name (e.g., libssl.so.1.1 -> libssl)
  const filename = path.basename(filePath);
  const libMatch = filename.match(/^(lib[^.]+)/);
  
  return {
    name: libMatch ? libMatch[1] : filename.replace(/\.(so|a)(\.\d+)*$/i, ''),
    version: 'unknown',
    path: path.dirname(filePath),
    relativePath: relativePath
  };
}

/**
 * Alpine (apk) ecosystem
 * System packages tracked in /lib/apk/db/installed
 * Libraries in /usr/lib/, /lib/
 */
function findApkPackageInfo(filePath, rootDir) {
  const relativePath = path.relative(rootDir, filePath);
  
  // Try to find package from Alpine installed database
  const installedPath = path.join(rootDir, 'lib/apk/db/installed');
  if (fs.existsSync(installedPath)) {
    try {
      const installed = fs.readFileSync(installedPath, 'utf8');
      const packages = installed.split('\n\n');
      
      for (const pkg of packages) {
        const lines = pkg.split('\n');
        let pkgName = '';
        let pkgVersion = '';
        const pkgFiles = [];
        
        for (const line of lines) {
          if (line.startsWith('P:')) pkgName = line.substring(2).trim();
          if (line.startsWith('V:')) pkgVersion = line.substring(2).trim();
          if (line.startsWith('F:')) {
            // F: line is followed by R: lines for files in that directory
            const currentDir = line.substring(2).trim();
            // Look ahead for R: lines
            const idx = lines.indexOf(line);
            for (let i = idx + 1; i < lines.length; i++) {
              if (lines[i].startsWith('R:')) {
                pkgFiles.push(currentDir + '/' + lines[i].substring(2).trim());
              } else if (!lines[i].startsWith('a:') && !lines[i].startsWith('Z:')) {
                break;
              }
            }
          }
        }
        
        // Check if our file matches
        const searchPath = relativePath.replace(/\\/g, '/');
        if (pkgFiles.some(f => searchPath === f || searchPath.endsWith('/' + f.split('/').pop()))) {
          return {
            name: pkgName,
            version: pkgVersion,
            path: path.dirname(filePath),
            relativePath: relativePath
          };
        }
        
        // Heuristic match by package name
        if (pkgName && searchPath.toLowerCase().includes(pkgName.toLowerCase())) {
          return {
            name: pkgName,
            version: pkgVersion,
            path: path.dirname(filePath),
            relativePath: relativePath
          };
        }
      }
    } catch (err) {
      // Continue with fallback
    }
  }
  
  // Fallback: extract from library name
  const filename = path.basename(filePath);
  const libMatch = filename.match(/^(lib[^.]+)/);
  
  return {
    name: libMatch ? libMatch[1] : filename.replace(/\.(so|a)(\.\d+)*$/i, ''),
    version: 'unknown',
    path: path.dirname(filePath),
    relativePath: relativePath
  };
}

/**
 * RPM (RHEL/CentOS/Fedora) ecosystem
 * Package database in /var/lib/rpm/
 * Note: Reading RPM DB requires special tools, so we use heuristics
 */
function findRpmPackageInfo(filePath, rootDir) {
  const relativePath = path.relative(rootDir, filePath);
  
  // Check for RPM database existence (indicates RPM-based system)
  const rpmDbPath = path.join(rootDir, 'var/lib/rpm');
  const rpmDbExists = fs.existsSync(rpmDbPath);
  
  // Try to read package info from rpm manifest if available
  // Some container images include /var/lib/rpm/Packages or manifest files
  const manifestPaths = [
    path.join(rootDir, 'var/lib/rpm/rpmdb.sqlite'),
    path.join(rootDir, 'var/lib/rpm/Packages'),
    path.join(rootDir, 'rpm-manifest.txt')
  ];
  
  // For now, use heuristics based on file location and name
  // Full RPM parsing would require librpm bindings
  
  // Common RPM package patterns
  const parts = relativePath.split(path.sep);
  
  // Check /usr/lib64 or /usr/lib patterns
  if (parts.includes('lib64') || parts.includes('lib')) {
    const filename = path.basename(filePath);
    
    // Try to match common library patterns
    // e.g., libcrypto.so.1.1 -> openssl-libs
    const libPatterns = {
      'libcrypto': 'openssl-libs',
      'libssl': 'openssl-libs',
      'libcurl': 'libcurl',
      'libz': 'zlib',
      'libpython': 'python3-libs',
      'libstdc++': 'libstdc++',
      'libgcc': 'libgcc',
      'libc': 'glibc',
      'libm': 'glibc',
      'libpthread': 'glibc',
      'libdl': 'glibc'
    };
    
    for (const [pattern, pkgName] of Object.entries(libPatterns)) {
      if (filename.startsWith(pattern)) {
        return {
          name: pkgName,
          version: 'unknown',
          path: path.dirname(filePath),
          relativePath: relativePath
        };
      }
    }
    
    // Generic library name extraction
    const libMatch = filename.match(/^(lib[^.]+)/);
    if (libMatch) {
      return {
        name: libMatch[1],
        version: 'unknown',
        path: path.dirname(filePath),
        relativePath: relativePath
      };
    }
  }
  
  // Fallback
  const filename = path.basename(filePath);
  return {
    name: filename.replace(/\.(so|a)(\.\d+)*$/i, ''),
    version: 'unknown',
    path: path.dirname(filePath),
    relativePath: relativePath
  };
}

/**
 * Generic/container filesystem
 * For scanning arbitrary directories without package attribution
 */
function findGenericPackageInfo(filePath, rootDir) {
  const relativePath = path.relative(rootDir, filePath);
  const parts = relativePath.split(path.sep);
  
  return {
    name: parts[0] || path.basename(filePath),
    version: 'unknown',
    path: path.join(rootDir, parts[0] || ''),
    relativePath: parts[0] || ''
  };
}

/**
 * Ecosystem definitions
 */
const ECOSYSTEMS = {
  npm: {
    name: 'npm',
    displayName: 'NPM/Node.js',
    directories: ['node_modules'],
    tagPrefix: 'SW_npm',
    findPackageInfo: findNpmPackageInfo,
    description: 'Node.js packages installed via npm/yarn/pnpm'
  },
  pip: {
    name: 'pip',
    displayName: 'Python/pip',
    directories: ['site-packages', 'dist-packages', 'Lib/site-packages'],
    tagPrefix: 'SW_pip',
    findPackageInfo: findPipPackageInfo,
    description: 'Python packages installed via pip'
  },
  maven: {
    name: 'maven',
    displayName: 'Maven/Java',
    directories: ['.m2/repository', 'lib', 'target/dependency'],
    tagPrefix: 'SW_maven',
    findPackageInfo: findMavenPackageInfo,
    description: 'Java packages from Maven repository'
  },
  cargo: {
    name: 'cargo',
    displayName: 'Cargo/Rust',
    directories: ['target/release', 'target/debug'],
    tagPrefix: 'SW_cargo',
    findPackageInfo: findCargoPackageInfo,
    description: 'Rust binaries built with Cargo'
  },
  go: {
    name: 'go',
    displayName: 'Go Modules',
    directories: ['vendor', 'pkg/mod'],
    tagPrefix: 'SW_go',
    findPackageInfo: findGoPackageInfo,
    description: 'Go modules and vendored dependencies'
  },
  ruby: {
    name: 'ruby',
    displayName: 'Ruby Gems',
    directories: ['vendor/bundle', 'gems'],
    tagPrefix: 'SW_ruby',
    findPackageInfo: findRubyPackageInfo,
    description: 'Ruby gems installed via Bundler'
  },
  nuget: {
    name: 'nuget',
    displayName: 'NuGet/.NET',
    directories: ['packages', '.nuget/packages', 'bin/Release', 'bin/Debug'],
    tagPrefix: 'SW_nuget',
    findPackageInfo: findNugetPackageInfo,
    description: '.NET packages from NuGet repository'
  },
  dpkg: {
    name: 'dpkg',
    displayName: 'Debian/Ubuntu',
    // Detection directories (first match triggers ecosystem)
    directories: ['var/lib/dpkg'],
    // Directories to actually scan for binaries (specific arch dirs first, generic as fallback)
    scanDirectories: ['usr/lib/x86_64-linux-gnu', 'lib/x86_64-linux-gnu', 'usr/lib/aarch64-linux-gnu', 'lib/aarch64-linux-gnu', 'usr/bin', 'bin'],
    tagPrefix: 'SW_dpkg',
    findPackageInfo: findDpkgPackageInfo,
    description: 'Debian/Ubuntu system packages (apt/dpkg)'
  },
  apk: {
    name: 'apk',
    displayName: 'Alpine Linux',
    // Detection directories
    directories: ['lib/apk/db'],
    // Directories to actually scan for binaries
    scanDirectories: ['usr/lib', 'lib', 'usr/bin', 'bin'],
    tagPrefix: 'SW_apk',
    findPackageInfo: findApkPackageInfo,
    description: 'Alpine Linux system packages (apk)'
  },
  rpm: {
    name: 'rpm',
    displayName: 'RHEL/CentOS/Fedora',
    // Detection directories
    directories: ['var/lib/rpm'],
    // Directories to actually scan for binaries
    scanDirectories: ['usr/lib64', 'usr/lib', 'lib64', 'lib', 'usr/bin', 'bin'],
    tagPrefix: 'SW_rpm',
    findPackageInfo: findRpmPackageInfo,
    description: 'RPM-based system packages (yum/dnf)'
  },
  generic: {
    name: 'generic',
    displayName: 'Generic',
    directories: ['.'],
    tagPrefix: 'SW_generic',
    findPackageInfo: findGenericPackageInfo,
    description: 'Generic directory scan without package attribution'
  }
};

/**
 * Detect which ecosystems are present in a directory
 * @param {string} targetDir - Directory to scan
 * @returns {string[]} - Array of detected ecosystem names
 */
function detectEcosystems(targetDir) {
  const detected = [];
  
  for (const [name, config] of Object.entries(ECOSYSTEMS)) {
    if (name === 'generic') continue; // Don't auto-detect generic
    
    for (const dir of config.directories) {
      const checkPath = path.join(targetDir, dir);
      if (fs.existsSync(checkPath)) {
        detected.push(name);
        break;
      }
    }
  }
  
  return detected;
}

/**
 * Get ecosystem configuration by name
 * @param {string} name - Ecosystem name
 * @returns {object|null} - Ecosystem configuration
 */
function getEcosystem(name) {
  return ECOSYSTEMS[name] || null;
}

/**
 * Get all available ecosystem names
 * @returns {string[]} - Array of ecosystem names
 */
function getAvailableEcosystems() {
  return Object.keys(ECOSYSTEMS);
}

/**
 * Find the package directory for an ecosystem in a target directory
 * @param {string} targetDir - Target directory
 * @param {string} ecosystemName - Ecosystem name
 * @returns {string|null} - Path to package directory or null
 */
function findEcosystemDirectory(targetDir, ecosystemName) {
  const ecosystem = ECOSYSTEMS[ecosystemName];
  if (!ecosystem) return null;
  
  for (const dir of ecosystem.directories) {
    const checkPath = path.join(targetDir, dir);
    if (fs.existsSync(checkPath)) {
      return checkPath;
    }
  }
  
  return null;
}

/**
 * Find all directories to scan for an ecosystem
 * For Linux package managers, this returns library directories, not package DB
 * @param {string} targetDir - Target directory
 * @param {string} ecosystemName - Ecosystem name
 * @returns {string[]} - Array of paths to scan
 */
function findEcosystemScanDirectories(targetDir, ecosystemName) {
  const ecosystem = ECOSYSTEMS[ecosystemName];
  if (!ecosystem) return [];
  
  // Use scanDirectories if available (for Linux package managers)
  const dirsToCheck = ecosystem.scanDirectories || ecosystem.directories;
  const found = [];
  
  for (const dir of dirsToCheck) {
    const checkPath = path.join(targetDir, dir);
    if (fs.existsSync(checkPath)) {
      found.push(checkPath);
    }
  }
  
  return found;
}

module.exports = {
  ECOSYSTEMS,
  detectEcosystems,
  getEcosystem,
  getAvailableEcosystems,
  findEcosystemDirectory,
  findEcosystemScanDirectories,
  // Export individual finders for testing
  findNpmPackageInfo,
  findPipPackageInfo,
  findMavenPackageInfo,
  findCargoPackageInfo,
  findGoPackageInfo,
  findRubyPackageInfo,
  findNugetPackageInfo,
  findDpkgPackageInfo,
  findApkPackageInfo,
  findRpmPackageInfo,
  findGenericPackageInfo
};
