# Supply Chain Scanning Strategy Guide

A practical guide to defending against software supply chain attacks. This document covers **when and where to scan third-party packages** to catch malicious code before it compromises your systems.

---

## The Supply Chain Threat

Software supply chain attacks target the dependencies your code relies on. Unlike vulnerabilities (bugs), these are **intentionally malicious** — attackers compromise packages to execute code on developer machines, build servers, or production systems.

### Notable Incidents

| Attack | Year | Impact |
|--------|------|--------|
| **event-stream** | 2018 | Malicious code targeting Bitcoin wallets |
| **ua-parser-js** | 2021 | Crypto miner + password stealer in 7M+ weekly downloads |
| **colors/faker** | 2022 | Maintainer sabotaged own packages |
| **PyPI typosquatting** | 2022 | 29 malicious packages stealing credentials |
| **Codecov** | 2021 | Supply chain attack via compromised bash uploader |

### Attack Vectors

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      SUPPLY CHAIN ATTACK VECTORS                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. TYPOSQUATTING              2. ACCOUNT TAKEOVER                         │
│     lodahs (not lodash)           Compromised maintainer                   │
│     reqeusts (not requests)       credentials                              │
│                                                                             │
│  3. DEPENDENCY CONFUSION       4. MALICIOUS UPDATE                         │
│     Internal package name          Legitimate package                       │
│     exists on public registry      compromised in new version              │
│                                                                             │
│  5. INSTALL SCRIPT ATTACKS     6. BUILD-TIME ATTACKS                       │
│     postinstall, setup.py          build.rs, build plugins                 │
│     execute on install             execute during compilation              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## The Critical Insight: When Code Executes

**CI/CD is often too late.** By the time code reaches your pipeline, malicious install scripts have already executed on developer machines.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     ATTACK EXECUTION TIMELINE                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Attacker publishes          Developer runs           Code reaches          │
│  malicious package           npm install              CI/CD                 │
│        │                          │                      │                  │
│        ▼                          ▼                      ▼                  │
│   ┌─────────┐              ┌─────────────┐         ┌──────────┐            │
│   │ Registry│─────────────►│  Developer  │────────►│  CI/CD   │            │
│   │  (npm)  │              │   Machine   │         │ Pipeline │            │
│   └─────────┘              └─────────────┘         └──────────┘            │
│                                   │                                         │
│                                   ▼                                         │
│                            ┌─────────────┐                                  │
│                            │ postinstall │  ◄── DAMAGE DONE                │
│                            │   script    │      Credentials stolen         │
│                            │   executes  │      Backdoor installed         │
│                            └─────────────┘                                  │
│                                                                             │
│   ◄─ INTERCEPT HERE ─►    ◄─ DETECT HERE ─►    ◄─── TOO LATE ───►         │
│       (Proactive)            (Reactive)            (Forensics)             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Package Manager Risk Profiles

Different ecosystems have different attack surfaces based on when code can execute.

### Risk Comparison

| Ecosystem | Install-time Execution | Mechanism | Risk Level |
|-----------|------------------------|-----------|------------|
| **npm** | ✅ Yes | `postinstall` scripts | 🔴 Critical |
| **pip** | ✅ Yes | `setup.py` (sdist) | 🔴 Critical |
| **NuGet** | ✅ Yes | PowerShell scripts | 🟠 High |
| **Composer** | ✅ Yes | PHP scripts | 🟠 High |
| **Ruby** | ⚠️ Partial | Native extension build | 🟡 Medium |
| **Maven** | ⚠️ Build-time | Build plugins | 🟡 Medium |
| **Cargo** | ⚠️ Build-time | `build.rs` | 🟡 Medium |
| **Go** | ❌ No | None | 🟢 Low |

### Visual Risk Profile

```
INSTALL-TIME EXECUTION (Highest Risk)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  npm       ████████████████████  postinstall runs immediately
  pip       ████████████████░░░░  setup.py runs for source dists
  NuGet     ████████████░░░░░░░░  install.ps1 PowerShell scripts
  Composer  ████████████░░░░░░░░  post-install-cmd hooks

BUILD-TIME EXECUTION (Medium Risk)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Cargo     ████████░░░░░░░░░░░░  build.rs during cargo build
  Ruby      ████████░░░░░░░░░░░░  extconf.rb for native gems
  Maven     ██████░░░░░░░░░░░░░░  build plugins execution

NO AUTOMATIC EXECUTION (Lowest Risk)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Go        ██░░░░░░░░░░░░░░░░░░  compile only, no install scripts
```

---

## Scanning Strategy: When & Where

### Defense Layers

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      SUPPLY CHAIN DEFENSE LAYERS                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  LAYER 1: Registry Proxy        LAYER 2: Pre-install Hook                  │
│  ┌─────────────────────┐        ┌─────────────────────┐                    │
│  │ Block before it     │        │ Intercept package   │                    │
│  │ reaches ANY machine │        │ install commands    │                    │
│  └─────────────────────┘        └─────────────────────┘                    │
│           │                              │                                  │
│           ▼                              ▼                                  │
│  ┌─────────────────────────────────────────────────────┐                   │
│  │              PACKAGE REGISTRIES                      │                   │
│  │         npm  |  PyPI  |  Maven  |  crates.io        │                   │
│  └─────────────────────────────────────────────────────┘                   │
│                              │                                              │
│                              ▼                                              │
│  LAYER 3: IDE Integration   LAYER 4: Lockfile Git Hook                     │
│  ┌─────────────────────┐    ┌─────────────────────┐                        │
│  │ Warn developers in  │    │ Scan only changed   │                        │
│  │ real-time           │    │ packages at commit  │                        │
│  └─────────────────────┘    └─────────────────────┘                        │
│                              │                                              │
│                              ▼                                              │
│  LAYER 5: PR CI (Diff Only) LAYER 6: Dependency Bot Scan                   │
│  ┌─────────────────────┐    ┌─────────────────────┐                        │
│  │ Scan new packages   │    │ Deep scan automated │                        │
│  │ in lockfile diff    │    │ dependency updates  │                        │
│  └─────────────────────┘    └─────────────────────┘                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Layer 1: Registry Proxy / Supply Chain Firewall

**When:** Before package reaches ANY machine  
**Effectiveness:** Highest — blocks threats at the source

```
┌──────────────┐     ┌───────────────────┐     ┌─────────────────┐
│   Public     │────►│  Proxy/Firewall   │────►│   Developer     │
│   Registry   │     │                   │     │   Machines      │
│  (npm, PyPI) │     │ • Scan packages   │     │                 │
└──────────────┘     │ • Block malicious │     │   CI/CD         │
                     │ • Cache approved  │     │                 │
                     └───────────────────┘     └─────────────────┘
```

**Tools:**
- [Socket.dev](https://socket.dev) — Purpose-built supply chain firewall
- [Snyk](https://snyk.io) — Registry integration
- [Artifactory](https://jfrog.com/artifactory/) — Private registry with scanning
- [Nexus Repository](https://www.sonatype.com/products/nexus-repository) — Repository manager
- [Cloudsmith](https://cloudsmith.com) — Hosted with security policies

**Pros:**
- Blocks before any code execution
- Organizational control
- Zero developer friction
- Works for all ecosystems

**Cons:**
- Infrastructure cost
- Subscription fees
- Initial setup complexity

---

## Layer 2: Pre-install Hook

**When:** After install command, before download/execution  
**Effectiveness:** High — last chance before code runs

### npm / Node.js

```bash
# Option 1: Disable scripts entirely (aggressive)
# .npmrc
ignore-scripts=true

# Option 2: Custom npm wrapper
#!/bin/bash
# /usr/local/bin/npm-safe
packages=$(echo "$@" | grep -E 'install|add|i ' | grep -oE '[a-z0-9@/_-]+')
for pkg in $packages; do
  # Check against threat database
  if curl -s "https://api.yourscanner.com/check/$pkg" | grep -q '"malicious":true'; then
    echo "🚫 BLOCKED: $pkg is flagged as malicious"
    exit 1
  fi
done
exec /usr/bin/npm "$@"
```

### pip / Python

```bash
# Option 1: Prefer wheels (no setup.py execution)
pip install --only-binary=:all: package-name

# Option 2: Disable build isolation
pip install --no-build-isolation package-name

# Option 3: Pre-install audit
pip-audit -r requirements.txt && pip install -r requirements.txt
```

### Universal: Husky Hook (Node.js projects)

```json
// package.json
{
  "scripts": {
    "preinstall": "node scripts/check-new-deps.js"
  }
}
```

---

## Layer 3: IDE Integration

**When:** During development, real-time  
**Effectiveness:** Medium — awareness, not prevention

```
┌─────────────────────────────────────────────────────────┐
│  package.json                                           │
├─────────────────────────────────────────────────────────┤
│  "dependencies": {                                      │
│    "lodash": "^4.17.21",           ✅ Safe             │
│    "event-stream": "3.3.6",        ⚠️ Known malicious  │
│    "ua-parser-js": "0.7.29",       🔴 Compromised      │
│    "left-pad": "1.3.0",            ℹ️ Deprecated       │
│  }                                                      │
└─────────────────────────────────────────────────────────┘
```

**Tools:**
- [Socket.dev VS Code Extension](https://marketplace.visualstudio.com/items?itemName=SocketSecurity.vscode-socket-security)
- [Snyk VS Code Extension](https://marketplace.visualstudio.com/items?itemName=snyk-security.snyk-vulnerability-scanner)
- JetBrains built-in package security

---

## Layer 4: Lockfile Git Hook

**When:** At commit time, when lockfile changes  
**Effectiveness:** Medium — catches before team exposure

### Universal Pre-commit Hook

```bash
#!/bin/bash
# .husky/pre-commit or .git/hooks/pre-commit

# Detect which lockfiles changed
changed_lockfiles=$(git diff --cached --name-only | grep -E \
  'package-lock\.json|yarn\.lock|pnpm-lock\.yaml|requirements.*\.txt|Pipfile\.lock|poetry\.lock|Cargo\.lock|go\.sum|Gemfile\.lock|composer\.lock|packages\.lock\.json')

if [ -z "$changed_lockfiles" ]; then
  exit 0  # No lockfile changes
fi

echo "📦 Lockfile changes detected - scanning new dependencies..."

for lockfile in $changed_lockfiles; do
  echo "Analyzing: $lockfile"
  
  # Extract new packages based on file type
  case "$lockfile" in
    package-lock.json|yarn.lock|pnpm-lock.yaml)
      new_pkgs=$(git diff --cached "$lockfile" | grep -oE '"[a-z0-9@/_-]+":' | tr -d '":' | sort -u | head -20)
      ;;
    requirements*.txt)
      new_pkgs=$(git diff --cached "$lockfile" | grep -E '^\+[a-zA-Z]' | sed 's/^+//' | cut -d'=' -f1 | head -20)
      ;;
    Cargo.lock)
      new_pkgs=$(git diff --cached "$lockfile" | grep -E '^\+name = ' | sed 's/.*"\(.*\)"/\1/' | head -20)
      ;;
    go.sum)
      new_pkgs=$(git diff --cached "$lockfile" | grep -E '^\+[a-z]' | awk '{print $1}' | sort -u | head -20)
      ;;
  esac
  
  if [ -n "$new_pkgs" ]; then
    echo "New packages:"
    echo "$new_pkgs"
    # Add your scanning logic here
    # node scan-packages.js $new_pkgs
  fi
done
```

---

## Layer 5: PR CI (Lockfile Diff Only)

**When:** In pull request, when lockfile changes  
**Effectiveness:** Medium — team gate, but after local install

### The "Changed Packages Only" Principle

```
Traditional:                          Smart:
┌─────────────────────┐              ┌─────────────────────┐
│  Scan all 1,500     │              │  Scan only 3 new    │
│  dependencies       │              │  packages added     │
│                     │              │                     │
│  Time: 5 minutes    │              │  Time: 5 seconds    │
│  Cost: $0.04        │              │  Cost: $0.001       │
│  Signal: Noisy      │              │  Signal: Clear      │
└─────────────────────┘              └─────────────────────┘
```

### GitHub Actions Workflow

```yaml
# .github/workflows/supply-chain-scan.yml
name: Supply Chain Scan

on:
  pull_request:
    paths:
      # npm
      - 'package-lock.json'
      - 'yarn.lock'
      - 'pnpm-lock.yaml'
      # pip
      - 'requirements*.txt'
      - 'Pipfile.lock'
      - 'poetry.lock'
      # Cargo
      - 'Cargo.lock'
      # Go
      - 'go.sum'
      # Ruby
      - 'Gemfile.lock'
      # NuGet
      - 'packages.lock.json'
      # Composer
      - 'composer.lock'

jobs:
  scan-changed-deps:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - name: Detect changed packages
        id: detect
        run: |
          # Get the diff
          git diff origin/${{ github.base_ref }}...HEAD --name-only > changed_files.txt
          
          # Process npm lockfiles
          if grep -q 'package-lock.json' changed_files.txt; then
            git diff origin/${{ github.base_ref }}...HEAD -- package-lock.json | \
              grep -oE '"resolved": "https://registry.npmjs.org/([^/]+)' | \
              sed 's/.*org\///' | sort -u > new_npm_packages.txt
            echo "npm_packages=$(cat new_npm_packages.txt | tr '\n' ' ')" >> $GITHUB_OUTPUT
          fi
          
          # Process pip requirements
          if grep -qE 'requirements.*\.txt' changed_files.txt; then
            git diff origin/${{ github.base_ref }}...HEAD -- 'requirements*.txt' | \
              grep -E '^\+[a-zA-Z]' | sed 's/^+//' | \
              cut -d'=' -f1 | cut -d'>' -f1 | sort -u > new_pip_packages.txt
            echo "pip_packages=$(cat new_pip_packages.txt | tr '\n' ' ')" >> $GITHUB_OUTPUT
          fi
      
      - name: Scan new npm packages
        if: steps.detect.outputs.npm_packages != ''
        run: |
          echo "🔍 Scanning new npm packages:"
          echo "${{ steps.detect.outputs.npm_packages }}"
          # Add your scanning logic
          # npx socket-security scan ${{ steps.detect.outputs.npm_packages }}
      
      - name: Scan new pip packages
        if: steps.detect.outputs.pip_packages != ''
        run: |
          echo "🔍 Scanning new pip packages:"
          echo "${{ steps.detect.outputs.pip_packages }}"
          # pip-audit package1 package2
```

---

## Layer 6: Dependency Bot Integration

**When:** When Dependabot/Renovate proposes updates  
**Effectiveness:** High for updates — focused deep analysis

```yaml
# Trigger specifically on dependency bot PRs
name: Scan Dependency Updates

on:
  pull_request:
    types: [opened, synchronize]

jobs:
  scan-update:
    if: |
      github.actor == 'dependabot[bot]' || 
      github.actor == 'renovate[bot]'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Parse update from PR title
        id: parse
        run: |
          # PR title: "Bump lodash from 4.17.20 to 4.17.21"
          title="${{ github.event.pull_request.title }}"
          package=$(echo "$title" | grep -oE 'Bump [a-z0-9@/_-]+' | sed 's/Bump //')
          from_ver=$(echo "$title" | grep -oE 'from [0-9.]+' | sed 's/from //')
          to_ver=$(echo "$title" | grep -oE 'to [0-9.]+' | sed 's/to //')
          
          echo "package=$package" >> $GITHUB_OUTPUT
          echo "from=$from_ver" >> $GITHUB_OUTPUT
          echo "to=$to_ver" >> $GITHUB_OUTPUT
      
      - name: Deep scan package update
        run: |
          echo "📦 Scanning: ${{ steps.parse.outputs.package }}"
          echo "Version change: ${{ steps.parse.outputs.from }} → ${{ steps.parse.outputs.to }}"
          
          # Deep analysis:
          # 1. Check for new maintainers
          # 2. Scan for new install scripts
          # 3. Compare code diff between versions
          # 4. Check for suspicious patterns
```

---

## Ecosystem-Specific Lockfile Patterns

### Detection Patterns by Ecosystem

| Ecosystem | Lockfile(s) | New Package Pattern |
|-----------|-------------|---------------------|
| **npm** | `package-lock.json` | `+"resolved": "https://registry.npmjs.org/PACKAGE` |
| **Yarn** | `yarn.lock` | `+PACKAGE@version:` |
| **pnpm** | `pnpm-lock.yaml` | `+  /PACKAGE@version:` |
| **pip** | `requirements.txt` | `+PACKAGE==version` |
| **Poetry** | `poetry.lock` | `+name = "PACKAGE"` |
| **Pipenv** | `Pipfile.lock` | `+"PACKAGE":` |
| **Cargo** | `Cargo.lock` | `+name = "PACKAGE"` |
| **Go** | `go.sum` | `+module/path vX.Y.Z` |
| **Ruby** | `Gemfile.lock` | `+    PACKAGE (version)` |
| **NuGet** | `packages.lock.json` | `+"PACKAGE":` |
| **Composer** | `composer.lock` | `+"name": "vendor/PACKAGE"` |
| **Maven** | `pom.xml` | `+<artifactId>PACKAGE</artifactId>` |

---

## Recommended Strategy Summary

| Layer | When | What | Catches | Cost |
|-------|------|------|---------|------|
| **Registry Proxy** | Before download | All packages | Known threats | $$$ |
| **Pre-install Hook** | Before install | New packages | Active threats | $ |
| **IDE Plugin** | During dev | All deps | Awareness | Free |
| **Lockfile Git Hook** | At commit | Changed deps | Before push | Free |
| **PR CI (diff only)** | At PR | Changed deps | Team gate | $ |
| **Dependency Bot Scan** | On bot PRs | Updated deps | Compromised updates | $ |

### Priority Order

1. **Today:** Enable lockfile diff scanning in PRs
2. **This week:** Add pre-commit hook for lockfile changes
3. **This month:** Evaluate registry proxy solutions
4. **Ongoing:** Deep scan dependency bot updates

---

## Mitigations by Attack Vector

| Attack Vector | Best Defense | Layer |
|---------------|--------------|-------|
| **Typosquatting** | Registry proxy blocklist | 1 |
| **Account takeover** | Maintainer change detection | 5, 6 |
| **Dependency confusion** | Internal registry priority | 1 |
| **Malicious update** | Version diff analysis | 6 |
| **Install scripts** | Disable scripts / sandbox | 2 |
| **Build-time attacks** | Build isolation | N/A |

---

## Tools Reference

| Category | Tool | Best For |
|----------|------|----------|
| **Registry Proxy** | [Socket.dev](https://socket.dev) | npm, PyPI firewall |
| **Registry Proxy** | [Artifactory](https://jfrog.com) | Multi-ecosystem proxy |
| **Vulnerability DB** | [Snyk](https://snyk.io) | Known CVEs |
| **npm Audit** | `npm audit` | Built-in npm scanning |
| **pip Audit** | [pip-audit](https://github.com/pypa/pip-audit) | Python vulnerabilities |
| **Cargo Audit** | `cargo audit` | Rust vulnerabilities |
| **Go Vuln** | `govulncheck` | Go vulnerabilities |
| **Universal** | [Trivy](https://github.com/aquasecurity/trivy) | Multi-ecosystem |

---

## See Also

- [Security Scanning Strategy](./SECURITY-SCANNING-STRATEGY.md) — Config scanning strategy
- [Software Misconfiguration Scanner](./SOFTWARE-MISCONFIGURATIONS.md) — Config scanner docs
- [UC Software Scan Action](../README.md) — Main documentation
