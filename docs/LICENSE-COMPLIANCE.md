# License Compliance Guide

This guide explains software license compliance, why it matters, and how to use the uc-software-scan's license checking feature.

## Table of Contents

- [Why License Compliance Matters](#why-license-compliance-matters)
- [Understanding Open Source Licenses](#understanding-open-source-licenses)
- [License Categories](#license-categories)
- [Common Licenses Explained](#common-licenses-explained)
- [Using the License Checker](#using-the-license-checker)
- [Creating a Custom Policy](#creating-a-custom-policy)
- [Handling License Issues](#handling-license-issues)
- [Best Practices](#best-practices)

---

## Why License Compliance Matters

### Legal Risks

Open source software comes with legal obligations. Ignoring license terms can lead to:

- **Litigation**: Companies have been sued for license violations
- **Injunctions**: Courts can order you to stop distributing your software
- **Forced disclosure**: You may be required to release your proprietary code
- **Financial damages**: Statutory damages can be significant

### Business Risks

- **Acquisition blockers**: License issues can derail M&A deals
- **Customer concerns**: Enterprise customers often audit dependencies
- **Reputation damage**: Public violations harm your brand
- **Remediation costs**: Replacing non-compliant components is expensive

### The Hidden Danger: Transitive Dependencies

Your direct dependencies may have permissive licenses, but their dependencies might not:

```
your-app (MIT) ✅
  └── package-a (MIT) ✅
       └── package-b (MIT) ✅
            └── package-c (GPL-3.0) ❌ Hidden!
```

This is why automated scanning of the entire dependency tree is essential.

---

## Understanding Open Source Licenses

### Permissive vs. Copyleft

Open source licenses fall into two main categories:

#### Permissive Licenses
- ✅ Allow commercial use
- ✅ Allow modification
- ✅ Allow proprietary derivatives
- ⚠️ Usually require attribution
- **Examples**: MIT, Apache-2.0, BSD

#### Copyleft Licenses
- ✅ Allow commercial use
- ✅ Allow modification
- ❌ Require derivatives to use the same license
- ⚠️ May require source code disclosure
- **Examples**: GPL, AGPL, LGPL

### The "Viral" Effect

Copyleft licenses are sometimes called "viral" because their requirements can propagate:

1. You use a GPL library
2. Your code becomes a "derivative work"
3. Your code must also be GPL
4. Anyone using your code must also be GPL

This is intentional—it's designed to keep software free and open.

---

## License Categories

### ✅ Allowed (Permissive)

These licenses are safe for most commercial use:

| License | Key Points |
|---------|------------|
| **MIT** | Minimal restrictions, just attribution |
| **Apache-2.0** | Attribution + patent grant |
| **BSD-2-Clause** | Simplified BSD, minimal requirements |
| **BSD-3-Clause** | Classic BSD, no endorsement clause |
| **ISC** | Functionally equivalent to MIT |
| **0BSD** | Zero-clause BSD, no requirements |
| **CC0-1.0** | Public domain dedication |
| **Unlicense** | Public domain dedication |

### ⚠️ Warning (Weak Copyleft)

These licenses have conditions that may require review:

| License | Key Points |
|---------|------------|
| **LGPL-2.1/3.0** | Copyleft for library, not your code (if linked correctly) |
| **MPL-2.0** | File-level copyleft, modifications must be shared |
| **EPL-2.0** | Module-level copyleft |
| **CDDL-1.0** | File-level copyleft, patent provisions |
| **Artistic-2.0** | Perl's license, complex terms |
| **CC-BY-SA** | Creative Commons ShareAlike |

### ❌ Denied (Strong Copyleft & Restrictive)

These licenses typically cannot be used in proprietary software:

| License | Risk Level | Why |
|---------|------------|-----|
| **GPL-2.0** | 🔴 High | Strong copyleft, requires source disclosure |
| **GPL-3.0** | 🔴 High | Strong copyleft + anti-tivoization |
| **AGPL-3.0** | 🔴 Critical | Network use triggers copyleft (SaaS killer) |
| **SSPL-1.0** | 🔴 Critical | Service-based copyleft (MongoDB) |
| **CC-BY-NC-*** | 🔴 High | Non-commercial restriction |
| **CC-BY-ND-*** | 🔴 High | No derivatives allowed |

---

## Common Licenses Explained

### MIT License

```
The most popular license on npm (~70% of packages)
```

**You CAN:**
- Use commercially
- Modify the code
- Distribute
- Use privately
- Sublicense

**You MUST:**
- Include copyright notice
- Include license text

**You CANNOT:**
- Hold author liable

### Apache 2.0 License

```
Popular for enterprise projects
```

**You CAN:**
- Use commercially
- Modify the code
- Distribute
- Use privately
- Grant patents

**You MUST:**
- Include copyright notice
- Include license text
- State changes made
- Include NOTICE file (if present)

**You CANNOT:**
- Use trademarks
- Hold author liable

### GPL-3.0 License

```
Strong copyleft - "viral" license
```

**You CAN:**
- Use commercially
- Modify the code
- Distribute
- Use privately

**You MUST:**
- Disclose source code
- Include copyright notice
- Include license text
- State changes made
- Use same license for derivatives

**You CANNOT:**
- Sublicense
- Hold author liable

### AGPL-3.0 License

```
GPL + network use triggers copyleft
```

The AGPL extends GPL to network/SaaS use. If you use AGPL code in a web service, you must provide source code to users of that service.

**Critical for SaaS/Cloud applications**

---

## Using the License Checker

### GitHub Action

```yaml
- name: Scan npm packages
  uses: Unknown-Cyber-Inc/uc-software-scan@v1
  with:
    license-check: 'true'
    license-policy: 'permissive'  # or path to custom policy
    fail-on-license: 'true'
    generate-summary: 'true'
```

### CLI Usage

```bash
# Basic scan
node license-checker.js

# With custom policy
node license-checker.js --policy ./my-policy.json

# With preset
node license-checker.js --policy strict

# Generate GitHub annotations
node license-checker.js --github-annotations --github-summary
```

### Policy Presets

| Preset | Description |
|--------|-------------|
| `permissive` | Default - allows permissive licenses, warns on weak copyleft, denies strong copyleft |
| `strict` | All non-permissive licenses require review |
| `copyleft-ok` | Allows GPL/LGPL (for open source projects) |

---

## Creating a Custom Policy

Create a `license-policy.json` file:

```json
{
  "allowed": [
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC"
  ],
  
  "warning": [
    "LGPL-3.0",
    "MPL-2.0"
  ],
  
  "denied": [
    "GPL-3.0",
    "AGPL-3.0"
  ],
  
  "unknownPolicy": "warning",
  
  "overrides": {
    "internal-package": "allowed",
    "problematic-pkg": "denied"
  }
}
```

### Policy Fields

| Field | Type | Description |
|-------|------|-------------|
| `allowed` | `string[]` | Licenses that pass without issues |
| `warning` | `string[]` | Licenses that need review |
| `denied` | `string[]` | Licenses that fail the check |
| `unknownPolicy` | `string` | How to handle unknown licenses: `allowed`, `warning`, or `denied` |
| `overrides` | `object` | Package-specific overrides |

### Package Overrides

Use overrides for:
- Packages you've reviewed and approved
- Internal packages with custom licenses
- False positives from license detection

```json
{
  "overrides": {
    "company-internal-lib": "allowed",
    "dual-licensed-pkg": "allowed",
    "suspicious-package": "denied"
  }
}
```

---

## Handling License Issues

### When You Find a Denied License

1. **Identify the dependency path**
   ```
   your-app → package-a → package-b (GPL)
   ```

2. **Evaluate alternatives**
   - Is there a permissively-licensed alternative?
   - Can you remove the dependency?

3. **Consult legal** if the package is critical
   - Some use cases may be acceptable
   - Dual-licensing may be available

4. **Consider commercial licenses**
   - Many GPL projects offer commercial licenses
   - Example: Qt, MySQL

5. **Isolate if necessary**
   - Run GPL code in a separate process
   - Communicate via APIs (consult legal)

### When You Find an Unknown License

1. **Check the repository**
   - Look for LICENSE file
   - Check README for license info

2. **Contact the maintainer**
   - Ask them to add SPDX identifier

3. **Add to overrides** if you've verified it's acceptable

---

## Best Practices

### 1. Scan Early and Often

```yaml
# In CI/CD pipeline
on: [push, pull_request]

jobs:
  license-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm install
      - uses: Unknown-Cyber-Inc/uc-software-scan@v1
        with:
          license-check: 'true'
          fail-on-license: 'true'
```

### 2. Block PRs with License Issues

Catch problems before they're merged:

```yaml
- uses: Unknown-Cyber-Inc/uc-software-scan@v1
  with:
    license-check: 'true'
    fail-on-license: 'true'
```

### 3. Maintain an Approved Package List

Create a process for reviewing and approving packages:

1. Developer wants to add a package
2. License check runs automatically
3. If warning/denied, requires review
4. Approved packages added to overrides

### 4. Document Your Policy

- Explain why certain licenses are denied
- Document the review process
- Keep overrides updated with justifications

### 5. Regular Audits

Even with automation:
- Review your policy quarterly
- Check for new license types
- Audit override justifications

---

## SPDX License Identifiers

The scanner uses [SPDX identifiers](https://spdx.org/licenses/) for license normalization:

| Common Variations | SPDX Identifier |
|-------------------|-----------------|
| `MIT`, `MIT License` | `MIT` |
| `Apache 2.0`, `Apache-2` | `Apache-2.0` |
| `BSD`, `BSD-3` | `BSD-3-Clause` |
| `GPL`, `GPLv3` | `GPL-3.0` |

### SPDX Expressions

Some packages use SPDX expressions for dual licensing:

```
MIT OR Apache-2.0        # Either license is acceptable
MIT AND CC-BY-4.0        # Both licenses apply
GPL-2.0-or-later         # GPL 2.0 or any later version
```

---

## Further Reading

- [SPDX License List](https://spdx.org/licenses/)
- [Choose a License](https://choosealicense.com/)
- [tl;drLegal](https://tldrlegal.com/) - Plain English license summaries
- [Open Source Initiative](https://opensource.org/licenses/)
- [GNU License Recommendations](https://www.gnu.org/licenses/license-recommendations.html)

---

## Getting Help

If you encounter license issues:

1. Check this documentation
2. Review the [tl;drLegal](https://tldrlegal.com/) summary for the license
3. Consult your organization's legal team for complex cases
4. Open an issue on the uc-software-scan repository for tool-related problems
