'use strict';

// Offline dependency CVE & supply-chain auditor for package.json, requirements.txt, and go.mod.

const fs = require('node:fs/promises');
const path = require('node:path');

function parseSemver(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const cleaned = raw.trim().replace(/^[v^~=<>!\s]+/, '');
  const m = cleaned.match(/^(\d+)\.(\d+)(?:\.(\d+))?/);
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3] || 0)];
}

function cmpSemver(a, b) {
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return 0;
}

function isPinnedBelow(spec, fixedStr) {
  if (!spec || typeof spec !== 'string') return false;
  const s = spec.trim();
  if (!s || s === '*' || s === 'latest' || s.startsWith('workspace:') || s.startsWith('file:') || s.startsWith('git')) {
    return false;
  }
  const v = parseSemver(s);
  const fixed = parseSemver(fixedStr);
  if (!v || !fixed) return false;
  return cmpSemver(v, fixed) < 0;
}

const NPM_ADVISORIES = [
  { pkg: 'vm2', below: '999.0.0', severity: 'critical', cwe: 'CWE-94', id: 'dep-npm-vm2-sandbox-escape', title: 'vm2 has unpatched critical sandbox escape CVEs (CVE-2023-37466)', hint: 'Replace vm2 with isolated-vm or Node worker_threads / OS-level sandboxing.' },
  { pkg: 'node-ipc', below: '999.0.0', severity: 'critical', cwe: 'CWE-506', id: 'dep-npm-node-ipc-supply-chain', title: 'node-ipc has documented supply-chain sabotage history', hint: 'Remove node-ipc or replace with standard Node net/ipc primitives.' },
  { pkg: 'lodash', below: '4.17.21', severity: 'high', cwe: 'CWE-1321', id: 'dep-npm-lodash-cve', title: 'lodash < 4.17.21 is vulnerable to Prototype Pollution & Command Injection', hint: 'Upgrade lodash to >= 4.17.21.' },
  { pkg: 'jsonwebtoken', below: '9.0.0', severity: 'high', cwe: 'CWE-287', id: 'dep-npm-jsonwebtoken-cve', title: 'jsonwebtoken < 9.0.0 has key/algorithm confusion CVEs', hint: 'Upgrade jsonwebtoken to >= 9.0.0.' },
  { pkg: 'axios', below: '1.6.0', severity: 'high', cwe: 'CWE-352', id: 'dep-npm-axios-cve', title: 'axios < 1.6.0 is vulnerable to CSRF/SSRF header leakage', hint: 'Upgrade axios to >= 1.6.0.' },
  { pkg: 'express', below: '4.19.2', severity: 'medium', cwe: 'CWE-601', id: 'dep-npm-express-cve', title: 'express < 4.19.2 is vulnerable to open redirect via malformed URLs', hint: 'Upgrade express to >= 4.19.2.' },
  { pkg: 'minimist', below: '1.2.6', severity: 'high', cwe: 'CWE-1321', id: 'dep-npm-minimist-cve', title: 'minimist < 1.2.6 is vulnerable to Prototype Pollution', hint: 'Upgrade minimist to >= 1.2.6.' },
  { pkg: 'qs', below: '6.10.3', severity: 'high', cwe: 'CWE-1321', id: 'dep-npm-qs-cve', title: 'qs < 6.10.3 is vulnerable to Prototype Pollution', hint: 'Upgrade qs to >= 6.10.3.' },
  { pkg: 'semver', below: '7.5.2', severity: 'medium', cwe: 'CWE-1333', id: 'dep-npm-semver-redos', title: 'semver < 7.5.2 is vulnerable to Regular Expression DoS (ReDoS)', hint: 'Upgrade semver to >= 7.5.2.' },
  { pkg: 'serialize-javascript', below: '3.1.0', severity: 'high', cwe: 'CWE-94', id: 'dep-npm-serialize-js-cve', title: 'serialize-javascript < 3.1.0 allows arbitrary code execution via RegExp', hint: 'Upgrade serialize-javascript to >= 3.1.0.' },
  { pkg: 'tar', below: '6.2.1', severity: 'high', cwe: 'CWE-22', id: 'dep-npm-tar-traversal', title: 'node-tar < 6.2.1 is vulnerable to arbitrary file overwrite / path traversal', hint: 'Upgrade tar to >= 6.2.1.' },
  { pkg: 'ws', below: '8.17.1', severity: 'medium', cwe: 'CWE-400', id: 'dep-npm-ws-dos', title: 'ws < 8.17.1 is vulnerable to DoS when handling excessive HTTP headers', hint: 'Upgrade ws to >= 8.17.1.' },
  { pkg: 'handlebars', below: '4.7.7', severity: 'critical', cwe: 'CWE-1321', id: 'dep-npm-handlebars-cve', title: 'handlebars < 4.7.7 allows Prototype Pollution leading to RCE', hint: 'Upgrade handlebars to >= 4.7.7.' },
  { pkg: 'follow-redirects', below: '1.15.6', severity: 'medium', cwe: 'CWE-200', id: 'dep-npm-follow-redirects-cve', title: 'follow-redirects < 1.15.6 leaks Authorization headers on cross-domain redirect', hint: 'Upgrade follow-redirects to >= 1.15.6.' },
];

const PY_ADVISORIES = [
  { pkg: 'pyyaml', below: '5.4.0', severity: 'critical', cwe: 'CWE-502', id: 'dep-py-pyyaml-cve', title: 'PyYAML < 5.4 allows arbitrary code execution via FullLoader', hint: 'Upgrade PyYAML to >= 5.4 and use yaml.safe_load().' },
  { pkg: 'requests', below: '2.31.0', severity: 'medium', cwe: 'CWE-200', id: 'dep-py-requests-cve', title: 'requests < 2.31.0 leaks Proxy-Authorization headers on redirect', hint: 'Upgrade requests to >= 2.31.0.' },
  { pkg: 'urllib3', below: '2.0.7', severity: 'medium', cwe: 'CWE-200', id: 'dep-py-urllib3-cve', title: 'urllib3 < 2.0.7 leaks Cookie/Authorization headers on cross-origin redirects', hint: 'Upgrade urllib3 to >= 2.0.7.' },
  { pkg: 'jinja2', below: '3.1.3', severity: 'high', cwe: 'CWE-79', id: 'dep-py-jinja2-cve', title: 'Jinja2 < 3.1.3 is vulnerable to XSS via xmlattr filter', hint: 'Upgrade Jinja2 to >= 3.1.3.' },
  { pkg: 'django', below: '4.2.11', severity: 'high', cwe: 'CWE-89', id: 'dep-py-django-cve', title: 'Django < 4.2.11 has known SQLi/ReDoS CVEs', hint: 'Upgrade Django to >= 4.2.11.' },
  { pkg: 'fastapi', below: '0.109.1', severity: 'medium', cwe: 'CWE-1333', id: 'dep-py-fastapi-cve', title: 'FastAPI < 0.109.1 is vulnerable to multipart ReDoS', hint: 'Upgrade fastapi to >= 0.109.1.' },
  { pkg: 'cryptography', below: '41.0.6', severity: 'high', cwe: 'CWE-327', id: 'dep-py-cryptography-cve', title: 'cryptography < 41.0.6 has OpenSSL / NULL-pointer dereference CVEs', hint: 'Upgrade cryptography to >= 41.0.6.' },
  { pkg: 'pillow', below: '10.2.0', severity: 'high', cwe: 'CWE-120', id: 'dep-py-pillow-cve', title: 'Pillow < 10.2.0 has arbitrary code execution / buffer overflow CVEs', hint: 'Upgrade Pillow to >= 10.2.0.' },
];

const GO_ADVISORIES = [
  { pkg: 'github.com/dgrijalva/jwt-go', below: '999.0.0', severity: 'high', cwe: 'CWE-287', id: 'dep-go-jwt-go-deprecated', title: 'github.com/dgrijalva/jwt-go is unmaintained with CVE-2020-26160', hint: 'Migrate to github.com/golang-jwt/jwt/v5.' },
  { pkg: 'golang.org/x/crypto', below: '0.17.0', severity: 'high', cwe: 'CWE-287', id: 'dep-go-xcrypto-cve', title: 'golang.org/x/crypto < v0.17.0 has SSH Terrapin prefix truncation CVE', hint: 'Upgrade golang.org/x/crypto to >= v0.17.0.' },
  { pkg: 'golang.org/x/net', below: '0.23.0', severity: 'high', cwe: 'CWE-400', id: 'dep-go-xnet-cve', title: 'golang.org/x/net < v0.23.0 has HTTP/2 Rapid Reset / CONTINUATION flood CVEs', hint: 'Upgrade golang.org/x/net to >= v0.23.0.' },
  { pkg: 'github.com/gin-gonic/gin', below: '1.9.1', severity: 'medium', cwe: 'CWE-20', id: 'dep-go-gin-cve', title: 'gin < v1.9.1 has X-Forwarded-For / route trust CVEs', hint: 'Upgrade github.com/gin-gonic/gin to >= v1.9.1.' },
];

function findLine(text, needle) {
  const lines = text.split(/\r?\n/);
  const idx = lines.findIndex((l) => l.includes(needle));
  return idx >= 0 ? { line: idx + 1, excerpt: lines[idx].trim() } : { line: 1, excerpt: needle };
}

function makeDepFinding(adv, rel, line, excerpt, declaredVersion) {
  return {
    id: `${rel}:${line}:${adv.id}`,
    ruleId: adv.id,
    title: `${adv.title} (declared: ${declaredVersion})`,
    severity: adv.severity,
    cwe: adv.cwe,
    hint: adv.hint,
    confidence: 'high',
    reason: `Dependency "${adv.pkg}" (${declaredVersion}) falls below patched version ${adv.below}.`,
    file: rel,
    line,
    excerpt: String(excerpt || '').slice(0, 220),
  };
}

async function readOptionalFile(filePath) {
  try {
    return await fs.readFile(filePath, 'utf8');
  } catch (err) {
    return err ? null : null;
  }
}

async function auditDependencies(scanRoot) {
  const findings = [];

  // 1. package.json
  const pkgRaw = await readOptionalFile(path.join(scanRoot, 'package.json'));
  if (pkgRaw) {
    try {
      const pkg = JSON.parse(pkgRaw);
      const sections = [pkg.dependencies, pkg.devDependencies, pkg.optionalDependencies];
      for (const deps of sections) {
        if (!deps || typeof deps !== 'object') continue;
        for (const adv of NPM_ADVISORIES) {
          const ver = deps[adv.pkg];
          if (typeof ver === 'string' && isPinnedBelow(ver, adv.below)) {
            const loc = findLine(pkgRaw, `"${adv.pkg}"`);
            findings.push(makeDepFinding(adv, 'package.json', loc.line, loc.excerpt, ver));
          }
        }
      }
    } catch (err) {
      if (err) { /* ignore malformed package.json */ }
    }
  }

  // 2. requirements.txt
  const reqRaw = await readOptionalFile(path.join(scanRoot, 'requirements.txt'));
  if (reqRaw) {
    const lines = reqRaw.split(/\r?\n/);
    lines.forEach((lineText, idx) => {
      const clean = lineText.split('#')[0].trim();
      if (!clean) return;
      const m = clean.match(/^([A-Za-z0-9_.-]+)\s*(?:={2}|<=|~=|<)\s*([0-9][0-9A-Za-z.]*)/);
      if (!m) return;
      const pkgName = m[1].toLowerCase().replace(/_/g, '-');
      const ver = m[2];
      for (const adv of PY_ADVISORIES) {
        if (pkgName === adv.pkg && isPinnedBelow(ver, adv.below)) {
          findings.push(makeDepFinding(adv, 'requirements.txt', idx + 1, lineText.trim(), ver));
        }
      }
    });
  }

  // 3. go.mod
  const goModRaw = await readOptionalFile(path.join(scanRoot, 'go.mod'));
  if (goModRaw) {
    const lines = goModRaw.split(/\r?\n/);
    lines.forEach((lineText, idx) => {
      const clean = lineText.split('//')[0].trim();
      const m = clean.match(/^(?:require\s+)?([^\s]+)\s+(v[0-9]+\.[0-9]+\.[0-9]+[^\s]*)/);
      if (!m) return;
      const pkgName = m[1];
      const ver = m[2];
      for (const adv of GO_ADVISORIES) {
        if (pkgName === adv.pkg && isPinnedBelow(ver, adv.below)) {
          findings.push(makeDepFinding(adv, 'go.mod', idx + 1, lineText.trim(), ver));
        }
      }
    });
  }

  return findings;
}

module.exports = { auditDependencies, isPinnedBelow };
