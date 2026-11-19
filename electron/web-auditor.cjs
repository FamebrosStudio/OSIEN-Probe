'use strict';

// Passive Live Web Auditor for http:// and https:// URLs.
// Performs a single polite GET request (no brute-forcing, no fuzzing, no intrusive payloads)
// and audits HTTP security headers, TLS/HSTS, cookies, server fingerprinting, CSP quality,
// WordPress/CMS passive metadata, and HTML/inline-JS rules via scanner.cjs.

const { scanFileContent, dedupeByCweLocation, rulesForKind, scoreFor, STYLE_HINT_RULES } = require('./scanner.cjs');

function makeWebFinding({ id, title, severity, cwe, hint, reason, url, excerpt }) {
  return {
    id: `${url}:1:${id}`,
    ruleId: id,
    title,
    severity,
    cwe,
    hint,
    confidence: 'high',
    reason,
    file: url,
    line: 1,
    excerpt: String(excerpt || '').trim().slice(0, 220),
  };
}

function getSetCookies(headers) {
  if (typeof headers.getSetCookie === 'function') return headers.getSetCookie();
  const single = headers.get('set-cookie');
  return single ? [single] : [];
}

function analyzeHttpHeaders(finalUrl, headers) {
  const findings = [];
  const isHttps = finalUrl.startsWith('https://');
  const h = (name) => headers.get(name) || '';

  // 1. HSTS on HTTPS
  if (isHttps && !h('strict-transport-security')) {
    findings.push(makeWebFinding({
      id: 'web-missing-hsts',
      title: 'Missing Strict-Transport-Security (HSTS) header',
      severity: 'medium',
      cwe: 'CWE-319',
      hint: 'Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` to enforce HTTPS.',
      reason: 'HTTPS response lacks an HSTS header, leaving initial connections vulnerable to SSL stripping.',
      url: finalUrl,
      excerpt: 'Strict-Transport-Security: (missing)',
    }));
  } else if (!isHttps) {
    findings.push(makeWebFinding({
      id: 'web-insecure-http',
      title: 'Site served over unencrypted HTTP',
      severity: 'high',
      cwe: 'CWE-319',
      hint: 'Redirect all HTTP traffic to HTTPS and enable HSTS.',
      reason: 'Target URL did not upgrade to HTTPS.',
      url: finalUrl,
      excerpt: finalUrl,
    }));
  }

  // 2. Content-Security-Policy quality
  const csp = h('content-security-policy');
  if (!csp) {
    findings.push(makeWebFinding({
      id: 'web-missing-csp',
      title: 'Missing Content-Security-Policy (CSP) header',
      severity: 'medium',
      cwe: 'CWE-693',
      hint: 'Define a Content-Security-Policy restricting script-src, object-src, and frame-ancestors.',
      reason: 'No Content-Security-Policy header was returned.',
      url: finalUrl,
      excerpt: 'Content-Security-Policy: (missing)',
    }));
  } else if (!/\b(?:default-src|script-src)\b/i.test(csp)) {
    findings.push(makeWebFinding({
      id: 'web-weak-csp',
      title: 'Content-Security-Policy lacks script-src / default-src restrictions',
      severity: 'medium',
      cwe: 'CWE-693',
      hint: 'Expand CSP beyond upgrade-insecure-requests to include default-src, script-src, and frame-ancestors.',
      reason: `CSP "${csp.slice(0, 100)}" does not restrict script execution or framing.`,
      url: finalUrl,
      excerpt: `Content-Security-Policy: ${csp}`,
    }));
  }

  // 3. Clickjacking protection (X-Frame-Options or CSP frame-ancestors)
  const xfo = h('x-frame-options');
  if (!xfo && !/\bframe-ancestors\b/i.test(csp)) {
    findings.push(makeWebFinding({
      id: 'web-missing-frame-protection',
      title: 'Missing clickjacking protection (X-Frame-Options / CSP frame-ancestors)',
      severity: 'medium',
      cwe: 'CWE-1021',
      hint: "Set `X-Frame-Options: SAMEORIGIN` and `Content-Security-Policy: frame-ancestors 'self'`.",
      reason: 'Neither X-Frame-Options nor CSP frame-ancestors is present.',
      url: finalUrl,
      excerpt: 'X-Frame-Options: (missing)',
    }));
  }

  // 4. MIME sniffing
  if (h('x-content-type-options').toLowerCase() !== 'nosniff') {
    findings.push(makeWebFinding({
      id: 'web-missing-nosniff',
      title: 'Missing X-Content-Type-Options: nosniff header',
      severity: 'low',
      cwe: 'CWE-16',
      hint: 'Add `X-Content-Type-Options: nosniff` to prevent MIME type confusion.',
      reason: 'Response lacks X-Content-Type-Options: nosniff.',
      url: finalUrl,
      excerpt: 'X-Content-Type-Options: (missing)',
    }));
  }

  // 5. Referrer-Policy & Permissions-Policy
  if (!h('referrer-policy')) {
    findings.push(makeWebFinding({
      id: 'web-missing-referrer-policy',
      title: 'Missing Referrer-Policy header',
      severity: 'low',
      cwe: 'CWE-200',
      hint: 'Set `Referrer-Policy: strict-origin-when-cross-origin` to avoid leaking URL paths/tokens.',
      reason: 'No Referrer-Policy header was returned.',
      url: finalUrl,
      excerpt: 'Referrer-Policy: (missing)',
    }));
  }
  if (!h('permissions-policy')) {
    findings.push(makeWebFinding({
      id: 'web-missing-permissions-policy',
      title: 'Missing Permissions-Policy header',
      severity: 'info',
      cwe: 'CWE-16',
      hint: 'Restrict unused browser features via `Permissions-Policy: camera=(), microphone=(), geolocation=()`.',
      reason: 'No Permissions-Policy header was returned.',
      url: finalUrl,
      excerpt: 'Permissions-Policy: (missing)',
    }));
  }

  // 6. Server/stack version disclosure
  const poweredBy = h('x-powered-by');
  if (poweredBy) {
    findings.push(makeWebFinding({
      id: 'web-server-version-leak',
      title: `Server technology disclosed via X-Powered-By (${poweredBy})`,
      severity: 'low',
      cwe: 'CWE-200',
      hint: 'Disable X-Powered-By in PHP (`expose_php = Off`), Express (`app.disable("x-powered-by")`), or your reverse proxy.',
      reason: `X-Powered-By header exposes exact runtime version "${poweredBy}".`,
      url: finalUrl,
      excerpt: `X-Powered-By: ${poweredBy}`,
    }));
  }

  // 7. Cookie attributes
  for (const rawCookie of getSetCookies(headers)) {
    const cookieName = rawCookie.split('=')[0].trim();
    if (!/\bsamesite=/i.test(rawCookie)) {
      findings.push(makeWebFinding({
        id: 'web-cookie-no-samesite',
        title: `Cookie "${cookieName}" missing SameSite attribute`,
        severity: 'low',
        cwe: 'CWE-352',
        hint: `Add SameSite=Lax (or Strict) to cookie "${cookieName}".`,
        reason: 'Cookie does not specify SameSite attribute.',
        url: finalUrl,
        excerpt: rawCookie.slice(0, 140),
      }));
    }
    if (isHttps && !/\bsecure\b/i.test(rawCookie)) {
      findings.push(makeWebFinding({
        id: 'web-cookie-no-secure',
        title: `Cookie "${cookieName}" missing Secure flag over HTTPS`,
        severity: 'medium',
        cwe: 'CWE-614',
        hint: `Set the Secure flag on "${cookieName}" so it is never sent over cleartext HTTP.`,
        reason: 'HTTPS response sets a cookie without the Secure attribute.',
        url: finalUrl,
        excerpt: rawCookie.slice(0, 140),
      }));
    }
  }

  // 8. Passive WordPress API / metadata exposure
  const linkHdr = h('link');
  if (/wp-json/i.test(linkHdr)) {
    findings.push(makeWebFinding({
      id: 'web-wp-rest-api-exposed',
      title: 'WordPress REST API endpoint advertised in Link header (/wp-json/)',
      severity: 'info',
      cwe: 'CWE-200',
      hint: 'Verify `/wp-json/wp/v2/users` does not enumerate admin usernames and restrict unneeded REST endpoints.',
      reason: 'Response advertises WordPress REST API discovery via Link header.',
      url: finalUrl,
      excerpt: linkHdr.slice(0, 160),
    }));
  }

  return findings;
}

async function scanLiveUrl(targetUrl, options = {}) {
  const startedAt = Date.now();
  const parsed = new URL(targetUrl);
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error(`Unsupported URL protocol "${parsed.protocol}"; expected http: or https:`);
  }

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), options.timeoutMs || 15000);
  let res;
  let html = '';
  try {
    res = await fetch(parsed.toString(), {
      redirect: 'follow',
      headers: { 'user-agent': 'OSIEN-Probe-Auditor/1.0' },
      signal: ctrl.signal,
    });
    const contentType = res.headers.get('content-type') || '';
    if (/text\/html|application\/xhtml/i.test(contentType)) {
      html = await res.text();
    }
  } finally {
    clearTimeout(timer);
  }

  const finalUrl = res.url || parsed.toString();
  const headerFindings = analyzeHttpHeaders(finalUrl, res.headers);
  const htmlList = [];

  if (html) {
    const catalog = rulesForKind('Website');
    const htmlRes = scanFileContent(html, 'index.html', '.html', 'html', catalog, new Map());
    const htmlFindings = Array.isArray(htmlRes) ? htmlRes : (htmlRes?.findings || []);
    for (const f of htmlFindings) {
      if (options.bugsOnly && STYLE_HINT_RULES.has(f.ruleId)) {
        continue;
      }
      if (options.bugsOnly && f.ruleId === 'html-form-get' && /role\s*=\s*["']search["']|search/i.test(f.excerpt || '')) {
        continue;
      }
      htmlList.push(f);
    }
  }

  const combined = [...headerFindings, ...(options.bugsOnly ? dedupeByCweLocation(htmlList) : htmlList)];
  const capped = combined.slice(0, options.maxFindings || 1000);
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of capped) {
    if (severityCounts[f.severity] !== undefined) severityCounts[f.severity]++;
  }

  return {
    root: finalUrl,
    kind: 'Live Website',
    status: res.status,
    scannedFiles: html ? 1 : 0,
    totalRules: 10 + (html ? rulesForKind('Website').length : 0),
    totalChecks: 10 + (html ? rulesForKind('Website').length : 0),
    durationMs: Date.now() - startedAt,
    score: scoreFor(capped),
    severityCounts,
    findings: capped,
    truncated: combined.length > capped.length,
    testCommand: '',
    scannedAt: new Date().toISOString(),
  };
}

module.exports = {
  scanLiveUrl,
  analyzeHttpHeaders,
};
