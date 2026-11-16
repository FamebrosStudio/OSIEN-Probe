'use strict';

const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { spawn } = require('node:child_process');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
};

const activeRuns = new Map();

function getSystemProfile() {
  const cpus = os.cpus() || [];
  const totalBytes = os.totalmem();
  const freeBytes = os.freemem();
  const totalMemGb = Math.round((totalBytes / (1024 ** 3)) * 10) / 10;
  const freeMemGb = Math.round((freeBytes / (1024 ** 3)) * 10) / 10;
  const cpuCores = cpus.length || 2;
  const cpuModel = cpus[0]?.model?.trim() || 'Local CPU';
  const tier = totalMemGb >= 15 && cpuCores >= 8 ? 'high' : totalMemGb >= 7 && cpuCores >= 4 ? 'balanced' : 'light';
  const maxSteps = tier === 'high' ? 80 : tier === 'balanced' ? 55 : 35;
  const stepDelayMs = tier === 'high' ? 140 : tier === 'balanced' ? 200 : 280;
  return { cpuModel, cpuCores, totalMemGb, freeMemGb, tier, maxSteps, stepDelayMs };
}

async function fileExists(target) {
  try {
    const stat = await fs.stat(target);
    return stat.isFile();
  } catch {
    return false;
  }
}

async function detectWebEntry(root) {
  const pkgPath = path.join(root, 'package.json');
  if (await fileExists(pkgPath)) {
    try {
      const pkg = JSON.parse(await fs.readFile(pkgPath, 'utf8'));
      const scripts = pkg.scripts || {};
      const scriptName = scripts.dev ? 'dev' : scripts.preview ? 'preview' : scripts.start ? 'start' : null;
      if (scriptName) {
        return { mode: 'npm', scriptName, command: `npm run ${scriptName}` };
      }
    } catch {
      // Fall through to static detection when package.json cannot be parsed.
    }
  }
  for (const candidate of ['index.html', 'public/index.html', 'dist/index.html', 'build/index.html']) {
    const full = path.join(root, candidate);
    if (await fileExists(full)) {
      return { mode: 'static', entryDir: path.dirname(full), entryFile: candidate };
    }
  }
  return { mode: 'static', entryDir: root, entryFile: null };
}

function startStaticSandboxServer(entryDir) {
  return new Promise((resolve, reject) => {
    const rootResolved = path.resolve(entryDir);
    const server = http.createServer(async (req, res) => {
      try {
        const reqUrl = new URL(req.url || '/', 'http://127.0.0.1');
        const cleanPath = decodeURIComponent(reqUrl.pathname).replace(/^\/+/, '');
        let target = path.resolve(rootResolved, cleanPath || 'index.html');
        if (!target.startsWith(rootResolved)) {
          res.writeHead(403);
          res.end('Forbidden');
          return;
        }
        let stat;
        try {
          stat = await fs.stat(target);
          if (stat.isDirectory()) target = path.join(target, 'index.html');
        } catch {
          target = path.join(rootResolved, 'index.html');
        }
        const data = await fs.readFile(target);
        const ext = path.extname(target).toLowerCase();
        res.writeHead(200, { 'Content-Type': MIME_TYPES[ext] || 'application/octet-stream' });
        res.end(data);
      } catch {
        res.writeHead(404);
        res.end('Not found');
      }
    });
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolve({
        url: `http://127.0.0.1:${addr.port}`,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

function killProcessTree(child) {
  if (!child || child.killed) return;
  try {
    if (process.platform === 'win32' && child.pid) {
      spawn('taskkill', ['/pid', String(child.pid), '/t', '/f'], { windowsHide: true });
    } else {
      child.kill('SIGTERM');
    }
  } catch {
    // Process may already have exited.
  }
}

const ANSI_RE = new RegExp('\\u001b\\[[0-9;]*[A-Za-z]', 'g');
function stripAnsi(text) {
  return String(text || '').replace(ANSI_RE, '');
}

function startNpmSandboxServer(root, scriptName, onLog) {
  return new Promise((resolve, reject) => {
    if (!/^[a-zA-Z0-9:_-]+$/.test(scriptName)) {
      reject(new Error(`Invalid npm script name: ${scriptName}`));
      return;
    }
    const env = {
      PATH: process.env.PATH,
      SystemRoot: process.env.SystemRoot || process.env.SYSTEMROOT,
      SYSTEMROOT: process.env.SYSTEMROOT || process.env.SystemRoot,
      ComSpec: process.env.ComSpec,
      HOME: process.env.HOME,
      USERPROFILE: process.env.USERPROFILE,
      APPDATA: process.env.APPDATA,
      LOCALAPPDATA: process.env.LOCALAPPDATA,
      TEMP: process.env.TEMP,
      TMP: process.env.TMP,
      BROWSER: 'none',
      PORT: '4179',
      FORCE_COLOR: '0',
      NO_COLOR: '1',
    };
    const child = process.platform === 'win32'
      ? spawn(process.env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', `npm.cmd run ${scriptName}`], {
          cwd: root,
          windowsHide: true,
          env,
        })
      : spawn('npm', ['run', scriptName], {
          cwd: root,
          windowsHide: true,
          env,
        });

    let settled = false;
    const timeout = setTimeout(() => {
      if (!settled) {
        settled = true;
        killProcessTree(child);
        reject(new Error(`Timed out waiting for "npm run ${scriptName}" to expose a local URL.`));
      }
    }, 25000);

    const handleChunk = (chunk) => {
      const text = stripAnsi(chunk.toString('utf8'));
      for (const line of text.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (trimmed) onLog(trimmed);
        const match = trimmed.match(/https?:\/\/(?:localhost|127\.0\.0\.1|\[::1\]):\d{2,5}[^\s]*/i);
        if (match && !settled) {
          settled = true;
          clearTimeout(timeout);
          resolve({
            url: match[0],
            close: async () => {
              killProcessTree(child);
            },
          });
        }
      }
    };

    child.stdout.on('data', handleChunk);
    child.stderr.on('data', handleChunk);
    child.on('error', (err) => {
      if (!settled) {
        settled = true;
        clearTimeout(timeout);
        reject(err);
      }
    });
    child.on('exit', (code) => {
      if (!settled) {
        settled = true;
        clearTimeout(timeout);
        reject(new Error(`Dev server exited early with code ${code}.`));
      }
    });
  });
}

// Pure-DOM autonomous exploration & defensive stress script injected into the sandboxed page.
function buildExtremeProbeScript(stepIndex) {
  return `(() => {
    const STEP = ${Number(stepIndex)};
    const PROBE_ID = '__osien_probe_cursor__';
    let cursor = document.getElementById(PROBE_ID);
    if (!cursor) {
      cursor = document.createElement('div');
      cursor.id = PROBE_ID;
      cursor.style.cssText = 'position:fixed;z-index:2147483647;width:18px;height:18px;border-radius:50%;border:2px solid #a8c77e;background:rgba(140,207,94,0.28);box-shadow:0 0 12px rgba(168,199,126,0.75);pointer-events:none;transition:left .12s ease,top .12s ease,transform .1s ease;left:16px;top:16px;';
      document.documentElement.appendChild(cursor);
    }

    const findings = [];
    const checkPageHealth = () => {
      // 1. Check for horizontal layout overflow
      if (document.documentElement.scrollWidth > window.innerWidth + 8) {
        findings.push({
          ruleId: 'extreme-layout-overflow',
          title: 'Horizontal layout overflow detected',
          severity: 'low',
          cwe: 'CWE-1084',
          detail: 'scrollWidth (' + document.documentElement.scrollWidth + 'px) exceeds viewport (' + window.innerWidth + 'px)',
        });
      }
      // 2. Check for broken images
      for (const img of document.querySelectorAll('img')) {
        if (img.complete && img.naturalWidth === 0 && img.getAttribute('src')) {
          findings.push({
            ruleId: 'extreme-broken-image',
            title: 'Broken image failed to load',
            severity: 'low',
            cwe: 'CWE-404',
            detail: img.getAttribute('src'),
          });
        }
      }
      // 3. Check for unescaped probe marker rendered as a live DOM element
      if (document.querySelector('[data-osien-xss-probe="1"]')) {
        findings.push({
          ruleId: 'extreme-dom-xss-unescaped',
          title: 'Unescaped HTML/XSS input rendered as live DOM node',
          severity: 'critical',
          cwe: 'CWE-79',
          detail: 'Fuzzed input containing <b data-osien-xss-probe="1"> was parsed as active HTML in the DOM.',
        });
      }
      // 4. Check external target=_blank links missing noopener
      for (const a of document.querySelectorAll('a[target="_blank"]')) {
        const rel = (a.getAttribute('rel') || '').toLowerCase();
        if (!rel.includes('noopener')) {
          findings.push({
            ruleId: 'extreme-tabnabbing-link',
            title: 'target="_blank" link missing rel="noopener"',
            severity: 'medium',
            cwe: 'CWE-1022',
            detail: a.getAttribute('href') || a.textContent.trim().slice(0, 60),
          });
        }
      }
    };

    const isVisible = (el) => {
      if (!el || el.id === PROBE_ID) return false;
      const r = el.getBoundingClientRect();
      const s = getComputedStyle(el);
      return r.width > 4 && r.height > 4 && s.visibility !== 'hidden' && s.display !== 'none' && !el.disabled;
    };

    const inputs = [...document.querySelectorAll('input:not([type="hidden"]):not([type="checkbox"]):not([type="radio"]), textarea, select')].filter(isVisible);
    const clickables = [...document.querySelectorAll('button, a[href], [role="button"], input[type="submit"], input[type="button"]')].filter(isVisible);

    const fuzzPayloads = [
      '',
      '<b data-osien-xss-probe="1">probe</b>',
      "' OR '1'='1",
      '-999999',
      'A'.repeat(280),
      'probe@example.com',
    ];

    let action = 'idle';
    let targetLabel = '';
    const interacted = window.__osienVisited || (window.__osienVisited = new Set());

    // Prefer filling an untouched visible input first, otherwise click an interactive control
    const nextInput = inputs.find((el, idx) => !interacted.has('in:' + idx + ':' + (el.name || el.id || el.type)));
    if (nextInput) {
      const idx = inputs.indexOf(nextInput);
      const key = 'in:' + idx + ':' + (nextInput.name || nextInput.id || nextInput.type);
      interacted.add(key);
      const r = nextInput.getBoundingClientRect();
      cursor.style.left = Math.max(4, r.left + r.width / 2 - 9) + 'px';
      cursor.style.top = Math.max(4, r.top + r.height / 2 - 9) + 'px';
      nextInput.scrollIntoView({ block: 'nearest', behavior: 'instant' });
      const payload = fuzzPayloads[STEP % fuzzPayloads.length];
      if (nextInput.tagName === 'SELECT') {
        const opts = nextInput.options;
        if (opts.length > 0) nextInput.selectedIndex = (STEP % opts.length);
      } else {
        const proto = nextInput.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
        const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
        if (setter) setter.call(nextInput, payload);
        else nextInput.value = payload;
      }
      nextInput.dispatchEvent(new Event('input', { bubbles: true }));
      nextInput.dispatchEvent(new Event('change', { bubbles: true }));
      action = 'fuzz-input';
      targetLabel = (nextInput.getAttribute('aria-label') || nextInput.name || nextInput.placeholder || nextInput.tagName).slice(0, 48);
    } else if (clickables.length > 0) {
      const candidate = clickables[STEP % clickables.length];
      const r = candidate.getBoundingClientRect();
      cursor.style.left = Math.max(4, r.left + r.width / 2 - 9) + 'px';
      cursor.style.top = Math.max(4, r.top + r.height / 2 - 9) + 'px';
      cursor.style.transform = 'scale(1.35)';
      setTimeout(() => { cursor.style.transform = 'scale(1)'; }, 90);
      candidate.scrollIntoView({ block: 'nearest', behavior: 'instant' });
      targetLabel = (candidate.innerText || candidate.getAttribute('aria-label') || candidate.getAttribute('href') || candidate.tagName).trim().slice(0, 48);
      action = STEP % 5 === 0 ? 'stress-double-click' : 'click';
      const href = candidate.getAttribute('href') || '';
      if (candidate.tagName === 'A' && /^https?:\\/\\//i.test(href) && !href.startsWith(location.origin)) {
        action = 'skip-external-link';
      } else {
        candidate.click();
        if (action === 'stress-double-click') candidate.click();
      }
    }

    checkPageHealth();
    return {
      url: location.href,
      title: document.title,
      action,
      targetLabel,
      inputsCount: inputs.length,
      clickablesCount: clickables.length,
      findings,
    };
  })()`;
}

async function runExtremeTest({ project, BrowserWindow, session, onEvent }) {
  if (activeRuns.has(project.id)) {
    throw new Error('An Extreme Sandbox Test is already running for this project.');
  }
  const profile = getSystemProfile();
  const state = { cancelled: false, win: null, server: null };
  activeRuns.set(project.id, state);

  const emit = (type, payload) => {
    try {
      onEvent({ projectId: project.id, type, ...payload });
    } catch {
      // Renderer may have closed.
    }
  };

  const emittedFindings = new Set();
  const pushFinding = (f) => {
    const key = `${f.ruleId}:${f.detail || f.title}`;
    if (emittedFindings.has(key)) return;
    emittedFindings.add(key);
    emit('finding', { finding: f });
  };

  try {
    emit('log', { level: 'info', text: `PC profile: ${profile.cpuCores} cores, ${profile.totalMemGb} GB RAM (${profile.tier} tier · ${profile.maxSteps} autonomous steps)` });
    const entry = await detectWebEntry(project.root);
    emit('log', { level: 'info', text: entry.mode === 'npm' ? `Starting sandboxed dev server (${entry.command})…` : `Starting isolated static sandbox server on 127.0.0.1…` });

    const server = entry.mode === 'npm'
      ? await startNpmSandboxServer(project.root, entry.scriptName, (line) => emit('log', { level: 'server', text: line }))
      : await startStaticSandboxServer(entry.entryDir);
    state.server = server;
    if (state.cancelled) return { cancelled: true };

    const targetUrl = new URL(server.url);
    const targetPort = targetUrl.port;
    const allowedOrigins = new Set([
      targetUrl.origin,
      `http://localhost${targetPort ? `:${targetPort}` : ''}`,
      `http://127.0.0.1${targetPort ? `:${targetPort}` : ''}`,
      `http://[::1]${targetPort ? `:${targetPort}` : ''}`,
    ]);
    emit('log', { level: 'info', text: `Sandbox live at ${server.url} — external network blocked` });

    const sandboxSession = session.fromPartition(`osien-sandbox-${project.id}-${Date.now()}`, { cache: false });
    sandboxSession.webRequest.onBeforeRequest((details, callback) => {
      const u = details.url || '';
      const allowed = [...allowedOrigins].some((o) => u.startsWith(o)) || u.startsWith('data:') || u.startsWith('blob:') || u.startsWith('devtools:');
      if (!allowed) {
        emit('log', { level: 'warn', text: `Sandbox blocked outbound request: ${u.slice(0, 90)}` });
      }
      callback({ cancel: !allowed });
    });

    let headerChecked = false;
    sandboxSession.webRequest.onCompleted((details) => {
      if (details.statusCode >= 500) {
        pushFinding({
          ruleId: 'extreme-http-5xx',
          title: `Server returned HTTP ${details.statusCode}`,
          severity: 'high',
          cwe: 'CWE-703',
          detail: details.url,
        });
      }
      if (!headerChecked && details.resourceType === 'mainFrame') {
        headerChecked = true;
        const headers = details.responseHeaders || {};
        const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), Array.isArray(v) ? v.join(', ') : String(v)]));
        if (!lower['content-security-policy']) {
          pushFinding({
            ruleId: 'extreme-missing-csp',
            title: 'Missing Content-Security-Policy header on document response',
            severity: 'medium',
            cwe: 'CWE-693',
            detail: details.url,
          });
        }
        if (!lower['x-content-type-options']) {
          pushFinding({
            ruleId: 'extreme-missing-xcto',
            title: 'Missing X-Content-Type-Options: nosniff header',
            severity: 'low',
            cwe: 'CWE-693',
            detail: details.url,
          });
        }
      }
    });

    const win = new BrowserWindow({
      width: 1120,
      height: 740,
      show: false,
      webPreferences: {
        offscreen: true,
        session: sandboxSession,
        sandbox: true,
        contextIsolation: true,
        nodeIntegration: false,
        webSecurity: true,
      },
    });
    state.win = win;

    win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
    win.webContents.on('console-message', (_e, level, msg, line, sourceId) => {
      if (level >= 3) {
        pushFinding({
          ruleId: 'extreme-console-error',
          title: 'Runtime console error in browser',
          severity: 'medium',
          cwe: 'CWE-390',
          detail: `${msg} (${sourceId || 'page'}:${line})`.slice(0, 180),
        });
      }
    });
    win.webContents.on('render-process-gone', (_e, details) => {
      pushFinding({
        ruleId: 'extreme-renderer-crash',
        title: `Browser tab crashed (${details.reason})`,
        severity: 'critical',
        cwe: 'CWE-248',
        detail: `Exit code ${details.exitCode}`,
      });
    });

    await win.loadURL(server.url);

    let clicks = 0;
    let inputsFuzzed = 0;
    const routes = new Set([server.url]);

    for (let step = 0; step < profile.maxSteps; step++) {
      if (state.cancelled || win.isDestroyed()) break;
      try {
        const res = await win.webContents.executeJavaScript(buildExtremeProbeScript(step), true);
        if (res) {
          routes.add(res.url);
          if (res.action === 'fuzz-input') inputsFuzzed += 1;
          else if (res.action === 'click' || res.action === 'stress-double-click') clicks += 1;
          for (const f of res.findings || []) pushFinding(f);
          emit('step', {
            step: step + 1,
            maxSteps: profile.maxSteps,
            url: res.url,
            action: res.action,
            targetLabel: res.targetLabel,
            stats: { pages: routes.size, clicks, inputsFuzzed, findings: emittedFindings.size },
          });
        }
      } catch (err) {
        emit('log', { level: 'warn', text: `Step ${step + 1} probe error: ${err.message}` });
      }

      if (!win.isDestroyed()) {
        try {
          const frame = await win.webContents.capturePage();
          const jpeg = frame.resize({ width: 760, quality: 'good' }).toJPEG(72);
          emit('frame', { dataUrl: `data:image/jpeg;base64,${jpeg.toString('base64')}` });
        } catch {
          // Ignore transient capture errors during navigation.
        }
      }
      await new Promise((r) => setTimeout(r, profile.stepDelayMs));
    }

    emit('done', {
      cancelled: state.cancelled,
      stats: { pages: routes.size, clicks, inputsFuzzed, findings: emittedFindings.size },
    });
    return {
      cancelled: state.cancelled,
      stats: { pages: routes.size, clicks, inputsFuzzed, findings: emittedFindings.size },
    };
  } finally {
    await cleanupRunState(state);
    activeRuns.delete(project.id);
  }
}

async function cleanupRunState(state) {
  if (state.win && !state.win.isDestroyed()) {
    try { state.win.destroy(); } catch (err) { void err; }
  }
  if (state.server) {
    try { await state.server.close(); } catch (err) { void err; }
  }
}

async function stopExtremeTest(projectId) {
  const state = activeRuns.get(projectId);
  if (!state) return false;
  state.cancelled = true;
  await cleanupRunState(state);
  activeRuns.delete(projectId);
  return true;
}

module.exports = {
  getSystemProfile,
  detectWebEntry,
  startStaticSandboxServer,
  startNpmSandboxServer,
  stripAnsi,
  buildExtremeProbeScript,
  runExtremeTest,
  stopExtremeTest,
};
