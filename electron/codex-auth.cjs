'use strict';

const fs = require('node:fs/promises');
const fsSync = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawn } = require('node:child_process');

let cachedCodexScript = null;
let cachedCodexBinary = null;

function codexDir() {
  return path.join(os.homedir(), '.codex');
}

function codexAuthFile() {
  return path.join(codexDir(), 'auth.json');
}

function codexModelsCacheFile() {
  return path.join(codexDir(), 'models_cache.json');
}

function findCachedCodexBinary() {
  if (cachedCodexBinary && fsSync.existsSync(cachedCodexBinary)) return cachedCodexBinary;
  const npxRoots = [
    process.env.LOCALAPPDATA ? path.join(process.env.LOCALAPPDATA, 'npm-cache', '_npx') : null,
    path.join(os.homedir(), '.npm', '_npx'),
  ].filter(Boolean);

  const relCandidates = process.platform === 'win32'
    ? [
        path.join('@openai', 'codex-win32-x64', 'vendor', 'x86_64-pc-windows-msvc', 'bin', 'codex.exe'),
        path.join('@openai', 'codex-win32-arm64', 'vendor', 'aarch64-pc-windows-msvc', 'bin', 'codex.exe'),
      ]
    : process.platform === 'darwin'
      ? [
          path.join('@openai', 'codex-darwin-arm64', 'vendor', 'aarch64-apple-darwin', 'bin', 'codex'),
          path.join('@openai', 'codex-darwin-x64', 'vendor', 'x86_64-apple-darwin', 'bin', 'codex'),
        ]
      : [
          path.join('@openai', 'codex-linux-x64', 'vendor', 'x86_64-unknown-linux-musl', 'bin', 'codex'),
          path.join('@openai', 'codex-linux-arm64', 'vendor', 'aarch64-unknown-linux-musl', 'bin', 'codex'),
        ];

  for (const root of npxRoots) {
    try {
      for (const entry of fsSync.readdirSync(root)) {
        for (const rel of relCandidates) {
          const candidate = path.join(root, entry, 'node_modules', rel);
          if (fsSync.existsSync(candidate)) {
            cachedCodexBinary = candidate;
            return candidate;
          }
        }
      }
    } catch {
      // Directory may not exist yet.
    }
  }
  return null;
}

function findCachedCodexScript() {
  if (cachedCodexScript && fsSync.existsSync(cachedCodexScript)) return cachedCodexScript;
  const npxRoots = [
    process.env.LOCALAPPDATA ? path.join(process.env.LOCALAPPDATA, 'npm-cache', '_npx') : null,
    path.join(os.homedir(), '.npm', '_npx'),
  ].filter(Boolean);

  for (const root of npxRoots) {
    try {
      for (const entry of fsSync.readdirSync(root)) {
        const candidate = path.join(root, entry, 'node_modules', '@openai', 'codex', 'bin', 'codex.js');
        if (fsSync.existsSync(candidate)) {
          cachedCodexScript = candidate;
          return candidate;
        }
      }
    } catch {
      // Directory may not exist yet.
    }
  }
  return null;
}

async function getCodexAuthStatus() {
  try {
    const raw = await fs.readFile(codexAuthFile(), 'utf8');
    const data = JSON.parse(raw);
    const hasTokens = Boolean(data?.tokens?.access_token || data?.OPENAI_API_KEY || data?.access_token);
    return { connected: hasTokens, authPath: codexAuthFile() };
  } catch {
    return { connected: false, authPath: codexAuthFile() };
  }
}

async function getAvailableCodexModels() {
  try {
    const raw = await fs.readFile(codexModelsCacheFile(), 'utf8');
    const data = JSON.parse(raw);
    const list = Array.isArray(data?.models)
      ? data.models.filter((m) => m && m.visibility !== 'hide' && m.slug).map((m) => String(m.slug))
      : [];
    return list.length ? list : ['default'];
  } catch {
    return ['default'];
  }
}

function spawnCodex(args, options = {}) {
  const nativeBin = findCachedCodexBinary();
  const childEnv = { ...process.env, ELECTRON_RUN_AS_NODE: '1' };
  if (nativeBin) {
    return spawn(nativeBin, args, {
      cwd: options.cwd || os.homedir(),
      windowsHide: options.windowsHide !== false,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: childEnv,
    });
  }
  const cachedScript = findCachedCodexScript();
  if (cachedScript) {
    return spawn(process.execPath, [cachedScript, ...args], {
      cwd: options.cwd || os.homedir(),
      windowsHide: options.windowsHide !== false,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: childEnv,
    });
  }
  const joined = args.map((a) => (/[\s"]/g.test(a) ? `"${a.replace(/"/g, '\\"')}"` : a)).join(' ');
  if (process.platform === 'win32') {
    return spawn(process.env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', `npx.cmd --yes @openai/codex ${joined}`], {
      cwd: options.cwd || os.homedir(),
      windowsHide: options.windowsHide !== false,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: childEnv,
    });
  }
  return spawn('npx', ['--yes', '@openai/codex', ...args], {
    cwd: options.cwd || os.homedir(),
    windowsHide: options.windowsHide !== false,
    stdio: ['pipe', 'pipe', 'pipe'],
    env: childEnv,
  });
}

function connectCodexBrowser(timeoutMs = 180000) {
  return new Promise((resolve, reject) => {
    const child = spawnCodex(['login'], { windowsHide: true });
    let stderr = '';
    const timer = setTimeout(() => {
      try { child.kill(); } catch (err) { void err; }
      reject(new Error('ChatGPT sign-in timed out after 3 minutes. Please try again.'));
    }, timeoutMs);

    child.stderr.on('data', (chunk) => {
      stderr = (stderr + chunk.toString('utf8')).slice(-800);
    });
    child.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on('exit', async (code) => {
      clearTimeout(timer);
      const status = await getCodexAuthStatus();
      if (status.connected) {
        resolve(status);
        return;
      }
      reject(new Error(`ChatGPT sign-in did not complete (exit code ${code}). ${stderr.trim()}`.trim()));
    });
  });
}

async function disconnectCodex() {
  try {
    await fs.unlink(codexAuthFile());
  } catch (err) {
    if (err?.code !== 'ENOENT') throw err;
  }
  return getCodexAuthStatus();
}

async function runCodexExec({ root, model, prompt, timeoutMs = 90000 }) {
  const outFile = path.join(os.tmpdir(), `osien-codex-${Date.now()}-${Math.random().toString(16).slice(2)}.txt`);
  const args = ['exec', '--ephemeral', '-s', 'read-only', '--skip-git-repo-check', '-o', outFile];
  if (model && model !== 'default') {
    if (!/^[a-zA-Z0-9._:-]+$/.test(model)) {
      throw new Error(`Invalid Codex model name: ${model}`);
    }
    args.push('-m', model);
  }
  args.push('-');

  try {
    return await new Promise((resolve, reject) => {
      const child = spawnCodex(args, { cwd: root, windowsHide: true });
      let stdout = '';
      let stderr = '';
      const timer = setTimeout(() => {
        try { child.kill(); } catch (err) { void err; }
        reject(new Error('Codex request timed out.'));
      }, timeoutMs);

      child.stdout.on('data', (chunk) => { stdout += chunk.toString('utf8'); });
      child.stderr.on('data', (chunk) => { stderr = (stderr + chunk.toString('utf8')).slice(-800); });
      child.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
      child.on('exit', async (code) => {
        clearTimeout(timer);
        let output = '';
        try {
          output = (await fs.readFile(outFile, 'utf8')).trim();
        } catch {
          output = stdout.trim();
        }
        if (code !== 0 && !output) {
          reject(new Error(`Codex CLI exited with code ${code}: ${stderr.trim() || 'Ensure ChatGPT is connected in Settings.'}`));
          return;
        }
        resolve(output);
      });

      child.stdin.write(prompt);
      child.stdin.end();
    });
  } finally {
    try { await fs.unlink(outFile); } catch (err) { void err; }
  }
}

module.exports = {
  codexAuthFile,
  findCachedCodexScript,
  getCodexAuthStatus,
  getAvailableCodexModels,
  connectCodexBrowser,
  disconnectCodex,
  runCodexExec,
};
