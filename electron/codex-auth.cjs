'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { spawn } = require('node:child_process');

function codexAuthFile() {
  return path.join(os.homedir(), '.codex', 'auth.json');
}

async function getCodexAuthStatus() {
  try {
    const raw = await fs.readFile(codexAuthFile(), 'utf8');
    const data = JSON.parse(raw);
    const hasTokens = Boolean(data?.tokens?.access_token || data?.OPENAI_API_KEY || data?.access_token);
    return {
      connected: hasTokens,
      authPath: codexAuthFile(),
    };
  } catch {
    return {
      connected: false,
      authPath: codexAuthFile(),
    };
  }
}

function spawnCodex(args, options = {}) {
  const joined = args.map((a) => (/[\s"]/g.test(a) ? `"${a.replace(/"/g, '\\"')}"` : a)).join(' ');
  if (process.platform === 'win32') {
    return spawn(process.env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', `npx.cmd --yes @openai/codex ${joined}`], {
      cwd: options.cwd || os.homedir(),
      windowsHide: options.windowsHide !== false,
      env: process.env,
    });
  }
  return spawn('npx', ['--yes', '@openai/codex', ...args], {
    cwd: options.cwd || os.homedir(),
    windowsHide: options.windowsHide !== false,
    env: process.env,
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

function runCodexExec({ root, model, prompt, timeoutMs = 90000 }) {
  return new Promise((resolve, reject) => {
    if (!/^[a-zA-Z0-9._:-]+$/.test(model)) {
      reject(new Error(`Invalid Codex model name: ${model}`));
      return;
    }
    const child = spawnCodex(['exec', '--skip-git-repo-check', '-m', model, '-'], {
      cwd: root,
      windowsHide: true,
    });
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
    child.on('exit', (code) => {
      clearTimeout(timer);
      if (code !== 0 && !stdout.trim()) {
        reject(new Error(`Codex CLI exited with code ${code}: ${stderr.trim() || 'Ensure ChatGPT is connected in Settings.'}`));
        return;
      }
      resolve(stdout.trim());
    });

    child.stdin.write(prompt);
    child.stdin.end();
  });
}

module.exports = {
  codexAuthFile,
  getCodexAuthStatus,
  connectCodexBrowser,
  disconnectCodex,
  runCodexExec,
};
