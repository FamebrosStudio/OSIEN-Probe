'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');

const {
  getSystemProfile,
  detectWebEntry,
  startStaticSandboxServer,
  buildExtremeProbeScript,
} = require('../electron/extreme-tester.cjs');

test('getSystemProfile reports PC hardware tier and step budget', () => {
  const profile = getSystemProfile();
  assert.ok(profile.cpuCores >= 1);
  assert.ok(profile.totalMemGb > 0);
  assert.ok(['high', 'balanced', 'light'].includes(profile.tier));
  assert.ok(profile.maxSteps >= 35);
  assert.ok(profile.stepDelayMs >= 140);
});

test('detectWebEntry detects npm dev script and static index.html fallback', async () => {
  const npmRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'osien-web-npm-'));
  await fs.writeFile(path.join(npmRoot, 'package.json'), JSON.stringify({ name: 'site', scripts: { dev: 'vite' } }));
  const npmEntry = await detectWebEntry(npmRoot);
  assert.equal(npmEntry.mode, 'npm');
  assert.equal(npmEntry.scriptName, 'dev');

  const staticRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'osien-web-static-'));
  await fs.writeFile(path.join(staticRoot, 'index.html'), '<h1>Hello</h1>');
  const staticEntry = await detectWebEntry(staticRoot);
  assert.equal(staticEntry.mode, 'static');
  assert.equal(staticEntry.entryFile, 'index.html');
});

test('startStaticSandboxServer serves local HTML on 127.0.0.1 and shuts down cleanly', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'osien-sandbox-srv-'));
  await fs.writeFile(path.join(root, 'index.html'), '<!doctype html><h1>Sandbox OK</h1>');
  const srv = await startStaticSandboxServer(root);
  try {
    assert.match(srv.url, /^http:\/\/127\.0\.0\.1:\d+$/);
    const body = await new Promise((resolve, reject) => {
      http.get(srv.url, (res) => {
        let data = '';
        res.on('data', (c) => { data += c; });
        res.on('end', () => resolve({ status: res.statusCode, data }));
      }).on('error', reject);
    });
    assert.equal(body.status, 200);
    assert.match(body.data, /Sandbox OK/);
  } finally {
    await srv.close();
  }
});

test('buildExtremeProbeScript produces valid executable probe script', () => {
  const src = buildExtremeProbeScript(3);
  assert.match(src, /__osien_probe_cursor__/);
  assert.match(src, /data-osien-xss-probe/);
  assert.doesNotThrow(() => new Function(src));
});
