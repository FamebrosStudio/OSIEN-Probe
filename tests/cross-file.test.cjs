'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs/promises');
const { scanProjectRoot } = require('../electron/scanner.cjs');
const { generateFileBatchFixes } = require('../electron/ai-review.cjs');

test('cross-file analyzer detects interprocedural taint, unawaited async, missing route auth, async race, TOCTOU, and API contract mismatch', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'osien-cross-'));
  try {
    await fs.writeFile(path.join(dir, 'db.js'), [
      'const fs = require("node:fs");',
      'function readAsset(filePath) {',
      '  return fs.readFileSync(filePath, "utf8");',
      '}',
      'async function saveAudit(entry) {',
      '  return Promise.resolve(entry);',
      '}',
      'module.exports = { readAsset, saveAudit };',
    ].join('\n'));

    await fs.writeFile(path.join(dir, 'routes.js'), [
      'const fs = require("node:fs");',
      'const { readAsset, saveAudit } = require("./db");',
      'let cachedCount = 0;',
      'async function bumpCount() {',
      '  const before = cachedCount;',
      '  await Promise.resolve(before);',
      '  cachedCount = before + 1;',
      '}',
      'function handleRoutes(router, requireAuth) {',
      '  router.get("/api/items", requireAuth, (req, res) => res.json([]));',
      '  router.post("/api/items", requireAuth, (req, res) => {',
      '    saveAudit(req.body.user_id);',
      '    const data = readAsset(req.query.name);',
      '    if (fs.existsSync(req.query.alt)) {',
      '      return res.send(fs.readFileSync(req.query.alt, "utf8"));',
      '    }',
      '    res.send(data);',
      '  });',
      '  router.delete("/api/items/:id", (req, res) => res.json({ deleted: true }));',
      '}',
      'module.exports = { bumpCount, handleRoutes };',
    ].join('\n'));

    await fs.writeFile(path.join(dir, 'client.js'), [
      'export async function createItem(userId) {',
      '  return fetch("/api/items", {',
      '    method: "POST",',
      '    body: JSON.stringify({ userId }),',
      '  });',
      '}',
    ].join('\n'));

    const res = await scanProjectRoot(dir, 'API / backend');
    const ruleIds = new Set(res.findings.map((f) => f.ruleId));

    assert.ok(ruleIds.has('js-crossfile-taint'), `Expected js-crossfile-taint, got: ${[...ruleIds]}`);
    assert.ok(ruleIds.has('js-crossfile-unawaited-async'), `Expected js-crossfile-unawaited-async, got: ${[...ruleIds]}`);
    assert.ok(ruleIds.has('js-route-missing-auth'), `Expected js-route-missing-auth, got: ${[...ruleIds]}`);
    assert.ok(ruleIds.has('js-shared-state-async-race'), `Expected js-shared-state-async-race, got: ${[...ruleIds]}`);
    assert.ok(ruleIds.has('js-toctou-fs'), `Expected js-toctou-fs, got: ${[...ruleIds]}`);
    assert.ok(ruleIds.has('js-api-contract-mismatch'), `Expected js-api-contract-mismatch, got: ${[...ruleIds]}`);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('generateFileBatchFixes validates and returns multiple patches in one call', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'osien-batch-'));
  try {
    await fs.writeFile(path.join(dir, 'app.js'), 'const a = eval(x);\nconst b = new Function(y);\n', 'utf8');
    const patches = await generateFileBatchFixes(dir, 'app.js', [
      { id: 'f1', line: 1, title: 'eval()', severity: 'high', cwe: 'CWE-95', hint: 'Avoid eval', excerpt: 'const a = eval(x);' },
      { id: 'f2', line: 2, title: 'new Function()', severity: 'high', cwe: 'CWE-95', hint: 'Avoid Function', excerpt: 'const b = new Function(y);' },
    ], {
      provider: 'cloud-codex',
      model: 'gpt-5.1-codex-mini',
      apiKey: 'test-key',
      fetch: async () => ({
        ok: true,
        json: async () => ({
          choices: [{
            message: {
              content: JSON.stringify({
                patches: [
                  { findingId: 'f1', explanation: 'Remove eval', target: 'const a = eval(x);', replacement: 'const a = JSON.parse(x);' },
                  { findingId: 'f2', explanation: 'Remove Function', target: 'const b = new Function(y);', replacement: 'const b = () => y;' },
                ],
              }),
            },
          }],
        }),
      }),
    });
    assert.equal(patches.length, 2);
    assert.equal(patches[0].findingId, 'f1');
    assert.equal(patches[1].findingId, 'f2');
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
