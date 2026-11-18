'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const { scanProjectRoot } = require('../electron/scanner.cjs');

test('dependency auditor detects vulnerable npm, Python, and Go packages and ignores patched versions', async () => {
  const vulnDir = await fs.mkdtemp(path.join(os.tmpdir(), 'deepcheck-dep-vuln-'));
  await fs.writeFile(path.join(vulnDir, 'package.json'), JSON.stringify({
    name: 'vuln-app',
    dependencies: { lodash: '^4.17.19', express: '^4.19.2' },
  }, null, 2));
  await fs.writeFile(path.join(vulnDir, 'requirements.txt'), 'pyyaml==5.3.1\nrequests==2.32.0\n');
  await fs.writeFile(path.join(vulnDir, 'go.mod'), 'module example.com/app\nrequire github.com/dgrijalva/jwt-go v3.2.0\n');

  const report = await scanProjectRoot(vulnDir, 'API / backend');
  const ids = new Set(report.findings.map((f) => f.ruleId));
  assert.ok(ids.has('dep-npm-lodash-cve'), 'flags lodash < 4.17.21');
  assert.ok(!ids.has('dep-npm-express-cve'), 'does not flag patched express >= 4.19.2');
  assert.ok(ids.has('dep-py-pyyaml-cve'), 'flags PyYAML < 5.4');
  assert.ok(!ids.has('dep-py-requests-cve'), 'does not flag patched requests >= 2.31.0');
  assert.ok(ids.has('dep-go-jwt-go-deprecated'), 'flags deprecated jwt-go');
});

test('semantic polyglot detects Solidity CEI reentrancy, unprotected init, and Python/Go taint', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'deepcheck-sem-'));
  await fs.writeFile(path.join(dir, 'Vault.sol'), [
    'pragma solidity ^0.8.20;',
    'contract Vault {',
    '  mapping(address => uint256) public balances;',
    '  function initialize(address _owner) external { owner = _owner; }',
    '  function withdraw(uint256 amount) external {',
    '    (bool ok, ) = msg.sender.call{value: amount}("");',
    '    require(ok);',
    '    balances[msg.sender] -= amount;',
    '  }',
    '  function safeWithdraw(uint256 amount) external nonReentrant {',
    '    balances[msg.sender] -= amount;',
    '    (bool ok, ) = msg.sender.call{value: amount}("");',
    '    require(ok);',
    '  }',
    '}',
  ].join('\n'));

  await fs.writeFile(path.join(dir, 'app.py'), [
    'def handler(request, cursor):',
    '    uid = request.args.get("id")',
    '    cursor.execute("SELECT * FROM users WHERE id = " + uid)',
  ].join('\n'));

  await fs.writeFile(path.join(dir, 'main.go'), [
    'package main',
    'func handler(r *http.Request, db *sql.DB) {',
    '    q := r.URL.Query().Get("name")',
    '    db.Query("SELECT * FROM users WHERE name = " + q)',
    '}',
  ].join('\n'));

  const report = await scanProjectRoot(dir, 'Blockchain / Web3');
  const ids = new Set(report.findings.map((f) => f.ruleId));
  assert.ok(ids.has('sol-reentrancy-cei'), 'detects Solidity CEI reentrancy');
  assert.ok(ids.has('sol-unprotected-sensitive-fn'), 'detects unprotected initialize()');
  assert.ok(ids.has('py-taint-sink'), 'detects Python request->SQL taint');
  assert.ok(ids.has('go-taint-sink'), 'detects Go request->SQL taint');
  const safeWithdrawFlags = report.findings.filter((f) => f.ruleId === 'sol-reentrancy-cei' && f.line >= 10);
  assert.equal(safeWithdrawFlags.length, 0, 'does not flag nonReentrant safeWithdraw');
});

test('monorepo lockfile CVE audit and Python/Go cross-file taint detection', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'deepcheck-xpoly-'));
  await fs.mkdir(path.join(dir, 'packages', 'web'), { recursive: true });
  await fs.writeFile(path.join(dir, 'packages', 'web', 'package-lock.json'), JSON.stringify({
    packages: { 'node_modules/minimist': { version: '1.2.5' } },
  }));
  await fs.writeFile(path.join(dir, 'Cargo.lock'), '[[package]]\nname = "hyper"\nversion = "0.14.20"\n');
  await fs.writeFile(path.join(dir, 'db_helpers.py'), 'def run_user_query(cursor, q):\n    cursor.execute("SELECT * FROM t WHERE a=" + q)\n');
  await fs.writeFile(path.join(dir, 'routes.py'), 'def endpoint(request, cursor):\n    name = request.args.get("name")\n    run_user_query(cursor, name)\n');
  await fs.writeFile(path.join(dir, 'store.go'), 'package main\nfunc FindUser(db *sql.DB, q string) {\n    db.Query("SELECT * FROM u WHERE n=" + q)\n}\n');
  await fs.writeFile(path.join(dir, 'api.go'), 'package main\nfunc Handle(r *http.Request, db *sql.DB) {\n    name := r.URL.Query().Get("n")\n    FindUser(db, name)\n}\n');

  const report = await scanProjectRoot(dir, 'API / backend');
  const ids = new Set(report.findings.map((f) => f.ruleId));
  assert.ok(ids.has('dep-npm-minimist-cve'), 'flags vulnerable minimist in nested monorepo package-lock.json');
  assert.ok(ids.has('dep-rust-hyper-cve'), 'flags vulnerable hyper in Cargo.lock');
  assert.ok(ids.has('py-crossfile-taint'), 'detects Python cross-file taint');
  assert.ok(ids.has('go-crossfile-taint'), 'detects Go cross-file taint');
});

test('real-world false-positive regression guard (JSX attrs, JSON-LD, model.eval, platform.system, .env.local.example)', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'deepcheck-fp-guard-'));
  await fs.writeFile(path.join(dir, '.env.local.example'), 'NEXT_PUBLIC_SUPABASE_ANON_KEY="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.demo"\n');
  await fs.writeFile(path.join(dir, 'JsonLd.tsx'), [
    'export function JsonLd({ data }: { data: unknown }) {',
    '  return <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(data) }} />;',
    '}',
    'export function InputField({ val }: { val: string }) {',
    '  return <input type="text" value={val} onChange={() => {}} />;',
    '}',
  ].join('\n'));
  await fs.writeFile(path.join(dir, 'ml_check.py'), [
    'import hashlib, platform',
    'GRANT_TYPE_REFRESH_TOKEN = "refresh_token"',
    'sys_name = platform.system().lower()',
    'model.eval()',
    'digest = hashlib.sha256(b"blob %d\\0" % len(b"abc")).hexdigest()',
  ].join('\n'));

  const report = await scanProjectRoot(dir, 'Website', { bugsOnly: true });
  assert.equal(report.findings.length, 0, `expected 0 false positives, got: ${report.findings.map((f) => `${f.ruleId}:${f.line}`).join(', ')}`);
});
