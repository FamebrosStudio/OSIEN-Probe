'use strict';

// Semantic security analyzers for Solidity (.sol), Python (.py), and Go (.go):
//  - Solidity Checks-Effects-Interactions (reentrancy) & unprotected sensitive functions
//  - Python & Go intraprocedural AND cross-file request-input taint into SQL / shell sinks

function buildFinding(rel, line, id, title, severity, cwe, hint, reason, excerpt) {
  return {
    id: `${rel}:${line}:${id}`,
    ruleId: id,
    title,
    severity,
    cwe,
    hint,
    confidence: 'high',
    reason,
    file: rel,
    line,
    excerpt: String(excerpt || '').trim().slice(0, 220),
  };
}

function analyzeSolidity(raw, rel) {
  const findings = [];
  const lines = raw.split(/\r?\n/);
  const fnRe = /\bfunction\s+([A-Za-z_]\w*)\s*\(([^)]*)\)([^{;]*)\{/g;

  let m;
  while ((m = fnRe.exec(raw)) !== null) {
    const fnName = m[1];
    const modifiers = m[3] || '';
    const bodyStart = m.index + m[0].length;
    let depth = 1;
    let pos = bodyStart;
    while (pos < raw.length && depth > 0) {
      const ch = raw[pos++];
      if (ch === '{') depth++;
      else if (ch === '}') depth--;
    }
    const body = raw.slice(bodyStart, pos - 1);
    const fnStartLine = raw.slice(0, m.index).split(/\r?\n/).length;

    const isPublicOrExt = /\b(?:public|external)\b/.test(modifiers);
    const hasReentrancyGuard = /\bnonReentrant\b/i.test(modifiers);
    const hasAuthGuard = /\b(?:onlyOwner|onlyRole|onlyAdmin|initializer|reinitializer|auth|requiresAuth)\b/i.test(modifiers)
      || /\brequire\s*\(\s*msg\.sender\s*={2}/.test(body)
      || /\bif\s*\(\s*msg\.sender\s*!=/.test(body)
      || /\b_checkOwner\s*\(/.test(body);

    if (!hasReentrancyGuard) {
      const extCallRe = /\.(?:call\s*\{[^}]*value\s*:|call\.value\s*\(|send\s*\()/;
      const callMatch = extCallRe.exec(body);
      if (callMatch) {
        const afterCall = body.slice(callMatch.index + callMatch[0].length);
        const stateWriteRe = /\b([A-Za-z_]\w*\[[^\]]+\](?:\[[^\]]+\])?)\s*(?:=|-=|\+=)|\bdelete\s+[A-Za-z_]\w*\[/;
        const writeMatch = stateWriteRe.exec(afterCall);
        if (writeMatch) {
          const callOffset = bodyStart + callMatch.index;
          const callLine = raw.slice(0, callOffset).split(/\r?\n/).length;
          findings.push(buildFinding(
            rel,
            callLine,
            'sol-reentrancy-cei',
            `Potential reentrancy in "${fnName}()": state updated after external Ether call`,
            'critical',
            'CWE-841',
            'Update contract balances/state BEFORE making external calls (Checks-Effects-Interactions) or add a nonReentrant modifier.',
            `External value transfer in "${fnName}" precedes state mutation.`,
            lines[callLine - 1],
          ));
        }
      }
    }

    if (isPublicOrExt && !hasAuthGuard) {
      const hasDangerOp = /\bselfdestruct\s*\(|\.delegatecall\s*\(/.test(body);
      const isInit = /^(?:initialize|init)$/i.test(fnName);
      if (hasDangerOp || isInit) {
        findings.push(buildFinding(
          rel,
          fnStartLine,
          'sol-unprotected-sensitive-fn',
          isInit
            ? `Initializer "${fnName}()" lacks initializer/access guard`
            : `Public/external function "${fnName}()" performs ${/\bselfdestruct/.test(body) ? 'selfdestruct' : 'delegatecall'} without access control`,
          'critical',
          'CWE-284',
          isInit
            ? 'Protect upgradeable initializers with OpenZeppelin `initializer` modifier.'
            : 'Restrict privileged selfdestruct/delegatecall functions with `onlyOwner` or role-based access control.',
          `"${fnName}" is public/external and lacks owner/initializer guard.`,
          lines[fnStartLine - 1],
        ));
      }
    }
  }

  return findings;
}

const PY_SOURCE_RE = /\b(?:request\.(?:args|form|json|data|values|get_json)|input\s*\(|sys\.argv)/;
const PY_SINK_RE = /\b(?:cursor\.execute|os\.system|subprocess\.(?:run|Popen|call)\s*\(|eval\s*\(|exec\s*\()/;

function analyzePythonTaint(raw, rel) {
  const findings = [];
  const lines = raw.split(/\r?\n/);
  const tainted = new Set();

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    if (/^(?:async\s+)?def\s+/.test(trimmed)) { tainted.clear(); continue; }

    const assign = trimmed.match(/^([A-Za-z_]\w*)\s*=\s*(.+)$/);
    if (assign) {
      const [, lhs, rhs] = assign;
      if (PY_SOURCE_RE.test(rhs) || [...tainted].some((v) => new RegExp(`\\b${v}\\b`).test(rhs))) tainted.add(lhs);
      else tainted.delete(lhs);
    }

    if (PY_SINK_RE.test(trimmed)) {
      const usesTainted = PY_SOURCE_RE.test(trimmed) || [...tainted].some((v) => new RegExp(`\\b${v}\\b`).test(trimmed));
      if (usesTainted && (!/\bsubprocess\./.test(trimmed) || /\bshell\s*=\s*True\b/.test(trimmed))) {
        findings.push(buildFinding(
          rel, i + 1, 'py-taint-sink',
          'User-controlled input reaches dangerous Python execution/SQL sink',
          'high', 'CWE-89',
          'Use parameterized SQL queries or argument arrays (shell=False) instead of passing tainted input.',
          'Tainted request/input variable flows into a dangerous sink in the same function.',
          trimmed,
        ));
      }
    }
  }
  return findings;
}

const GO_SOURCE_RE = /\b(?:r\.URL\.Query\s*\(|r\.FormValue\s*\(|c\.(?:Query|Param|PostForm)\s*\()/;
const GO_SINK_RE = /\b(?:db\.(?:Query|Exec|QueryRow)\s*\(|exec\.Command\s*\(\s*"(?:sh|bash)"\s*,\s*"-c")/;

function analyzeGoTaint(raw, rel) {
  const findings = [];
  const lines = raw.split(/\r?\n/);
  const tainted = new Set();

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (!trimmed || trimmed.startsWith('//')) continue;
    if (/^func\s+/.test(trimmed)) { tainted.clear(); continue; }

    const assign = trimmed.match(/^([A-Za-z_]\w*)(?:\s*,\s*[A-Za-z_]\w*)?\s*:?=\s*(.+)$/);
    if (assign) {
      const [, lhs, rhs] = assign;
      if (GO_SOURCE_RE.test(rhs) || [...tainted].some((v) => new RegExp(`\\b${v}\\b`).test(rhs))) tainted.add(lhs);
    }

    if (GO_SINK_RE.test(trimmed)) {
      const usesTainted = GO_SOURCE_RE.test(trimmed) || [...tainted].some((v) => new RegExp(`\\b${v}\\b`).test(trimmed));
      const hasConcatOrFmt = /[+]|fmt\.Sprintf\s*\(/.test(trimmed) || [...tainted].some((v) => new RegExp(`\\b${v}\\b`).test(trimmed));
      if (usesTainted && hasConcatOrFmt) {
        if (/\bdb\.(?:Query|Exec|QueryRow)\s*\(/.test(trimmed) && !/[+]|fmt\.Sprintf/.test(trimmed)) continue;
        findings.push(buildFinding(
          rel, i + 1, 'go-taint-sink',
          'HTTP request input flows into Go SQL/shell sink',
          'high', 'CWE-89',
          'Use parameterized SQL placeholders ($1 / ?) or pass explicit command arguments without sh -c.',
          'Tainted HTTP request input flows into SQL concatenation or shell command execution.',
          trimmed,
        ));
      }
    }
  }
  return findings;
}

function analyzeSemanticPolyglot(raw, rel, extName) {
  if (extName === '.sol') return analyzeSolidity(raw, rel);
  if (extName === '.py') return analyzePythonTaint(raw, rel);
  if (extName === '.go') return analyzeGoTaint(raw, rel);
  return [];
}

function analyzeCrossFilePolyglot(polyglotFiles) {
  const findings = [];
  const pySinkFns = new Map();
  const goSinkFns = new Map();

  // Pass 1: collect sink helper functions across Python & Go files
  for (const { rel, raw, extName } of polyglotFiles) {
    const lines = raw.split(/\r?\n/);
    if (extName === '.py') {
      for (let i = 0; i < lines.length; i++) {
        const defMatch = lines[i].match(/^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)/);
        if (!defMatch) continue;
        const fnName = defMatch[1];
        const params = defMatch[2].split(',').map((p) => p.trim().split(/[:=]/)[0].trim()).filter((p) => p && p !== 'self' && p !== 'cls');
        if (!params.length) continue;
        const body = lines.slice(i + 1, Math.min(lines.length, i + 25)).join('\n');
        if (PY_SINK_RE.test(body) && params.some((p) => new RegExp(`\\b${p}\\b`).test(body))) {
          pySinkFns.set(fnName, { file: rel, line: i + 1 });
        }
      }
    } else if (extName === '.go') {
      for (let i = 0; i < lines.length; i++) {
        const fnMatch = lines[i].match(/^\s*func\s+([A-Z][A-Za-z0-9_]*)\s*\(([^)]*)\)/);
        if (!fnMatch) continue;
        const fnName = fnMatch[1];
        const params = fnMatch[2].split(',').map((p) => p.trim().split(/\s+/)[0]).filter(Boolean);
        if (!params.length) continue;
        const body = lines.slice(i + 1, Math.min(lines.length, i + 30)).join('\n');
        if (GO_SINK_RE.test(body) && params.some((p) => new RegExp(`\\b${p}\\b`).test(body))) {
          goSinkFns.set(fnName, { file: rel, line: i + 1 });
        }
      }
    }
  }

  // Pass 2: trace tainted HTTP inputs in callers into those cross-file sink helpers
  for (const { rel, raw, extName } of polyglotFiles) {
    const lines = raw.split(/\r?\n/);
    if (extName === '.py' && pySinkFns.size > 0) {
      const tainted = new Set();
      for (let i = 0; i < lines.length; i++) {
        const trimmed = lines[i].trim();
        if (/^(?:async\s+)?def\s+/.test(trimmed)) { tainted.clear(); continue; }
        const assign = trimmed.match(/^([A-Za-z_]\w*)\s*=\s*(.+)$/);
        if (assign && (PY_SOURCE_RE.test(assign[2]) || [...tainted].some((v) => new RegExp(`\\b${v}\\b`).test(assign[2])))) {
          tainted.add(assign[1]);
        }
        for (const [fnName, sinkMeta] of pySinkFns.entries()) {
          if (sinkMeta.file === rel) continue;
          const callRe = new RegExp(`\\b${fnName}\\s*\\(([^)]+)\\)`);
          const cm = callRe.exec(trimmed);
          if (cm && (PY_SOURCE_RE.test(cm[1]) || [...tainted].some((v) => new RegExp(`\\b${v}\\b`).test(cm[1])))) {
            findings.push(buildFinding(
              rel, i + 1, 'py-crossfile-taint',
              `Cross-file taint: request input passed to "${fnName}()" (${sinkMeta.file}:${sinkMeta.line})`,
              'critical', 'CWE-89',
              `Sanitize or parameterize input before calling "${fnName}()" in ${sinkMeta.file}.`,
              `Tainted input flows from ${rel}:${i + 1} into sink helper ${sinkMeta.file}:${sinkMeta.line}.`,
              trimmed,
            ));
          }
        }
      }
    } else if (extName === '.go' && goSinkFns.size > 0) {
      const tainted = new Set();
      for (let i = 0; i < lines.length; i++) {
        const trimmed = lines[i].trim();
        if (/^func\s+/.test(trimmed)) { tainted.clear(); continue; }
        const assign = trimmed.match(/^([A-Za-z_]\w*)(?:\s*,\s*[A-Za-z_]\w*)?\s*:?=\s*(.+)$/);
        if (assign && (GO_SOURCE_RE.test(assign[2]) || [...tainted].some((v) => new RegExp(`\\b${v}\\b`).test(assign[2])))) {
          tainted.add(assign[1]);
        }
        for (const [fnName, sinkMeta] of goSinkFns.entries()) {
          if (sinkMeta.file === rel) continue;
          const callRe = new RegExp(`\\b(?:[a-z_]+\\.)?${fnName}\\s*\\(([^)]+)\\)`);
          const cm = callRe.exec(trimmed);
          if (cm && (GO_SOURCE_RE.test(cm[1]) || [...tainted].some((v) => new RegExp(`\\b${v}\\b`).test(cm[1])))) {
            findings.push(buildFinding(
              rel, i + 1, 'go-crossfile-taint',
              `Cross-file taint: HTTP input passed to "${fnName}()" (${sinkMeta.file}:${sinkMeta.line})`,
              'critical', 'CWE-89',
              `Use parameterized queries or validate input before calling "${fnName}()" in ${sinkMeta.file}.`,
              `Tainted HTTP input flows from ${rel}:${i + 1} into sink helper ${sinkMeta.file}:${sinkMeta.line}.`,
              trimmed,
            ));
          }
        }
      }
    }
  }

  return findings;
}

module.exports = { analyzeSemanticPolyglot, analyzeCrossFilePolyglot };
