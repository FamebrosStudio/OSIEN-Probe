'use strict';

// Semantic security analyzers for Solidity (.sol), Python (.py), and Go (.go).
// Catches multi-line control-flow/data-flow bugs that single-line regexes miss:
//  - Solidity Checks-Effects-Interactions (reentrancy) & unprotected sensitive functions
//  - Python intraprocedural request-input taint into SQL / OS command sinks
//  - Go intraprocedural HTTP request-input taint into SQL / exec sinks

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

    // 1. Checks-Effects-Interactions violation (reentrancy): external call BEFORE state mutation
    if (!hasReentrancyGuard) {
      const extCallRe = /\.(?:call\s*\{[^}]*value\s*:|call\.value\s*\(|send\s*\()/;
      const callMatch = extCallRe.exec(body);
      if (callMatch) {
        const afterCall = body.slice(callMatch.index + callMatch[0].length);
        // Look for storage mapping/state assignment after the external call
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

    // 2. Unprotected sensitive function (initialize / selfdestruct / delegatecall / withdraw)
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
          `"${fnName}" is ${isPublicOrExt ? 'public/external' : ''} and lacks owner/initializer guard.`,
          lines[fnStartLine - 1],
        ));
      }
    }
  }

  return findings;
}

function analyzePythonTaint(raw, rel) {
  const findings = [];
  const lines = raw.split(/\r?\n/);
  const tainted = new Set();
  const sourceRe = /\b(?:request\.(?:args|form|json|data|values|get_json)|input\s*\(|sys\.argv)/;
  const sinkRe = /\b(?:cursor\.execute|os\.system|subprocess\.(?:run|Popen|call)\s*\(|eval\s*\(|exec\s*\()/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    // Reset taint tracking at top-level function boundary
    if (/^(?:async\s+)?def\s+/.test(trimmed)) {
      tainted.clear();
      continue;
    }

    const assign = trimmed.match(/^([A-Za-z_]\w*)\s*=\s*(.+)$/);
    if (assign) {
      const [, lhs, rhs] = assign;
      if (sourceRe.test(rhs) || [...tainted].some((v) => new RegExp(`\\b${v}\\b`).test(rhs))) {
        tainted.add(lhs);
      } else {
        tainted.delete(lhs);
      }
    }

    if (sinkRe.test(trimmed)) {
      const usesTainted = sourceRe.test(trimmed) || [...tainted].some((v) => new RegExp(`\\b${v}\\b`).test(trimmed));
      if (usesTainted && (!/\bsubprocess\./.test(trimmed) || /\bshell\s*=\s*True\b/.test(trimmed))) {
        findings.push(buildFinding(
          rel,
          i + 1,
          'py-taint-sink',
          'User-controlled input reaches dangerous Python execution/SQL sink',
          'high',
          'CWE-89',
          'Use parameterized SQL queries or argument arrays (shell=False) instead of passing tainted input.',
          'Tainted request/input variable flows into a dangerous sink in the same function.',
          trimmed,
        ));
      }
    }
  }

  return findings;
}

function analyzeGoTaint(raw, rel) {
  const findings = [];
  const lines = raw.split(/\r?\n/);
  const tainted = new Set();
  const sourceRe = /\b(?:r\.URL\.Query\s*\(|r\.FormValue\s*\(|c\.(?:Query|Param|PostForm)\s*\()/;
  const sinkRe = /\b(?:db\.(?:Query|Exec|QueryRow)\s*\(|exec\.Command\s*\(\s*"(?:sh|bash)"\s*,\s*"-c")/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('//')) continue;

    if (/^func\s+/.test(trimmed)) {
      tainted.clear();
      continue;
    }

    const assign = trimmed.match(/^([A-Za-z_]\w*)(?:\s*,\s*[A-Za-z_]\w*)?\s*:?=\s*(.+)$/);
    if (assign) {
      const [, lhs, rhs] = assign;
      if (sourceRe.test(rhs) || [...tainted].some((v) => new RegExp(`\\b${v}\\b`).test(rhs))) {
        tainted.add(lhs);
      }
    }

    if (sinkRe.test(trimmed)) {
      const usesTainted = sourceRe.test(trimmed) || [...tainted].some((v) => new RegExp(`\\b${v}\\b`).test(trimmed));
      const hasConcatOrFmt = /[+]|fmt\.Sprintf\s*\(/.test(trimmed) || [...tainted].some((v) => new RegExp(`\\b${v}\\b`).test(trimmed));
      if (usesTainted && hasConcatOrFmt) {
        // For db.Query/Exec, only flag when concatenated/formatted rather than parameterized ($1 / ?)
        if (/\bdb\.(?:Query|Exec|QueryRow)\s*\(/.test(trimmed) && !/[+]|fmt\.Sprintf/.test(trimmed)) continue;
        findings.push(buildFinding(
          rel,
          i + 1,
          'go-taint-sink',
          'HTTP request input flows into Go SQL/shell sink',
          'high',
          'CWE-89',
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

module.exports = { analyzeSemanticPolyglot };
