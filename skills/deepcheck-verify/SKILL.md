---
name: deepcheck-verify
description: Use DeepCheck offline static analysis, multi-language AST scanning, and SARIF/JSON audit reports to verify code changes for security vulnerabilities, logic bugs, secrets, and regressions before finishing a task.
---

# DeepCheck Verification Skill

Run DeepCheck as a fast, offline static-analysis and bug-detection gate after writing or modifying code. It executes **no project code** during scans and supports JavaScript/TypeScript (Babel AST + taint tracking), Python, Go, Rust, Java, Kotlin, C/C++, C#, Ruby, PHP, Swift, Bash, HTML, CSS, JSON, YAML, and SQL.

## When to Use

- After implementing features, bug fixes, or refactors in any supported language.
- Before claiming a task is complete or ready for review/release.
- To audit an existing codebase or generate a **SARIF 2.1.0** / **Markdown** / **JSON** security & bug report.

## How to Run Verification

Run the DeepCheck CLI directly against the target project directory:

```powershell
node C:\Users\VIVOBOOK\deepcheck\scripts\audit.cjs "<project-path>" "<category>"
```

**Supported `<category>` values:**
- `"Website"` — Web UI, HTML/CSS accessibility, XSS, CSRF, CSP, JS/TS
- `"Software"` — Desktop/CLI apps, Electron, general multi-language source
- `"API / backend"` — HTTP services, auth, SQL/NoSQL, SSRF, rate limiting
- `"Mobile app"` — Android/iOS/WebView security & mobile config
- `"Library"` — npm/package metadata, exports, dependency hygiene
- `"Data / ML"` — Python ML/data pipelines (`torch.load`, `trust_remote_code`, `joblib`, seeding)

## Useful Flags for AI Verification

- **`--fail-on <severity>`**: Exit with code `1` if any finding at or above `critical | high | medium | low | info` is found (ideal as a CI/verification gate).
- **`--json`**: Machine-readable scan summary, `score`, `severityCounts`, `findings[]`, and `testFiles[]`.
- **`--sarif`**: Standard SARIF 2.1.0 JSON output for security tooling.
- **`--markdown`**: Clean Markdown audit report.

Example verification gate:

```powershell
node C:\Users\VIVOBOOK\deepcheck\scripts\audit.cjs "C:\path\to\project" "API / backend" --json --fail-on high
```

## Interpreting Results & Handling Findings

1. **Fix real `critical`, `high`, and `medium` findings first** (e.g., command/SQL injection, prototype pollution, hardcoded secrets, off-by-one loops, async race conditions, unawaited promises, `NaN`/`typeof` bugs, `sprintf`, `pickle.loads`).
2. **Validate context:** Static analysis is a high-signal heuristic, not formal proof. Read the reported `file:line` and `reason`/`hint` before editing.
3. **Suppress only verified false positives:** If a line is genuinely safe and intentionally flagged, add an inline comment rather than disabling rules globally:
   - `// deepcheck-disable-next-line <ruleId>` (or `# deepcheck-disable-next-line <ruleId>`)
   - `// deepcheck-disable-line <ruleId>`
4. **Re-run DeepCheck** after your final edit to confirm the fix and verify the updated score.
