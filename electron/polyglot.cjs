'use strict';

const { parse, kind, registerDynamicLanguage } = require('@ast-grep/napi');

function loadParsers() {
  return {
    python: require('@ast-grep/lang-python'),
    go: require('@ast-grep/lang-go'),
    rust: require('@ast-grep/lang-rust'),
    java: require('@ast-grep/lang-java'),
    kotlin: require('@ast-grep/lang-kotlin'),
    cpp: require('@ast-grep/lang-cpp'),
    csharp: require('@ast-grep/lang-csharp'),
    ruby: require('@ast-grep/lang-ruby'),
    php: require('@ast-grep/lang-php'),
    swift: require('@ast-grep/lang-swift'),
    bash: require('@ast-grep/lang-bash'),
  };
}

const languageByExtension = {
  '.py': 'python', '.go': 'go', '.rs': 'rust', '.java': 'java',
  '.kt': 'kotlin', '.kts': 'kotlin', '.c': 'cpp', '.h': 'cpp',
  '.cc': 'cpp', '.cpp': 'cpp', '.hpp': 'cpp', '.cs': 'csharp',
  '.rb': 'ruby', '.php': 'php', '.swift': 'swift',
  '.sh': 'bash', '.bash': 'bash', '.zsh': 'bash',
};

const rules = [
  { lang: 'python', pattern: 'eval($A)', id: 'polyglot-python-eval', title: 'Dynamic Python evaluation', severity: 'high', cwe: 'CWE-95', hint: 'Avoid eval on data; parse it or use a restricted mapping.' },
  { lang: 'python', pattern: 'exec($A)', id: 'polyglot-python-exec', title: 'Dynamic Python execution', severity: 'high', cwe: 'CWE-95', hint: 'Avoid exec on dynamic input; use explicit operations.' },
  { lang: 'python', pattern: 'pickle.loads($A)', id: 'polyglot-python-pickle', title: 'Unsafe Python deserialization', severity: 'high', cwe: 'CWE-502', hint: 'Do not load pickle data from untrusted sources.' },
  { lang: 'python', pattern: 'pickle.load($A)', id: 'polyglot-python-pickle', title: 'Unsafe Python deserialization', severity: 'high', cwe: 'CWE-502', hint: 'Do not load pickle data from untrusted sources.' },
  { lang: 'python', pattern: 'marshal.loads($A)', id: 'polyglot-python-marshal', title: 'Unsafe Python marshal deserialization', severity: 'high', cwe: 'CWE-502', hint: 'Do not unmarshal untrusted bytecode payloads.' },
  { lang: 'python', pattern: 'marshal.load($A)', id: 'polyglot-python-marshal', title: 'Unsafe Python marshal deserialization', severity: 'high', cwe: 'CWE-502', hint: 'Do not unmarshal untrusted bytecode payloads.' },
  { lang: 'python', pattern: 'yaml.load($A)', id: 'polyglot-python-yaml-load', title: 'Unsafe YAML deserialization', severity: 'high', cwe: 'CWE-502', hint: 'Use safe_load for YAML that is not fully trusted.' },
  { lang: 'python', pattern: 'os.system($A)', id: 'polyglot-python-shell', title: 'Shell command execution', severity: 'high', cwe: 'CWE-78', hint: 'Use subprocess with an argument list and no shell.' },
  { lang: 'python', pattern: 'subprocess.run($A, shell=True)', id: 'polyglot-python-shell', title: 'Shell command execution', severity: 'high', cwe: 'CWE-78', hint: 'Use subprocess with an argument list and no shell.' },
  { lang: 'python', pattern: 'cursor.execute($Q.format($$$))', id: 'polyglot-python-sql-format', title: 'SQL built with .format()', severity: 'high', cwe: 'CWE-89', hint: 'Pass query parameters as a tuple/list to cursor.execute instead of .format().' },
  { lang: 'python', pattern: 'cursor.execute($Q % $A)', id: 'polyglot-python-sql-percent', title: 'SQL built with % formatting', severity: 'high', cwe: 'CWE-89', hint: 'Pass query parameters as a tuple/list to cursor.execute instead of %.' },
  { lang: 'python', pattern: 'requests.get($URL)', id: 'polyglot-python-requests-timeout', title: 'HTTP request without timeout', severity: 'low', cwe: 'CWE-400', hint: 'Pass timeout=... so hung upstreams cannot stall the worker indefinitely.' },
  { lang: 'python', pattern: 'requests.post($URL)', id: 'polyglot-python-requests-timeout', title: 'HTTP request without timeout', severity: 'low', cwe: 'CWE-400', hint: 'Pass timeout=... so hung upstreams cannot stall the worker indefinitely.' },
  { lang: 'python', pattern: 'assert ($A, $B)', id: 'polyglot-python-assert-tuple', title: 'Assert on non-empty tuple (always true)', severity: 'high', cwe: 'CWE-670', hint: 'Remove the parentheses: "assert cond, msg" instead of "assert (cond, msg)".' },
  { lang: 'python', pattern: '$X is "$S"', id: 'polyglot-python-is-literal', title: 'Identity check (is) against string literal', severity: 'medium', cwe: 'CWE-595', hint: 'Use == for value equality; "is" checks object identity and fails unpredictably.' },
  { lang: 'python', pattern: 'except Exception:\n    pass', id: 'polyglot-python-except-pass', title: 'Silent broad exception swallow', severity: 'medium', cwe: 'CWE-390', hint: 'Log or handle the exception instead of swallowing all Exception types.' },
  { lang: 'python', pattern: 'except:\n    pass', id: 'polyglot-python-bare-except', title: 'Bare except: swallows KeyboardInterrupt and SystemExit', severity: 'medium', cwe: 'CWE-390', hint: 'Catch specific exceptions (except ValueError:) instead of a bare except:.' },
  { lang: 'python', pattern: 'def $F($A=[]):\n    $$$BODY', id: 'polyglot-python-mutable-default', title: 'Mutable default list argument in Python function', severity: 'high', cwe: 'CWE-665', hint: 'Use def f(x=None): and initialize x = [] inside the function so calls do not share one list.' },
  { lang: 'python', pattern: 'def $F($A={}):\n    $$$BODY', id: 'polyglot-python-mutable-default', title: 'Mutable default dict argument in Python function', severity: 'high', cwe: 'CWE-665', hint: 'Use def f(x=None): and initialize x = {} inside the function so calls do not share one dict.' },
  { lang: 'python', pattern: 'yaml.unsafe_load($A)', id: 'polyglot-python-yaml-unsafe', title: 'Unsafe YAML deserialization (unsafe_load)', severity: 'critical', cwe: 'CWE-502', hint: 'Use yaml.safe_load() instead of yaml.unsafe_load().' },
  { lang: 'python', pattern: 'os.popen($A)', id: 'polyglot-python-os-popen', title: 'Legacy os.popen shell execution', severity: 'high', cwe: 'CWE-78', hint: 'Replace os.popen with subprocess.run(..., shell=False).' },
  { lang: 'python', pattern: 'tempfile.mktemp($A)', id: 'polyglot-python-mktemp', title: 'Insecure tempfile.mktemp race condition', severity: 'medium', cwe: 'CWE-377', hint: 'Use tempfile.NamedTemporaryFile or tempfile.mkdtemp().' },
  { lang: 'python', pattern: 'tempfile.mktemp()', id: 'polyglot-python-mktemp', title: 'Insecure tempfile.mktemp race condition', severity: 'medium', cwe: 'CWE-377', hint: 'Use tempfile.NamedTemporaryFile or tempfile.mkdtemp().' },
  { lang: 'python', pattern: 'ssl._create_unverified_context()', id: 'polyglot-python-ssl-unverified', title: 'Unverified SSL context disabled certificate checks', severity: 'critical', cwe: 'CWE-295', hint: 'Use ssl.create_default_context() so TLS certificates are verified.' },
  { lang: 'python', pattern: 'hashlib.md5($A)', id: 'polyglot-python-weak-hash', title: 'Weak cryptographic hash (MD5)', severity: 'medium', cwe: 'CWE-328', hint: 'Use hashlib.sha256() or blake2b() for integrity hashing.' },
  { lang: 'python', pattern: 'hashlib.sha1($A)', id: 'polyglot-python-weak-hash', title: 'Weak cryptographic hash (SHA-1)', severity: 'medium', cwe: 'CWE-328', hint: 'Use hashlib.sha256() or blake2b() for integrity hashing.' },
  { lang: 'go', pattern: 'exec.Command("sh", "-c", $CMD)', id: 'polyglot-go-shell', title: 'Shell command execution', severity: 'high', cwe: 'CWE-78', hint: 'Avoid invoking a shell with dynamically assembled commands.' },
  { lang: 'go', pattern: 'exec.Command("bash", "-c", $CMD)', id: 'polyglot-go-shell', title: 'Shell command execution', severity: 'high', cwe: 'CWE-78', hint: 'Avoid invoking a shell with dynamically assembled commands.' },
  { lang: 'go', pattern: 'template.HTML($A)', id: 'polyglot-go-html', title: 'Unescaped HTML rendering', severity: 'high', cwe: 'CWE-79', hint: 'Do not convert untrusted strings to trusted HTML.' },
  { lang: 'go', pattern: 'InsecureSkipVerify: true', id: 'polyglot-go-tls-insecure', title: 'Go TLS verification disabled', severity: 'high', cwe: 'CWE-295', hint: 'Keep InsecureSkipVerify false outside isolated local tests.' },
  { lang: 'go', pattern: 'md5.New()', id: 'polyglot-go-weak-hash', title: 'Weak cryptographic hash (MD5)', severity: 'medium', cwe: 'CWE-327', hint: 'Use sha256.New() or stronger for integrity/security hashing.' },
  { lang: 'go', pattern: 'sha1.New()', id: 'polyglot-go-weak-hash', title: 'Weak cryptographic hash (SHA-1)', severity: 'medium', cwe: 'CWE-327', hint: 'Use sha256.New() or stronger for integrity/security hashing.' },
  { lang: 'go', pattern: 'http.ListenAndServe($ADDR, $HANDLER)', id: 'polyglot-go-cleartext-http', title: 'Go cleartext HTTP server', severity: 'medium', cwe: 'CWE-319', hint: 'Prefer http.ListenAndServeTLS or terminate TLS at a trusted reverse proxy.' },
  { lang: 'go', pattern: 'http.Get($URL)', id: 'polyglot-go-http-get-no-timeout', title: 'http.Get uses default client without timeout', severity: 'low', cwe: 'CWE-400', hint: 'Use an explicit &http.Client{Timeout: ...} instead of package-level http.Get.' },
  { lang: 'go', pattern: 'os.Chmod($PATH, 0777)', id: 'polyglot-go-chmod-777', title: 'World-writable file permissions (0777)', severity: 'high', cwe: 'CWE-732', hint: 'Restrict permissions to 0600 or 0750.' },
  { lang: 'go', pattern: 'rand.Intn($N)', id: 'polyglot-go-math-rand', title: 'Non-cryptographic math/rand usage', severity: 'low', cwe: 'CWE-338', hint: 'Use crypto/rand for tokens, keys, or security-sensitive randomness.' },
  { lang: 'go', pattern: 'for $COND { $$$A defer $CALL $$$B }', id: 'polyglot-go-defer-in-loop', title: 'defer inside Go for-loop leaks resources until function return', severity: 'medium', cwe: 'CWE-775', hint: 'Move loop body into a helper function or close resources explicitly at the end of each iteration.' },
  { lang: 'rust', pattern: 'Command::new("sh").arg("-c").arg($CMD)', id: 'polyglot-rust-shell', title: 'Shell command execution', severity: 'high', cwe: 'CWE-78', hint: 'Avoid passing dynamic command text through a shell.' },
  { lang: 'rust', pattern: 'Command::new("bash").arg("-c").arg($CMD)', id: 'polyglot-rust-shell', title: 'Shell command execution', severity: 'high', cwe: 'CWE-78', hint: 'Avoid passing dynamic command text through a shell.' },
  { lang: 'rust', pattern: 'std::mem::transmute($A)', id: 'polyglot-rust-transmute', title: 'Unsafe Rust memory transmute', severity: 'medium', cwe: 'CWE-704', hint: 'Prefer safe conversions or explicit pointer casts over transmute.' },
  { lang: 'rust', pattern: 'std::mem::uninitialized()', id: 'polyglot-rust-uninit', title: 'Deprecated std::mem::uninitialized()', severity: 'high', cwe: 'CWE-908', hint: 'Use MaybeUninit<T> instead of mem::uninitialized(), which causes instant UB.' },
  { lang: 'rust', pattern: 'std::mem::uninitialized::<$T>()', id: 'polyglot-rust-uninit', title: 'Deprecated std::mem::uninitialized()', severity: 'high', cwe: 'CWE-908', hint: 'Use MaybeUninit<T> instead of mem::uninitialized(), which causes instant UB.' },
  { lang: 'rust', pattern: 'std::mem::zeroed::<$T>()', id: 'polyglot-rust-zeroed', title: 'Unsafe std::mem::zeroed() initialization', severity: 'medium', cwe: 'CWE-908', hint: 'Verify T permits all-zero bit patterns or use MaybeUninit<T>::zeroed().' },
  { lang: 'rust', pattern: 'String::from_utf8_unchecked($A)', id: 'polyglot-rust-utf8-unchecked', title: 'Unchecked UTF-8 conversion can cause UB', severity: 'high', cwe: 'CWE-704', hint: 'Use String::from_utf8() to validate UTF-8 bytes.' },
  { lang: 'java', pattern: 'new ObjectInputStream($A).readObject()', id: 'polyglot-java-deserialize', title: 'Unsafe Java deserialization', severity: 'high', cwe: 'CWE-502', hint: 'Avoid native object deserialization for untrusted data.' },
  { lang: 'java', pattern: 'Runtime.getRuntime().exec($CMD)', id: 'polyglot-java-shell', title: 'Shell command execution', severity: 'high', cwe: 'CWE-78', hint: 'Use a fixed executable and validated argument list.' },
  { lang: 'java', pattern: 'MessageDigest.getInstance("MD5")', id: 'polyglot-java-weak-hash', title: 'Weak cryptographic hash (MD5)', severity: 'medium', cwe: 'CWE-327', hint: 'Use SHA-256 or stronger.' },
  { lang: 'java', pattern: 'MessageDigest.getInstance("SHA-1")', id: 'polyglot-java-weak-hash', title: 'Weak cryptographic hash (SHA-1)', severity: 'medium', cwe: 'CWE-327', hint: 'Use SHA-256 or stronger.' },
  { lang: 'java', pattern: 'Cipher.getInstance("DES")', id: 'polyglot-java-weak-cipher', title: 'Weak DES cipher in Java', severity: 'high', cwe: 'CWE-327', hint: 'Use AES-GCM (AES/GCM/NoPadding) instead of DES.' },
  { lang: 'java', pattern: 'Cipher.getInstance("AES/ECB/PKCS5Padding")', id: 'polyglot-java-weak-cipher', title: 'Insecure AES-ECB cipher mode', severity: 'high', cwe: 'CWE-327', hint: 'ECB mode leaks patterns; use AES/GCM/NoPadding.' },
  { lang: 'java', pattern: '$STMT.executeQuery($Q + $A)', id: 'polyglot-java-sql-concat', title: 'Java SQL string concatenation', severity: 'high', cwe: 'CWE-89', hint: 'Use PreparedStatement with bound parameters.' },
  { lang: 'java', pattern: 'catch (Exception $E) {}', id: 'polyglot-java-empty-catch', title: 'Empty Java catch block', severity: 'medium', cwe: 'CWE-390', hint: 'Log or rethrow caught exceptions instead of ignoring them.' },
  { lang: 'java', pattern: 'SSLContext.getInstance("TLSv1")', id: 'polyglot-java-weak-tls', title: 'Deprecated TLSv1 protocol in Java', severity: 'high', cwe: 'CWE-326', hint: 'Use SSLContext.getInstance("TLSv1.3") or "TLSv1.2".' },
  { lang: 'java', pattern: 'new Random()', id: 'polyglot-java-weak-random', title: 'Non-cryptographic java.util.Random', severity: 'low', cwe: 'CWE-338', hint: 'Use java.security.SecureRandom for security-sensitive values.' },
  { lang: 'java', pattern: '$STMT.execute($Q + $A)', id: 'polyglot-java-sql-concat', title: 'Java SQL string concatenation', severity: 'high', cwe: 'CWE-89', hint: 'Use PreparedStatement with bound parameters.' },
  { lang: 'kotlin', pattern: 'Runtime.getRuntime().exec($CMD)', id: 'polyglot-kotlin-shell', title: 'Shell command execution', severity: 'high', cwe: 'CWE-78', hint: 'Use a fixed executable and validated argument list.' },
  { lang: 'kotlin', pattern: 'ObjectInputStream($A).readObject()', id: 'polyglot-kotlin-deserialize', title: 'Unsafe Kotlin deserialization', severity: 'high', cwe: 'CWE-502', hint: 'Avoid ObjectInputStream on untrusted streams.' },
  { lang: 'ruby', pattern: 'Marshal.load($A)', id: 'polyglot-ruby-deserialize', title: 'Unsafe Ruby deserialization', severity: 'high', cwe: 'CWE-502', hint: 'Do not deserialize untrusted data with Marshal.' },
  { lang: 'ruby', pattern: 'YAML.load($A)', id: 'polyglot-ruby-yaml-load', title: 'Unsafe Ruby YAML.load', severity: 'high', cwe: 'CWE-502', hint: 'Use YAML.safe_load for untrusted input.' },
  { lang: 'ruby', pattern: 'eval($A)', id: 'polyglot-ruby-eval', title: 'Dynamic Ruby evaluation', severity: 'high', cwe: 'CWE-95', hint: 'Avoid evaluating dynamically supplied Ruby code.' },
  { lang: 'ruby', pattern: 'system($A)', id: 'polyglot-ruby-shell', title: 'Shell command execution', severity: 'high', cwe: 'CWE-78', hint: 'Pass a fixed executable and separate validated arguments.' },
  { lang: 'php', pattern: 'eval', id: 'polyglot-php-eval', title: 'Dynamic PHP evaluation', severity: 'high', cwe: 'CWE-95', hint: 'Avoid evaluating dynamically supplied PHP code.' },
  { lang: 'php', pattern: 'unserialize', id: 'polyglot-php-deserialize', title: 'Unsafe PHP deserialization', severity: 'high', cwe: 'CWE-502', hint: 'Avoid unserialize on untrusted data; use a safe data format.' },
  { lang: 'php', pattern: 'system', id: 'polyglot-php-shell', title: 'Shell command execution', severity: 'high', cwe: 'CWE-78', hint: 'Avoid shell APIs or strictly validate an argument array.' },
  { lang: 'php', pattern: 'shell_exec', id: 'polyglot-php-shell', title: 'Shell command execution', severity: 'high', cwe: 'CWE-78', hint: 'Avoid shell APIs or strictly validate an argument array.' },
  { lang: 'php', pattern: 'passthru', id: 'polyglot-php-shell', title: 'Shell command execution', severity: 'high', cwe: 'CWE-78', hint: 'Avoid shell APIs or strictly validate an argument array.' },
  { lang: 'php', pattern: 'exec', id: 'polyglot-php-shell', title: 'Shell command execution', severity: 'high', cwe: 'CWE-78', hint: 'Avoid shell APIs or strictly validate an argument array.' },
  { lang: 'php', pattern: 'md5', id: 'polyglot-php-weak-hash', title: 'Weak MD5 hash in PHP', severity: 'medium', cwe: 'CWE-327', hint: 'Use password_hash() for passwords or hash("sha256", ...) for digests.' },
  { lang: 'cpp', pattern: 'gets($A)', id: 'polyglot-cpp-gets', title: 'Unbounded C++ input read', severity: 'high', cwe: 'CWE-787', hint: 'Use a bounded input API.' },
  { lang: 'cpp', pattern: 'strcpy($A, $B)', id: 'polyglot-cpp-copy', title: 'Unbounded C++ string copy', severity: 'medium', cwe: 'CWE-120', hint: 'Use a bounds-checked copy and validate destination capacity.' },
  { lang: 'cpp', pattern: 'strcat($A, $B)', id: 'polyglot-cpp-strcat', title: 'Unbounded C++ string concatenation', severity: 'medium', cwe: 'CWE-120', hint: 'Use bounded string concatenation and verify buffer capacity.' },
  { lang: 'cpp', pattern: 'sprintf($BUF, $$$)', id: 'polyglot-cpp-sprintf', title: 'Unbounded C/C++ sprintf', severity: 'high', cwe: 'CWE-120', hint: 'Use snprintf with explicit buffer size.' },
  { lang: 'cpp', pattern: 'vsprintf($BUF, $FMT, $ARGS)', id: 'polyglot-cpp-vsprintf', title: 'Unbounded C/C++ vsprintf', severity: 'high', cwe: 'CWE-120', hint: 'Use vsnprintf with explicit buffer size.' },
  { lang: 'cpp', pattern: 'scanf("%s", $BUF)', id: 'polyglot-cpp-scanf', title: 'Unbounded C/C++ scanf("%s")', severity: 'high', cwe: 'CWE-120', hint: 'Specify a field width limit or use fgets to prevent stack buffer overflow.' },
  { lang: 'cpp', pattern: 'system($CMD)', id: 'polyglot-cpp-system', title: 'C/C++ shell command execution', severity: 'high', cwe: 'CWE-78', hint: 'Avoid system(); invoke an executable directly without a shell.' },
  { lang: 'cpp', pattern: 'tmpnam($A)', id: 'polyglot-cpp-tmpnam', title: 'Insecure C tmpnam() race condition', severity: 'medium', cwe: 'CWE-377', hint: 'Use mkstemp() instead of tmpnam().' },
  { lang: 'cpp', pattern: 'mktemp($A)', id: 'polyglot-cpp-mktemp', title: 'Insecure C mktemp() race condition', severity: 'medium', cwe: 'CWE-377', hint: 'Use mkstemp() instead of mktemp().' },
  { lang: 'csharp', pattern: 'new BinaryFormatter()', id: 'polyglot-csharp-binaryformatter', title: 'Unsafe .NET binary formatter', severity: 'high', cwe: 'CWE-502', hint: 'Replace BinaryFormatter with a safe, constrained format.' },
  { lang: 'csharp', pattern: 'new LosFormatter()', id: 'polyglot-csharp-losformatter', title: 'Unsafe .NET LosFormatter', severity: 'high', cwe: 'CWE-502', hint: 'Avoid LosFormatter on untrusted payloads.' },
  { lang: 'csharp', pattern: 'new JavaScriptSerializer()', id: 'polyglot-csharp-js-serializer', title: 'Unsafe .NET JavaScriptSerializer', severity: 'medium', cwe: 'CWE-502', hint: 'Prefer System.Text.Json without SimpleTypeResolver.' },
  { lang: 'csharp', pattern: 'MD5.Create()', id: 'polyglot-csharp-weak-hash', title: 'Weak cryptographic hash (MD5)', severity: 'medium', cwe: 'CWE-327', hint: 'Use SHA256.Create() or stronger.' },
  { lang: 'csharp', pattern: 'SHA1.Create()', id: 'polyglot-csharp-weak-hash', title: 'Weak cryptographic hash (SHA-1)', severity: 'medium', cwe: 'CWE-327', hint: 'Use SHA256.Create() or stronger.' },
  { lang: 'csharp', pattern: 'Process.Start($CMD)', id: 'polyglot-csharp-process-start', title: 'Process launch in .NET', severity: 'medium', cwe: 'CWE-78', hint: 'Validate executable paths and disable UseShellExecute for untrusted input.' },
  { lang: 'csharp', pattern: 'new DESCryptoServiceProvider()', id: 'polyglot-csharp-weak-cipher', title: 'Broken DES cipher in .NET', severity: 'high', cwe: 'CWE-327', hint: 'Use Aes.Create() with GCM or authenticated CBC.' },
  { lang: 'ruby', pattern: 'Digest::MD5.hexdigest($A)', id: 'polyglot-ruby-weak-hash', title: 'Weak MD5 hash in Ruby', severity: 'medium', cwe: 'CWE-328', hint: 'Use Digest::SHA256.hexdigest or BCrypt/Argon2 for passwords.' },
  { lang: 'swift', pattern: 'NSKeyedUnarchiver.unarchiveObject(with: $A)', id: 'polyglot-swift-deserialize', title: 'Non-coding-secure Swift unarchiver', severity: 'high', cwe: 'CWE-502', hint: 'Use NSSecureCoding and unarchivedObject(ofClass:from:).' },
  { lang: 'swift', pattern: 'evaluateJavaScript($A)', id: 'polyglot-swift-js-eval', title: 'Dynamic JavaScript evaluation in WebView', severity: 'medium', cwe: 'CWE-79', hint: 'Never interpolate untrusted data into evaluateJavaScript.' },
  { lang: 'swift', pattern: 'CC_MD5($A, $B, $C)', id: 'polyglot-swift-weak-hash', title: 'Deprecated CC_MD5 hash in Swift', severity: 'medium', cwe: 'CWE-328', hint: 'Use CryptoKit SHA256 instead of CC_MD5.' },
  { lang: 'bash', pattern: 'eval $CMD', id: 'polyglot-bash-eval', title: 'Dynamic shell evaluation', severity: 'high', cwe: 'CWE-95', hint: 'Avoid eval; keep data separate from executable commands.' },
];

let registered = false;
const RELIABLE_SYNTAX_ERROR_LANGS = new Set(['python', 'go', 'rust', 'java', 'cpp', 'csharp', 'bash']);
const rulesByLang = new Map();
for (const rule of rules) {
  const list = rulesByLang.get(rule.lang) || [];
  list.push(rule);
  rulesByLang.set(rule.lang, list);
}

function ensureParsers() {
  if (registered) return;
  registerDynamicLanguage(loadParsers());
  registered = true;
}

function analyzePolyglot(source, file, extension, suppressions) {
  const language = languageByExtension[extension];
  if (!language) return [];
  ensureParsers();
  let root;
  try {
    root = parse(language, source).root();
  } catch {
    return [];
  }

  const lines = source.split(/\r?\n/);
  const emitted = new Set();
  const findings = [];
  let syntaxErrors = [];
  if (RELIABLE_SYNTAX_ERROR_LANGS.has(language)) {
    try {
      syntaxErrors = root.findAll(kind(language, 'ERROR'));
    } catch (error) {
      syntaxErrors = error ? [] : [];
    }
  }
  for (const error of syntaxErrors.slice(0, 3)) {
    const line = error.range().start.line + 1;
    const lineText = String(lines[line - 1] || error.text());
    // Skip Go 1.26 new(expr) syntax that older tree-sitter Go grammars flag as ERROR
    if (language === 'go' && /\bnew\s*\(/.test(lineText)) continue;
    const ruleId = 'polyglot-syntax-error';
    if (suppressions && (
      suppressions.allLines.value
      || suppressions.fileWide.has(ruleId)
      || suppressions.byLine.get(line)?.has('*')
      || suppressions.byLine.get(line)?.has(ruleId)
    )) continue;
    const key = `${ruleId}:${line}`;
    if (emitted.has(key)) continue;
    emitted.add(key);
    findings.push({
      id: `${file}:${line}:${ruleId}`,
      ruleId,
      title: 'Possible syntax error',
      severity: 'info',
      hint: 'Check this parser-reported syntax error; parser recovery may affect nearby findings.',
      confidence: 'low',
      reason: 'The language parser produced an ERROR node at this location.',
      file,
      line,
      excerpt: lineText.trim().slice(0, 220),
    });
  }
  for (const rule of (rulesByLang.get(language) || [])) {
    let matches;
    try {
      matches = language === 'php'
        ? root.findAll(kind(language, 'function_call_expression')).filter((node) => node.namedChildren()[0]?.text() === rule.pattern)
        : root.findAll(rule.pattern);
    } catch {
      continue;
    }
    for (const match of matches) {
      const line = match.range().start.line + 1;
      const key = `${rule.id}:${line}`;
      if (emitted.has(key) || suppressions && (
        suppressions.allLines.value
        || suppressions.fileWide.has(rule.id)
        || suppressions.byLine.get(line)?.has('*')
        || suppressions.byLine.get(line)?.has(rule.id)
      )) continue;
      emitted.add(key);
      findings.push({
        id: `${file}:${line}:${rule.id}`,
        ruleId: rule.id,
        title: rule.title,
        severity: rule.severity,
        cwe: rule.cwe,
        hint: rule.hint,
        confidence: 'high',
        reason: 'Language AST matched a risky API pattern; review its input and runtime context.',
        file,
        line,
        excerpt: String(lines[line - 1] || match.text()).trim().slice(0, 220),
      });
    }
  }
  return findings;
}

module.exports = { analyzePolyglot, languageByExtension };
