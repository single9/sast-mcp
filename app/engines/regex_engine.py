"""內建 regex 規則引擎（零外部依賴的後備引擎）。

定位是「沒有 Semgrep 時仍可運作的基本掃描」：規則以單行／簡單多行 regex 為主，
誤報率會比語意引擎高，報告中會標示 engine=builtin-regex。
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass
from pathlib import Path

from ..config import EXCLUDE_DIRS, SKIP_EXTENSIONS, get_settings
from ..models import Finding, normalize_severity
from .base import Engine, EngineResult

MAX_SNIPPET = 300
MAX_MATCHES_PER_RULE_PER_FILE = 20

LANG_BY_EXT = {
    ".py": "python",
    ".pyw": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".java": "java",
    ".go": "go",
    ".php": "php",
    ".rb": "ruby",
    ".cs": "csharp",
    ".rs": "rust",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".hxx": "cpp",
    ".ino": "cpp",
}

_SECRET_ALLOW = re.compile(
    r"""(?ix)
    ( os\.environ | getenv | process\.env | import\.meta\.env | \{\{ | <% | \$\{ |
      example | sample | changeme | change[_-]me | placeholder | dummy | fake |
      redacted | your[_-] | x{4,} | \*{3,} | \.\.\. | <[^>]+> )
    """,
)


@dataclass(frozen=True)
class RegexRule:
    id: str
    regex: re.Pattern[str]
    severity: str
    message: str
    cwe: tuple[str, ...]
    languages: tuple[str, ...] | None = None
    allow: re.Pattern[str] | None = None


def _rule(
    rule_id: str,
    pattern: str,
    severity: str,
    message: str,
    cwe: tuple[str, ...],
    *,
    languages: tuple[str, ...] | None = None,
    allow: re.Pattern[str] | None = None,
    flags: int = 0,
) -> RegexRule:
    return RegexRule(
        id=rule_id,
        regex=re.compile(pattern, flags),
        severity=severity,
        message=message,
        cwe=cwe,
        languages=languages,
        allow=allow,
    )


PY = ("python",)
JS = ("javascript",)
JAVA = ("java",)
GO = ("go",)
PHP = ("php",)
RB = ("ruby",)
CS = ("csharp",)
C = ("c",)
CPP = ("c", "cpp")
RUST = ("rust",)

RULES: tuple[RegexRule, ...] = (
    # ---------------- Python ----------------
    _rule(
        "builtin-python-eval",
        r"\beval\s*\(",
        "high",
        "使用 eval() 執行動態字串，可能導致遠端程式碼執行。",
        ("CWE-95",),
        languages=PY,
    ),
    _rule(
        "builtin-python-exec",
        r"(?<![\w.])exec\s*\(",
        "high",
        "使用 exec() 執行動態程式碼，可能導致遠端程式碼執行。",
        ("CWE-95",),
        languages=PY,
    ),
    _rule(
        "builtin-python-os-system",
        r"\bos\.(?:system|popen)\s*\(",
        "high",
        "使用 os.system / os.popen 執行 shell 指令，請改用參數化 API。",
        ("CWE-78",),
        languages=PY,
    ),
    _rule(
        "builtin-python-subprocess-shell",
        r"subprocess\.(?:run|call|Popen|check_output|check_call)\s*\(\s*[^)]*shell\s*=\s*True",
        "high",
        "subprocess 使用 shell=True，若指令含使用者輸入可能造成命令注入。",
        ("CWE-78",),
        languages=PY,
        flags=re.DOTALL,
    ),
    _rule(
        "builtin-python-pickle",
        r"\bpickle\.(?:loads?|Unpickler)\s*\(",
        "medium",
        "反序列化 pickle 資料可能導致程式碼執行，請改用安全格式。",
        ("CWE-502",),
        languages=PY,
    ),
    _rule(
        "builtin-python-yaml-load",
        r"\byaml\.load\s*\(",
        "medium",
        "yaml.load() 若未指定 SafeLoader 可能導致程式碼執行。",
        ("CWE-502",),
        languages=PY,
    ),
    _rule(
        "builtin-python-weak-hash",
        r"\bhashlib\.(?:md5|sha1)\s*\(|\b(?:md5|sha1)\s*\(",
        "low",
        "使用 MD5/SHA-1 等已弱化的雜湊演算法。",
        ("CWE-327",),
        languages=PY,
    ),
    _rule(
        "builtin-python-sql-injection",
        r"""(?:execute|executemany)\s*\(\s*(?:f["']|["'][^"']*["']\s*(?:%|\+|\.format\s*\())""",
        "high",
        "SQL 語句以字串拼接／格式化組成，可能造成 SQL injection。",
        ("CWE-89",),
        languages=PY,
        flags=re.DOTALL,
    ),
    _rule(
        "builtin-python-flask-debug",
        r"\.run\s*\([^)]*debug\s*=\s*True",
        "medium",
        "Flask 開啟 debug 模式，請勿在正式環境使用。",
        ("CWE-489",),
        languages=PY,
        flags=re.DOTALL,
    ),
    _rule(
        "builtin-python-verify-false",
        r"\bverify\s*=\s*False",
        "medium",
        "停用 TLS 憑證驗證，可能遭受中間人攻擊。",
        ("CWE-295",),
        languages=PY,
    ),
    # ---------------- JavaScript / TypeScript ----------------
    _rule(
        "builtin-js-eval",
        r"\beval\s*\(",
        "high",
        "使用 eval() 可能導致程式碼注入。",
        ("CWE-95",),
        languages=JS,
    ),
    _rule(
        "builtin-js-new-function",
        r"\bnew\s+Function\s*\(",
        "high",
        "new Function() 會將字串當成程式碼執行。",
        ("CWE-95",),
        languages=JS,
    ),
    _rule(
        "builtin-js-innerhtml",
        r"\.innerHTML\s*=",
        "high",
        "直接指派 innerHTML 可能造成 XSS，請改用 textContent 或經過消毒。",
        ("CWE-79",),
        languages=JS,
    ),
    _rule(
        "builtin-js-dangerously-set-inner-html",
        r"dangerouslySetInnerHTML",
        "medium",
        "React 的 dangerouslySetInnerHTML 可能造成 XSS。",
        ("CWE-79",),
        languages=JS,
    ),
    _rule(
        "builtin-js-document-write",
        r"\bdocument\.write(?:ln)?\s*\(",
        "medium",
        "document.write 可能造成 DOM-based XSS。",
        ("CWE-79",),
        languages=JS,
    ),
    _rule(
        "builtin-js-child-process",
        r"\bchild_process\b[^\n]*\.exec(?:Sync)?\s*\(",
        "high",
        "child_process.exec 會透過 shell 執行指令，可能造成命令注入。",
        ("CWE-78",),
        languages=JS,
    ),
    _rule(
        "builtin-js-sql-template",
        r"(?:query|execute)\s*\(\s*`[^`]*\$\{",
        "high",
        "SQL 語句以樣板字串拼接，可能造成 SQL injection。",
        ("CWE-89",),
        languages=JS,
        flags=re.DOTALL,
    ),
    # ---------------- Java ----------------
    _rule(
        "builtin-java-runtime-exec",
        r"Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(",
        "high",
        "Runtime.exec 可能造成命令注入。",
        ("CWE-78",),
        languages=JAVA,
    ),
    _rule(
        "builtin-java-sql-concat",
        r"\.execute(?:Query|Update|Batch)?\s*\([^)]*\+",
        "high",
        "以字串串接組 SQL，可能造成 SQL injection。",
        ("CWE-89",),
        languages=JAVA,
        flags=re.DOTALL,
    ),
    _rule(
        "builtin-java-weak-hash",
        r"MessageDigest\.getInstance\s*\(\s*[\"'](?:MD5|SHA-?1)[\"']",
        "medium",
        "使用 MD5/SHA-1 等已弱化的雜湊演算法。",
        ("CWE-327",),
        languages=JAVA,
        flags=re.IGNORECASE,
    ),
    # ---------------- Go ----------------
    _rule(
        "builtin-go-exec-command",
        r"\bexec\.Command(?:Context)?\s*\(",
        "low",
        "exec.Command 若帶入未驗證的使用者輸入，可能造成命令注入。",
        ("CWE-78",),
        languages=GO,
    ),
    # ---------------- PHP ----------------
    _rule(
        "builtin-php-code-exec",
        r"\b(?:eval|assert)\s*\(",
        "high",
        "動態執行程式碼可能導致遠端程式碼執行。",
        ("CWE-95",),
        languages=PHP,
    ),
    _rule(
        "builtin-php-shell-exec",
        r"\b(?:system|shell_exec|passthru|exec|popen|proc_open)\s*\(",
        "high",
        "執行 shell 指令可能造成命令注入。",
        ("CWE-78",),
        languages=PHP,
    ),
    # ---------------- Ruby ----------------
    _rule(
        "builtin-ruby-code-exec",
        r"\b(?:eval|instance_eval|class_eval|send)\s*\(",
        "medium",
        "動態執行程式碼可能導致程式碼注入。",
        ("CWE-95",),
        languages=RB,
    ),
    # ---------------- Node.js ----------------
    _rule(
        "builtin-node-vm-exec",
        r"\bvm\.runIn(?:New|This)?Context\s*\(",
        "high",
        "使用 vm 執行字串程式碼；若內容含使用者輸入，可能造成遠端程式碼執行。",
        ("CWE-95",),
        languages=JS,
    ),
    _rule(
        "builtin-node-weak-hash",
        r"\bcrypto\.create(?:Hash|Hmac)\s*\(\s*[\"'](?:md5|sha1)[\"']",
        "medium",
        "使用 MD5/SHA-1 等已弱化的雜湊演算法；密碼請改用 bcrypt/argon2，完整性請用 SHA-256 以上。",
        ("CWE-327",),
        languages=JS,
        flags=re.IGNORECASE,
    ),
    _rule(
        "builtin-node-insecure-tls",
        r"(?i)\b(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0)",
        "high",
        "停用 TLS 憑證驗證，可能遭受中間人攻擊。",
        ("CWE-295",),
        languages=JS,
    ),
    _rule(
        "builtin-node-spawn-shell",
        r"(?is)\b(?:spawn|spawnSync|execFile|execFileSync)\s*\([^;]*\bshell\s*:\s*true",
        "high",
        "spawn/execFile 使用 shell: true，若參數含使用者輸入可能造成命令注入。",
        ("CWE-78",),
        languages=JS,
    ),
    _rule(
        "builtin-node-weak-cipher",
        r"(?i)\bcreateCipher\s*\(|\bcreateCipheriv\s*\(\s*[\"'](?:des|des-ede3|rc4|rc2|bf)",
        "medium",
        "使用已淘汰或不安全的加密演算法（createCipher/DES/RC4），請改用 AES-GCM 等 AEAD。",
        ("CWE-327",),
        languages=JS,
    ),
    _rule(
        "builtin-node-jwt-none",
        r"(?is)algorithms\s*:\s*\[\s*[\"']none[\"']",
        "high",
        "JWT 允許 alg=none，攻擊者可自行偽造權杖。",
        ("CWE-347",),
        languages=JS,
    ),
    _rule(
        "builtin-node-sql-concat",
        r"(?i)\b(?:query|execute)\s*\(\s*[\"'][^\"']*[\"']\s*\+",
        "high",
        "SQL 語句以字串串接組成，可能造成 SQL injection；請改用參數化查詢。",
        ("CWE-89",),
        languages=JS,
    ),
    # ---------------- C / C++ ----------------
    _rule(
        "builtin-cpp-gets",
        r"\bgets\s*\(",
        "high",
        "gets() 不檢查緩衝區長度，已被移除；請改用 fgets()。",
        ("CWE-242",),
        languages=CPP,
    ),
    _rule(
        "builtin-cpp-unsafe-string-functions",
        r"\b(?:strcpy|strcat|sprintf|vsprintf)\s*\(",
        "medium",
        "strcpy/strcat/sprintf 不檢查目的緩衝區長度，可能造成溢位；請改用 strncpy/strncat/snprintf。",
        ("CWE-120",),
        languages=CPP,
    ),
    _rule(
        "builtin-cpp-command-exec",
        r"\b(?:system|popen)\s*\(",
        "high",
        "system/popen 會透過 shell 執行指令，若含使用者輸入可能造成命令注入。",
        ("CWE-78",),
        languages=CPP,
    ),
    _rule(
        "builtin-cpp-format-string",
        r"\bprintf\s*\(\s*[A-Za-z_]\w*\s*[,)]",
        "high",
        "printf 的第一個參數不是字串常值，若含使用者輸入可能造成格式字串攻擊。",
        ("CWE-134",),
        languages=CPP,
    ),
    _rule(
        "builtin-cpp-weak-crypto",
        r"\b(?:MD5|SHA1)(?:_Init)?\s*\(|\bEVP_(?:md5|sha1)\s*\(",
        "medium",
        "使用 MD5/SHA-1 等已弱化的雜湊演算法。",
        ("CWE-327",),
        languages=CPP,
        flags=re.IGNORECASE,
    ),
    _rule(
        "builtin-cpp-insecure-temp",
        r"\b(?:tmpnam|tempnam|mktemp)\s*\(",
        "medium",
        "tmpnam/mktemp 產生可預測的暫存檔名，可能導致符號連結攻擊或檔案覆寫。",
        ("CWE-377",),
        languages=CPP,
    ),
    _rule(
        "builtin-cpp-permissive-file-mode",
        r"\b(?:chmod|open|creat)\s*\([^;\n]*\b0?777\b",
        "medium",
        "建立檔案時使用 0777 權限，任何使用者都可讀寫；請改用最小權限。",
        ("CWE-732",),
        languages=CPP,
        flags=re.IGNORECASE,
    ),
    _rule(
        "builtin-cpp-unsafe-scanf",
        r"\b(?:scanf|fscanf|sscanf)\s*\([^;\n]*%s",
        "medium",
        "scanf 使用 %s 沒有長度限制，可能造成緩衝區溢位；請改用 %Ns 或 fgets。",
        ("CWE-120",),
        languages=CPP,
        flags=re.IGNORECASE,
    ),
    _rule(
        "builtin-cpp-exec-family",
        r"\bexec(?:l|le|lp|v|ve|vp|vpe)\s*\(",
        "medium",
        "使用 exec 系列函式執行外部程式；請確認參數不含未驗證的使用者輸入。",
        ("CWE-78",),
        languages=CPP,
        flags=re.IGNORECASE,
    ),
    # ---------------- C# / .NET ----------------
    _rule(
        "builtin-csharp-sql-injection",
        r'(?is)\b(?:new\s+SqlCommand|CommandText\s*=)\s*\(?\s*(?:"(?:[^"\\]|\\.)*"\s*\+|\$"(?:[^"\\]|\\.)*\{|string\.Format\s*\()',
        "high",
        "SQL 語句以字串串接或插值組成，可能造成 SQL injection；請改用參數化查詢。",
        ("CWE-89",),
        languages=CS,
    ),
    _rule(
        "builtin-csharp-command-injection",
        r"\bProcess\.Start\s*\(",
        "medium",
        "Process.Start 若帶入未驗證的使用者輸入，可能造成命令注入或任意程式執行。",
        ("CWE-78",),
        languages=CS,
    ),
    _rule(
        "builtin-csharp-binary-formatter",
        r"\bnew\s+(?:BinaryFormatter|LosFormatter|ObjectStateFormatter|NetDataContractSerializer|SoapFormatter)\s*\(",
        "high",
        "BinaryFormatter 等格式反序列化不受信任資料可能導致遠端程式碼執行。",
        ("CWE-502",),
        languages=CS,
    ),
    _rule(
        "builtin-csharp-weak-hash",
        r"\b(?:MD5|SHA1)\.(?:Create|HashData)\s*\(|\bnew\s+(?:MD5|SHA1)CryptoServiceProvider\s*\(",
        "medium",
        "使用 MD5/SHA-1 等已弱化的雜湊演算法；密碼請改用 bcrypt/argon2/PBKDF2。",
        ("CWE-327",),
        languages=CS,
        flags=re.IGNORECASE,
    ),
    _rule(
        "builtin-csharp-xxe",
        r"\bDtdProcessing\.Parse\b|\bXmlResolver\s*=\s*new\s+XmlUrlResolver\s*\(",
        "medium",
        "啟用 DTD 或外部 XML resolver 可能導致 XXE；請關閉 DtdProcessing 並避免 XmlUrlResolver。",
        ("CWE-611",),
        languages=CS,
    ),
    _rule(
        "builtin-csharp-request-validation-disabled",
        r"(?i)\[?\s*ValidateInput\s*\(\s*false\s*\)",
        "medium",
        "停用請求驗證會讓未過濾的輸入進入應用程式，請改用明確的白名單或編碼。",
        ("CWE-79",),
        languages=CS,
    ),
    _rule(
        "builtin-csharp-cors-allow-any",
        r"\bAllowAnyOrigin\s*\(\s*\)",
        "medium",
        "CORS 允許任意來源；若 API 帶有認證或敏感資料，請改用明確白名單。",
        ("CWE-942",),
        languages=CS,
    ),
    _rule(
        "builtin-csharp-insecure-cookie",
        r"(?is)new\s+HttpCookie\s*\([^)]*\)\s*\{[^}]*\bSecure\s*=\s*false",
        "medium",
        "Cookie 未設定 Secure，可能經由明文 HTTP 傳輸而外洩。",
        ("CWE-614",),
        languages=CS,
    ),
    _rule(
        "builtin-csharp-ldap-injection",
        r'(?is)(?:\bnew\s+DirectorySearcher\s*\(\s*|\.Filter\s*=\s*)(?:"(?:[^"\\]|\\.)*"\s*\+|\$"(?:[^"\\]|\\.)*\{)',
        "high",
        "LDAP filter 以字串串接或插值組成，可能造成 LDAP injection。",
        ("CWE-90",),
        languages=CS,
    ),
    _rule(
        "builtin-csharp-connection-string-secret",
        r"(?i)\b(?:Password|Pwd)\s*=\s*[^;\"'\s]{6,}",
        "medium",
        "連線字串直接內嵌密碼，請改用整合驗證或密鑰管理服務。",
        ("CWE-798",),
        languages=CS,
        allow=_SECRET_ALLOW,
    ),
    # ---------------- Rust ----------------
    _rule(
        "builtin-rust-shell-command",
        r'\bCommand::new\s*\(\s*"(?:sh|bash|zsh|dash|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh(?:\.exe)?)"',
        "high",
        "直接叫用 shell 執行指令；若參數含使用者輸入，可能造成命令注入。",
        ("CWE-78",),
        languages=RUST,
    ),
    _rule(
        "builtin-rust-insecure-tls",
        r"danger_accept_invalid_(?:certs|hostnames)\s*\(\s*true",
        "high",
        "停用 TLS 憑證或主機名稱驗證，可能遭受中間人攻擊。",
        ("CWE-295",),
        languages=RUST,
    ),
    _rule(
        "builtin-rust-weak-hash",
        r"\b(?:md5::compute|sha1::Sha1::new|Md5::new|Sha1::new)\s*\(",
        "medium",
        "使用 MD5/SHA-1 等已弱化的雜湊演算法。",
        ("CWE-327",),
        languages=RUST,
    ),
    _rule(
        "builtin-rust-sql-format",
        r'(?is)\bformat!\s*\(\s*"[^"]*\b(?:select|insert|update|delete)\b',
        "medium",
        "以 format! 拼接 SQL 字串；若插值含使用者輸入，可能造成 SQL injection。",
        ("CWE-89",),
        languages=RUST,
    ),
    _rule(
        "builtin-rust-unsafe",
        r"\bunsafe\s*\{",
        "info",
        "unsafe 區塊需人工確認記憶體安全與型別不變量。",
        ("CWE-758",),
        languages=RUST,
    ),
    _rule(
        "builtin-rust-secret-logged",
        r'(?is)\b(?:println|eprintln|print|tracing::(?:trace|debug|info|warn|error))!\s*\(\s*"[^"]*\b(?:token|secret|password|passwd|api[_-]?key|access[_-]?key)\b',
        "medium",
        "把權杖、密碼或金鑰寫進日誌／標準輸出，可能經由日誌收集外洩。",
        ("CWE-532",),
        languages=RUST,
    ),
    _rule(
        "builtin-rust-permissive-cors",
        r"CorsLayer::permissive\s*\(|allow_(?:origin|methods|headers)\s*\(\s*Any\s*\)",
        "medium",
        "CORS 允許任意來源／方法／標頭；請改為明確白名單。",
        ("CWE-942",),
        languages=RUST,
    ),
    _rule(
        "builtin-rust-transmute",
        r"\b(?:std|core)::mem::transmute\b",
        "high",
        "使用 transmute 重新解釋記憶體；型別或長度不一致時會造成未定義行為。",
        ("CWE-704",),
        languages=RUST,
    ),
    _rule(
        "builtin-rust-from-raw-parts",
        r"\b(?:std|core)::slice::from_raw_parts(?:_mut)?\s*\(",
        "high",
        "從裸指標建立 slice；長度或生命週期錯誤會造成越界讀寫。",
        ("CWE-119",),
        languages=RUST,
    ),
    _rule(
        "builtin-rust-get-unchecked",
        r"\.get_unchecked(?:_mut)?\s*\(",
        "medium",
        "使用 get_unchecked 略過邊界檢查；索引錯誤會造成未定義行為。",
        ("CWE-125",),
        languages=RUST,
    ),
    _rule(
        "builtin-rust-ffi-extern",
        r'\bextern\s+"C(?:-unwind)?"\s*\{',
        "info",
        "FFI 邊界需確認 C 端記憶體配置、長度與空指標處理。",
        ("CWE-758",),
        languages=RUST,
    ),
    _rule(
        "builtin-rust-unsafe-impl",
        r"\bunsafe\s+impl\s+(?:Send|Sync)\b",
        "medium",
        "手動宣告 Send/Sync 會繞過編譯器的執行緒安全檢查，需人工確認。",
        ("CWE-758",),
        languages=RUST,
    ),
    _rule(
        "builtin-rust-path-traversal",
        r"\bNamedFile::open\s*\(",
        "medium",
        "以使用者可控路徑開啟檔案可能造成路徑穿越；請驗證並限制在允許目錄內。",
        ("CWE-22",),
        languages=RUST,
    ),
    _rule(
        "builtin-rust-open-redirect",
        r"\bRedirect::(?:to|temporary|permanent)\s*\(",
        "info",
        "重新導向目標若來自使用者輸入，可能造成 open redirect。",
        ("CWE-601",),
        languages=RUST,
    ),
    _rule(
        "builtin-rust-deserialize",
        r"\b(?:serde_json::from_str|bincode::deserialize)\s*\(",
        "info",
        "反序列化外部輸入需確認格式與大小限制，避免資源耗盡或型別混淆。",
        ("CWE-502",),
        languages=RUST,
    ),
    # ---------------- 跨語言：機密資訊 ----------------
    _rule(
        "builtin-private-key",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
        "critical",
        "原始碼中出現私密金鑰。",
        ("CWE-798", "CWE-321"),
    ),
    _rule(
        "builtin-aws-access-key",
        r"\bAKIA[0-9A-Z]{16}\b",
        "high",
        "原始碼中出現疑似 AWS Access Key ID。",
        ("CWE-798",),
    ),
    _rule(
        "builtin-google-api-key",
        r"\bAIza[0-9A-Za-z\-_]{35}\b",
        "high",
        "原始碼中出現疑似 Google API Key。",
        ("CWE-798",),
    ),
    _rule(
        "builtin-slack-token",
        r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b",
        "high",
        "原始碼中出現疑似 Slack token。",
        ("CWE-798",),
    ),
    _rule(
        "builtin-url-credentials",
        r"https?://[^/\s:@]+:[^/\s@]+@",
        "high",
        "URL 中直接內嵌帳號密碼。",
        ("CWE-798", "CWE-522"),
    ),
    _rule(
        "builtin-hardcoded-secret",
        r"""(?ix)
        \b(?: api[_-]?key | apikey | secret(?:[_-]?key)? | password | passwd | pwd |
              access[_-]?token | auth[_-]?token )\b
        \s*[:=]\s*
        (?P<quote>["']) (?P<value>[^"'\n]{8,}) (?P=quote)
        """,
        "medium",
        "疑似硬編碼的密碼／金鑰，請改用環境變數或密鑰管理服務。",
        ("CWE-798",),
        allow=_SECRET_ALLOW,
    ),
)


def _rules_for(path: Path) -> list[RegexRule]:
    lower_name = path.name.lower()
    if lower_name.endswith((".min.js", ".min.css")):
        return []
    language = LANG_BY_EXT.get(path.suffix.lower())
    return [
        rule
        for rule in RULES
        if rule.languages is None or (language is not None and language in rule.languages)
    ]


def _iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDE_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.is_symlink():
                continue
            if path.suffix.lower() in SKIP_EXTENSIONS:
                continue
            yield path


class RegexEngine(Engine):
    name = "builtin-regex"
    description = "內建 regex 規則（無需外部工具，誤報率較高）"

    def available(self) -> bool:
        return True

    def version(self) -> str | None:
        return "builtin-2026.11"

    def scan(self, root: Path, timeout: int) -> EngineResult:
        settings = get_settings()
        max_file_bytes = settings.max_file_bytes
        started = time.monotonic()
        findings: list[Finding] = []
        errors: list[str] = []
        files_scanned = 0
        seen: set[tuple[str, str, int | None]] = set()
        timed_out = False

        for path in _iter_files(root):
            if time.monotonic() - started > timeout:
                timed_out = True
                break
            try:
                if path.stat().st_size > max_file_bytes:
                    continue
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if not text or "\x00" in text[:4096]:
                continue
            rules = _rules_for(path)
            if not rules:
                continue

            files_scanned += 1
            rel_path = str(path.relative_to(root)).replace(os.sep, "/")
            lines = text.splitlines()

            for rule in rules:
                matches = 0
                for match in rule.regex.finditer(text):
                    line_no = text.count("\n", 0, match.start()) + 1
                    line_text = lines[line_no - 1].strip() if line_no - 1 < len(lines) else ""
                    if rule.allow and rule.allow.search(match.group(0)):
                        continue
                    key = (rule.id, rel_path, line_no)
                    if key in seen:
                        continue
                    seen.add(key)

                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            severity=normalize_severity(rule.severity),
                            message=rule.message,
                            file=rel_path,
                            line=line_no,
                            end_line=line_no,
                            column=match.start() - text.rfind("\n", 0, match.start()),
                            cwe=list(rule.cwe),
                            engine=self.name,
                            snippet=line_text[:MAX_SNIPPET] or None,
                        )
                    )
                    matches += 1
                    if matches >= MAX_MATCHES_PER_RULE_PER_FILE:
                        break

        if timed_out:
            errors.append(f"掃描逾時（{timeout} 秒），結果可能不完整")

        return EngineResult(findings=findings, files_scanned=files_scanned, errors=errors)
