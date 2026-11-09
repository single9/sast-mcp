"""C#、C/C++、Node.js 規則的迴歸測試。"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from app.engines.regex_engine import RegexEngine

C_SAMPLE = """
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void bad(char *user, char *buf) {
    gets(user);
    strcpy(buf, user);
    system(user);
    printf(user);
    tmpnam(buf);
    MD5_Init(NULL);
    chmod(user, 0777);
    scanf("%s", buf);
}
"""

CSHARP_SAMPLE = """
using System.Data.SqlClient;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Runtime.Serialization.Formatters.Binary;
using System.Xml;

class V {
    void F(string user, string conn, System.IO.Stream stream) {
        var cmd = new SqlCommand("SELECT * FROM t WHERE name='" + user + "'", new SqlConnection(conn));
        var cmd2 = new SqlCommand(string.Format("SELECT * FROM t WHERE name='{0}'", user), new SqlConnection(conn));
        Process.Start(user);
        new BinaryFormatter().Deserialize(stream);
        MD5.Create();
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse };
        var cookie = new HttpCookie("x") { Secure = false };
        var ds = new DirectorySearcher("(uid=" + user + ")");
        var policy = new CorsPolicyBuilder().AllowAnyOrigin().Build();
        string cs = "Server=.;Database=x;User Id=sa;Password=SuperSecret123;";
    }

    [ValidateInput(false)]
    public string X(string q) { return q; }
}
"""

NODE_SAMPLE = """
const cp = require('child_process');
const vm = require('vm');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

function bad(user, token, secret) {
  cp.spawn('ls', [user], { shell: true });
  vm.runInNewContext(user, {});
  crypto.createHash('md5').update(user).digest('hex');
  crypto.createCipher('des', secret);
  jwt.verify(token, secret, { algorithms: ['none'] });
  db.query("SELECT * FROM t WHERE id=" + user);
}
"""


def _find_semgrep() -> str | None:
    found = shutil.which("semgrep")
    if found:
        return found
    candidate = Path(__file__).resolve().parents[1] / ".venv" / "bin" / "semgrep"
    return str(candidate) if candidate.exists() else None


def test_regex_engine_covers_csharp_c_cpp_and_node(tmp_path):
    (tmp_path / "bad.c").write_text(C_SAMPLE, encoding="utf-8")
    (tmp_path / "bad.cs").write_text(CSHARP_SAMPLE, encoding="utf-8")
    (tmp_path / "bad.js").write_text(NODE_SAMPLE, encoding="utf-8")

    result = RegexEngine().scan(tmp_path, timeout=30)
    rule_ids = {finding.rule_id for finding in result.findings}

    assert {
        "builtin-cpp-gets",
        "builtin-cpp-command-exec",
        "builtin-cpp-unsafe-string-functions",
        "builtin-csharp-sql-injection",
        "builtin-csharp-binary-formatter",
        "builtin-csharp-xxe",
        "builtin-node-vm-exec",
        "builtin-node-weak-hash",
        "builtin-node-jwt-none",
    } <= rule_ids


def test_regex_engine_ignores_safe_csharp_c_cpp_and_node(tmp_path):
    (tmp_path / "good.c").write_text(
        '#include <stdio.h>\n#include <string.h>\n'
        'void good(char *user, char *buf, size_t n) {\n'
        '    strncpy(buf, user, n - 1);\n'
        '    snprintf(buf, n, "%s", user);\n'
        '    printf("%s", user);\n'
        '    chmod(user, 0644);\n'
        '}\n',
        encoding="utf-8",
    )
    (tmp_path / "good.cs").write_text(
        'using System.Data.SqlClient;\n'
        'class Good {\n'
        '    void F(string user, string conn) {\n'
        '        var cmd = new SqlCommand("SELECT * FROM t WHERE name=@name", new SqlConnection(conn));\n'
        '        cmd.Parameters.AddWithValue("@name", user);\n'
        '        var sha = SHA256.Create();\n'
        '        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit };\n'
        '    }\n'
        '}\n',
        encoding="utf-8",
    )
    (tmp_path / "good.js").write_text(
        "const crypto = require('crypto');\n"
        "const cp = require('child_process');\n"
        "const jwt = require('jsonwebtoken');\n"
        "function good(user, token, secret) {\n"
        "  crypto.createHash('sha256').update(user).digest('hex');\n"
        "  cp.spawn('ls', [user]);\n"
        "  jwt.verify(token, secret, { algorithms: ['HS256'] });\n"
        "  db.query('SELECT * FROM t WHERE id = ?', [user]);\n"
        "}\n",
        encoding="utf-8",
    )

    result = RegexEngine().scan(tmp_path, timeout=30)
    assert result.findings == []


def test_builtin_csharp_c_cpp_and_node_rules_with_semgrep(monkeypatch, tmp_path):
    from app.config import reset_settings_cache

    semgrep = _find_semgrep()
    if not semgrep:
        pytest.skip("semgrep 未安裝")

    (tmp_path / "bad.c").write_text(C_SAMPLE, encoding="utf-8")
    (tmp_path / "bad.cs").write_text(CSHARP_SAMPLE, encoding="utf-8")
    (tmp_path / "bad.js").write_text(NODE_SAMPLE, encoding="utf-8")

    monkeypatch.setenv("SAST_SEMGREP_BIN", semgrep)
    reset_settings_cache()
    try:
        from app.engines.semgrep_engine import SemgrepEngine

        result = SemgrepEngine().scan(tmp_path, timeout=60)
    finally:
        reset_settings_cache()

    rule_ids = {finding.rule_id for finding in result.findings}
    assert {
        "cpp-gets",
        "cpp-unsafe-string-functions",
        "cpp-command-exec",
        "cpp-format-string",
        "cpp-permissive-file-mode",
        "csharp-sql-injection",
        "csharp-command-injection",
        "csharp-binary-formatter",
        "csharp-weak-hash",
        "csharp-xxe",
        "csharp-insecure-cookie",
        "csharp-ldap-injection",
        "csharp-cors-allow-any",
        "node-vm-code-exec",
        "node-weak-hash",
        "node-spawn-shell",
        "node-weak-cipher",
        "node-jwt-none",
        "node-sql-concat",
    } <= rule_ids
