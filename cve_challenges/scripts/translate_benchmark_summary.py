#!/usr/bin/env python3
"""Translate BENCHMARK_SUMMARY.md to Chinese, preserving technical terms.

Workflow:
  1. python benchmarks/cve_challenges/scripts/build_benchmark_summary.py
  2. pip install deep-translator
  3. python benchmarks/cve_challenges/scripts/translate_benchmark_summary.py

Output: benchmarks/BENCHMARK_SUMMARY.zh.md (English source unchanged)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path

try:
    from deep_translator import GoogleTranslator
except ImportError:
    GoogleTranslator = None  # type: ignore

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
DEFAULT_INPUT = REPO_ROOT / "BENCHMARK_SUMMARY.md"
DEFAULT_OUTPUT = REPO_ROOT / "BENCHMARK_SUMMARY.zh.md"
DEFAULT_CACHE = SCRIPT_DIR / ".benchmark_summary_translate_cache.json"

HEADING_MAP = {
    "Overview": "概览",
    "Attack Path": "攻击路径",
    "Attack Path Summary": "攻击路径概要",
    "Step-by-Step": "分步操作",
    "Step-by-Step Exploitation": "分步利用",
    "Flag Location": "Flag 位置",
    "Prerequisites": "前置条件",
    "Knowledge": "知识要求",
    "Tools": "工具",
    "Verification": "验证",
    "Verification Commands": "验证命令",
    "Property": "属性",
    "Value": "值",
    "Difficulty": "难度",
    "Port": "端口",
    "Path": "路径",
    "Image": "镜像",
    "Plugin": "插件",
    "Step": "步骤",
}

# Terms kept verbatim (sorted longest-first at runtime).
GLOSSARY_TERMS = [
    "PersistentManager FileStore",
    "commons-collections",
    "SecretsManager",
    "CloudFormation",
    "AssumeRole",
    "Kerberoasting",
    "DCSync",
    "Golden Ticket",
    "Silver Ticket",
    "Shadow Credentials",
    "Pass-the-Hash",
    "Unconstrained Delegation",
    "Constrained Delegation",
    "AdminSDHolder",
    "ForceChangePassword",
    "KeyCredentialLink",
    "IngressNightmare",
    "NetworkPolicy",
    "Mutating Webhook",
    "Admission Controller",
    "Service Account",
    "DaemonSet",
    "ExternalIP",
    "hostPath",
    "hostPID",
    "seccomp",
    "kubelet",
    "etcd",
    "Helm",
    "Tiller",
    "runC",
    "CAP_SYS_ADMIN",
    "CAP_SYS_PTRACE",
    "LD_PRELOAD",
    "xp_cmdshell",
    "INTO DUMPFILE",
    "UNION-based",
    "NoSQL",
    "WordPress",
    "PostgreSQL",
    "Elasticsearch",
    "DynamoDB",
    "Active Directory",
    "Samba AD",
    "ATT&CK",
    "webshell",
    "deserialization",
    "ysoserial",
    "JSESSIONID",
    "Content-Range",
    "admin-ajax",
    "image_upload_handle",
    "simple-file-list",
    "wpbookit",
    "Jinja2",
    "GraphQL",
    "MongoDB",
    "Redis",
    "MySQL",
    "MSSQL",
    "Oracle",
    "CouchDB",
    "Tomcat",
    "Apache",
    "Docker",
    "Kubernetes",
    "KIND",
    "kubectl",
    "nmap",
    "impacket",
    "bloodhound",
    "mimikatz",
    "crackmapexec",
    "secretsdump",
    "GetNPUsers",
    "GetUserSPNs",
    "Rubeus",
    "PowerView",
    "certipy",
    "ldapsearch",
    "enum4linux",
    "responder",
    "hashcat",
    "john",
    "hydra",
    "sqlmap",
    "burp",
    "curl",
    "wget",
    "nc",
    "netcat",
    "python3",
    "bash",
    "powershell",
    "cmdi",
    "SQLi",
    "SSRF",
    "SSTI",
    "XXE",
    "XSS",
    "LFI",
    "RFI",
    "RCE",
    "RBAC",
    "IAM",
    "STS",
    "KMS",
    "SQS",
    "Lambda",
    "EC2",
    "S3",
    "SSM",
    "IMDS",
    "CVSS",
    "CVE",
    "RBCD",
    "GPP",
    "AS-REP",
    "Kerberos",
    "NTLM",
    "LDAP",
    "DNS",
    "HTTP",
    "HTTPS",
    "TCP",
    "UDP",
    "JWT",
    "PHP",
    "JSP",
    "ASP.NET",
    "JSON",
    "XML",
    "YAML",
    "API",
    "UDF",
    "TNS",
    "WAF",
    "LoTL",
    "BIG5",
    "ProcFS",
    "CNI",
    "CRI",
    "gitRepo",
]

PROTECT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("inline_code", re.compile(r"`[^`\n]+`")),
    ("html_comment", re.compile(r"<!--.*?-->", re.DOTALL)),
    ("html_anchor", re.compile(r'<a\s+id="[^"]+"\s*/?>')),
    ("flag", re.compile(r"flag\{[^}]+\}")),
    ("cve", re.compile(r"CVE-\d{4}-\d+")),
    ("cvss", re.compile(r"CVSS\s+[\d.]+")),
    ("attack", re.compile(r"T\d{4}(?:\.\d{3})?")),
    ("scenario_id", re.compile(r"\b(?:WEB|DB|LNX|CLOUD|DEF|NET|CI|LKX|K8S|AD)-\d{2}\b")),
    ("url", re.compile(r"https?://[^\s)\]`>]+")),
    ("localhost", re.compile(r"localhost(?::\d+)?(?:/[^\s)\]`>]*)?")),
    ("docker_image", re.compile(r"\b[\w.-]+:\d[\w.-]*(?:-[\w.-]+)*\b")),
    ("file_path", re.compile(r"(?<![\w./])(?:/[A-Za-z0-9_./-]+)+")),
    ("backtick_path", re.compile(r"`(?:[A-Za-z0-9_./-]+(?:/[A-Za-z0-9_./-]+)*)`")),
    ("port_num", re.compile(r"\b(?:10\d{3}|104\d{2}|107\d{2}|106\d{2}|102\d{2}|108\d{2})\b")),
    ("chain_id", re.compile(r"chain\d+(?:-step\d+)?(?:-[a-z]+)?")),
    ("level", re.compile(r"\bL[1-3]\b")),
    ("version", re.compile(r"\b\d+\.\d+(?:\.\d+)*\b")),
]

ZH_HEADER = (
    "> **中文版**：由 translate_benchmark_summary.py 自动生成，专用名词（CVE、工具名、命令等）保持原文。\n"
    "> **更新**：先运行 build_benchmark_summary.py 重建英文版，再运行 translate_benchmark_summary.py。\n"
)

FENCE_RE = re.compile(r"^(```+)(\s*(\w[\w-]*)?\s*)$")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+)$")
TABLE_SEP_RE = re.compile(r"^\|[-:\s|]+\|$")
SCENARIO_TITLE_RE = re.compile(
    r"^(#{2,6})\s+((?:WEB|DB|LNX|CLOUD|DEF|NET|CI|LKX|K8S|AD)-\d{2}:\s*)(.+)$"
)
MAX_CHUNK = 4500
REQUEST_DELAY = 0.4


def cjk_ratio(text: str) -> float:
    if not text.strip():
        return 0.0
    cjk = sum(1 for c in text if "\u4e00" <= c <= "\u9fff")
    letters = sum(1 for c in text if c.isalpha() or "\u4e00" <= c <= "\u9fff")
    if letters == 0:
        return 0.0
    return cjk / letters


def should_skip_translation(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return True
    if stripped.startswith("<!--") or stripped.startswith("<a id="):
        return True
    if cjk_ratio(stripped) > 0.4:
        return True
    if not re.search(r"[A-Za-z]{3,}", stripped):
        return True
    return False


class TokenProtector:
    def __init__(self) -> None:
        self._tokens: dict[str, str] = {}
        self._counter = 0

    def _placeholder(self) -> str:
        self._counter += 1
        return f"⟦T{self._counter:04d}⟧"

    def protect(self, text: str) -> str:
        self._tokens.clear()
        self._counter = 0
        protected = text

        # Glossary terms (longest first).
        for term in sorted(GLOSSARY_TERMS, key=len, reverse=True):
            if term in protected:
                ph = self._placeholder()
                self._tokens[ph] = term
                protected = protected.replace(term, ph)

        # Regex patterns.
        for _name, pattern in PROTECT_PATTERNS:
            def repl(m: re.Match[str], _ph_fn=self._placeholder, _tok=self._tokens) -> str:
                ph = _ph_fn()
                _tok[ph] = m.group(0)
                return ph

            protected = pattern.sub(repl, protected)

        return protected

    def restore(self, text: str) -> str:
        result = text
        for ph, original in self._tokens.items():
            result = result.replace(ph, original)
        return result


class TranslateCache:
    def __init__(self, path: Path, force: bool = False) -> None:
        self.path = path
        self.force = force
        self._data: dict[str, str] = {}
        if path.exists() and not force:
            try:
                self._data = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._data = {}

    def get(self, text: str) -> str | None:
        if self.force:
            return None
        key = hashlib.sha256(text.encode("utf-8")).hexdigest()
        return self._data.get(key)

    def set(self, original: str, translated: str) -> None:
        key = hashlib.sha256(original.encode("utf-8")).hexdigest()
        self._data[key] = translated

    def save(self) -> None:
        self.path.write_text(
            json.dumps(self._data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )


class Translator:
    def __init__(
        self,
        cache: TranslateCache,
        dry_run: bool = False,
        max_chunks: int | None = None,
    ) -> None:
        self.cache = cache
        self.dry_run = dry_run
        self.max_chunks = max_chunks
        self.protector = TokenProtector()
        self.chunks_translated = 0
        self.chunks_cached = 0
        self.chunks_skipped = 0
        self._engine = GoogleTranslator(source="auto", target="zh-CN") if GoogleTranslator else None

    def translate_text(self, text: str) -> str:
        if should_skip_translation(text):
            self.chunks_skipped += 1
            return text

        cached = self.cache.get(text)
        if cached is not None:
            self.chunks_cached += 1
            return cached

        if self.max_chunks is not None and self.chunks_translated >= self.max_chunks:
            return text

        if self.dry_run:
            self.chunks_translated += 1
            return text

        protected = self.protector.protect(text)
        translated = self._call_api(protected)
        restored = self.protector.restore(translated)

        self.cache.set(text, restored)
        self.chunks_translated += 1
        time.sleep(REQUEST_DELAY)
        return restored

    def _call_api(self, text: str) -> str:
        if self._engine is None:
            raise SystemExit("deep-translator required: pip install deep-translator")

        if len(text) <= MAX_CHUNK:
            return self._translate_with_retry(text)

        parts: list[str] = []
        current = ""
        for line in text.splitlines(keepends=True):
            if len(current) + len(line) > MAX_CHUNK and current:
                parts.append(current)
                current = line
            else:
                current += line
        if current:
            parts.append(current)

        return "".join(self._translate_with_retry(p) for p in parts)

    def _translate_with_retry(self, text: str, retries: int = 3) -> str:
        last_err: Exception | None = None
        for attempt in range(retries):
            try:
                return self._engine.translate(text)
            except Exception as exc:
                last_err = exc
                time.sleep(2 ** attempt)
        raise RuntimeError(f"Translation failed after {retries} retries: {last_err}") from last_err


def apply_heading_map(line: str) -> str:
    m = HEADING_RE.match(line)
    if not m:
        return line
    hashes, title = m.group(1), m.group(2).strip()
    if title in HEADING_MAP:
        return f"{hashes} {HEADING_MAP[title]}"
    return line


def translate_scenario_title(line: str, translator: Translator) -> str:
    m = SCENARIO_TITLE_RE.match(line)
    if not m:
        return line
    hashes, prefix, rest = m.group(1), m.group(2), m.group(3)
    # Split trailing (CVE-...) parenthetical from description.
    cve_match = re.search(r"\s*(\([^)]+\))\s*$", rest)
    if cve_match:
        desc = rest[: cve_match.start()].strip()
        suffix = rest[cve_match.start() :]
    else:
        desc = rest
        suffix = ""
    if should_skip_translation(desc):
        return line
    translated_desc = translator.translate_text(desc)
    return f"{hashes} {prefix}{translated_desc}{suffix}"


def translate_table_row(line: str, translator: Translator, is_header: bool) -> str:
    if not line.strip().startswith("|"):
        return line
    cells = [c.strip() for c in line.strip().strip("|").split("|")]
    out_cells = []
    for cell in cells:
        if is_header and cell in HEADING_MAP:
            out_cells.append(HEADING_MAP[cell])
        elif should_skip_translation(cell):
            out_cells.append(cell)
        else:
            out_cells.append(translator.translate_text(cell))
    return "| " + " | ".join(out_cells) + " |"


def translate_markdown(content: str, translator: Translator) -> str:
    lines = content.splitlines()
    out: list[str] = []
    in_fence = False
    fence_lang = ""
    i = 0

    while i < len(lines):
        line = lines[i]
        fence_m = FENCE_RE.match(line)

        if fence_m and not in_fence:
            in_fence = True
            fence_lang = (fence_m.group(3) or "").lower()
            out.append(line)
            i += 1
            continue

        if fence_m and in_fence:
            in_fence = False
            fence_lang = ""
            out.append(line)
            i += 1
            continue

        if in_fence:
            if fence_lang in ("bash", "sh", "shell", "python", "py", "powershell", "sql", "yaml", "json"):
                if line.startswith("## ") and re.search(r"[A-Za-z]{3,}", line):
                    comment = line[3:]
                    translated = translator.translate_text(comment)
                    out.append(f"## {translated}")
                else:
                    out.append(line)
            else:
                # Plain fence (attack path diagrams) — translate whole block.
                block_lines = [line]
                i += 1
                while i < len(lines):
                    if FENCE_RE.match(lines[i]):
                        break
                    block_lines.append(lines[i])
                    i += 1
                block_text = "\n".join(block_lines)
                if should_skip_translation(block_text):
                    out.extend(block_lines)
                else:
                    translated = translator.translate_text(block_text)
                    out.extend(translated.splitlines())
                continue
            i += 1
            continue

        # Outside fences.
        if line.strip().startswith("<!--") or line.strip().startswith("<a id="):
            out.append(line)
            i += 1
            continue

        scenario = SCENARIO_TITLE_RE.match(line)
        if scenario:
            out.append(translate_scenario_title(line, translator))
            i += 1
            continue

        heading = HEADING_RE.match(line)
        if heading and heading.group(2).strip() in HEADING_MAP:
            out.append(apply_heading_map(line))
            i += 1
            continue

        if line.strip().startswith("|"):
            is_sep = TABLE_SEP_RE.match(line.strip()) is not None
            if is_sep:
                out.append(line)
            else:
                is_header = (
                    i + 1 < len(lines)
                    and TABLE_SEP_RE.match(lines[i + 1].strip()) is not None
                )
                out.append(translate_table_row(line, translator, is_header=is_header))
            i += 1
            continue

        if line.strip().startswith("- ") or line.strip().startswith("* "):
            prefix = line[: len(line) - len(line.lstrip())]
            marker = line.lstrip()[:2]
            body = line.lstrip()[2:]
            if should_skip_translation(body):
                out.append(line)
            else:
                out.append(f"{prefix}{marker}{translator.translate_text(body)}")
            i += 1
            continue

        if should_skip_translation(line):
            out.append(line)
        else:
            out.append(translator.translate_text(line))
        i += 1

    return "\n".join(out)


def build_output(content: str, translator: Translator) -> str:
    translated = translate_markdown(content, translator)
    # Prepend Chinese header after first title block if not already present.
    if "**中文版**" not in translated[:500]:
        lines = translated.splitlines()
        insert_at = 1
        for idx, ln in enumerate(lines[:10]):
            if ln.startswith("> **范围**"):
                insert_at = idx + 1
        header_lines = ZH_HEADER.rstrip().splitlines()
        for offset, hl in enumerate(header_lines):
            lines.insert(insert_at + offset, hl)
        translated = "\n".join(lines)
    return translated.rstrip() + "\n"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Translate BENCHMARK_SUMMARY.md to Chinese.")
    p.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="Input markdown file")
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Output Chinese markdown")
    p.add_argument("--cache", type=Path, default=DEFAULT_CACHE, help="Translation cache JSON")
    p.add_argument("--force", action="store_true", help="Ignore cache and re-translate")
    p.add_argument("--dry-run", action="store_true", help="Count translatable segments only")
    p.add_argument("--max-chunks", type=int, default=None, help="Limit API calls (debug)")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    if not args.input.exists():
        raise SystemExit(f"Input not found: {args.input}")

    content = args.input.read_text(encoding="utf-8")
    cache = TranslateCache(args.cache, force=args.force)
    translator = Translator(cache, dry_run=args.dry_run, max_chunks=args.max_chunks)

    if args.dry_run:
        translate_markdown(content, translator)
        print(f"Dry run complete for {args.input}")
        print(f"  Segments to translate: {translator.chunks_translated}")
        print(f"  Segments skipped:      {translator.chunks_skipped}")
        print(f"  Cache hits:            {translator.chunks_cached}")
        return

    output = build_output(content, translator)
    args.output.write_text(output, encoding="utf-8")
    cache.save()

    src_lines = len(content.splitlines())
    out_lines = len(output.splitlines())
    print(f"Wrote {args.output}")
    print(f"  Lines: {out_lines} (source: {src_lines})")
    print(f"  Translated chunks: {translator.chunks_translated}")
    print(f"  Cache hits:        {translator.chunks_cached}")
    print(f"  Skipped:           {translator.chunks_skipped}")


if __name__ == "__main__":
    main()
