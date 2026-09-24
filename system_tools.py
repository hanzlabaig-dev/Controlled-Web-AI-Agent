"""
system_tools.py — Local capabilities: terminal, workspace files, memory.

TERMINAL (run_command)
  * Every command is shown to a human and needs y/N. No exceptions, unless you
    set AUTO_APPROVE_SAFE_COMMANDS=true, which only skips the prompt for a tiny
    read-only allow-list with no pipes / redirects / chaining.
  * A hard deny-list refuses obviously destructive or stealthy commands even
    if a human would say yes (approval fatigue is real).
  * Runs in WORKSPACE_DIR, with a timeout, capped output, and a scrubbed
    environment (your LLM/search API keys are NOT visible to the child).
  * PowerShell is the default shell on Windows; bash elsewhere.
  HONEST LIMIT: the deny-list is a seatbelt, not a sandbox. The human
  approval prompt is the real control — read every command before pressing y.

FILES (read_file, write_file, replace_in_file, list_dir, search_in_files)
  * Confined to WORKSPACE_DIR (realpath-checked, symlink escapes rejected).
  * .env files, private keys and similar secret files are never readable/writable.

MEMORY (remember, recall, forget)
  * Small JSON notes file so the agent keeps facts between runs.
"""

import fnmatch
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
from datetime import datetime, timezone

import config
import logger

# ---------------------------------------------------------------------------
# Human approval
# ---------------------------------------------------------------------------


def _ask_human(banner_lines: list, question: str) -> bool:
    print("\n" + "=" * 64)
    for line in banner_lines:
        print(f" {line}")
    print("=" * 64)
    try:
        return input(f"{question} [y/N]: ").strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


# ---------------------------------------------------------------------------
# Workspace helpers
# ---------------------------------------------------------------------------

_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".idea", ".vscode", "dist", "build"}
_SECRET_NAME_PATTERNS = (".env", ".env.*", "*.pem", "*.key", "*.pfx", "*.p12", "id_rsa*", "id_ed25519*",
                         ".npmrc", ".netrc", "credentials*", "*.kdbx")


def _workspace_root() -> str:
    root = os.path.realpath(config.WORKSPACE_DIR)
    os.makedirs(root, exist_ok=True)
    return root


def _is_secret_name(path: str) -> bool:
    base = os.path.basename(path).lower()
    return any(fnmatch.fnmatch(base, pat) for pat in _SECRET_NAME_PATTERNS)


def _resolve(rel_path: str, *, allow_missing: bool = True) -> str:
    """Resolve a workspace-relative path to an absolute one, or raise ValueError."""
    if not isinstance(rel_path, str) or not rel_path.strip():
        raise ValueError("path must be a non-empty string.")
    root = _workspace_root()
    candidate = os.path.realpath(os.path.join(root, rel_path.strip()))  # absolute paths are re-checked below
    try:
        inside = os.path.commonpath([os.path.normcase(root), os.path.normcase(candidate)]) == os.path.normcase(root)
    except ValueError:  # different drives on Windows
        inside = False
    if not inside:
        raise ValueError(f"Path escapes the workspace ({root}).")
    if _is_secret_name(candidate):
        raise ValueError("Secret-looking files (.env, keys, credentials) are off limits.")
    if not allow_missing and not os.path.exists(candidate):
        raise ValueError(f"Not found: {rel_path}")
    return candidate


def _looks_binary(sample: bytes) -> bool:
    return b"\x00" in sample


# ---------------------------------------------------------------------------
# File tools
# ---------------------------------------------------------------------------

def tool_read_file(path: str, start_line: int = 1, max_lines: int = 400) -> dict:
    try:
        full = _resolve(path, allow_missing=False)
    except ValueError as e:
        return {"error": f"BLOCKED: {e}"}
    if os.path.isdir(full):
        return {"error": "That is a directory — use list_dir."}
    try:
        size = os.path.getsize(full)
        with open(full, "rb") as f:
            raw = f.read(config.MAX_FILE_READ_BYTES + 1)
    except OSError as e:
        return {"error": f"Could not read file: {e}"}
    if _looks_binary(raw[:4096]):
        return {"error": "Binary file — not readable as text."}
    byte_truncated = len(raw) > config.MAX_FILE_READ_BYTES
    text = raw[:config.MAX_FILE_READ_BYTES].decode("utf-8", errors="replace")
    lines = text.splitlines()
    try:
        start = max(1, int(start_line))
        count = max(1, min(int(max_lines), 2000))
    except (TypeError, ValueError):
        start, count = 1, 400
    chunk = lines[start - 1:start - 1 + count]
    logger.log_event({"tool": "read_file", "path": path})
    return {
        "path": path,
        "size_bytes": size,
        "start_line": start,
        "end_line": start - 1 + len(chunk),
        "total_lines_in_loaded_text": len(lines),
        "truncated": byte_truncated or (start - 1 + count) < len(lines),
        "content": "\n".join(chunk),
    }


def tool_write_file(path: str, content: str, mode: str = "overwrite") -> dict:
    if not isinstance(content, str):
        return {"error": "content must be a string."}
    if mode not in ("overwrite", "append"):
        return {"error": "mode must be 'overwrite' or 'append'."}
    if len(content.encode("utf-8")) > config.MAX_FILE_WRITE_BYTES:
        return {"error": f"Content exceeds {config.MAX_FILE_WRITE_BYTES} bytes."}
    try:
        full = _resolve(path)
    except ValueError as e:
        return {"error": f"BLOCKED: {e}"}
    if os.path.isdir(full):
        return {"error": "That path is a directory."}

    existed = os.path.exists(full)
    if config.CONFIRM_FILE_WRITES:
        ok = _ask_human([f"write_file ({mode})", f"Path: {full}", f"Bytes: {len(content.encode('utf-8'))}",
                         "Exists: " + ("yes — will be modified" if existed else "no — will be created")],
                        "Allow this write?")
        if not ok:
            return {"error": "write_file was rejected by the human operator."}
    try:
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "a" if mode == "append" else "w", encoding="utf-8", newline="") as f:
            f.write(content)
    except OSError as e:
        return {"error": f"Could not write file: {e}"}
    logger.log_event({"tool": "write_file", "path": full, "mode": mode, "bytes": len(content)})
    return {"result": "written", "path": path, "mode": mode, "bytes": len(content.encode("utf-8")), "overwrote_existing": existed and mode == "overwrite"}


def tool_replace_in_file(path: str, old: str, new: str) -> dict:
    if not isinstance(old, str) or not old:
        return {"error": "old must be a non-empty string."}
    if not isinstance(new, str):
        return {"error": "new must be a string."}
    try:
        full = _resolve(path, allow_missing=False)
    except ValueError as e:
        return {"error": f"BLOCKED: {e}"}
    try:
        with open(full, "r", encoding="utf-8", newline="") as f:
            text = f.read()
    except (OSError, UnicodeDecodeError) as e:
        return {"error": f"Could not read file as UTF-8 text: {e}"}
    count = text.count(old)
    if count == 0:
        return {"error": "old text not found (must match exactly, including whitespace)."}
    if count > 1:
        return {"error": f"old text matches {count} places — include more surrounding text so it is unique."}
    if config.CONFIRM_FILE_WRITES and not _ask_human(
        ["replace_in_file", f"Path: {full}", f"Remove: {old[:200]!r}", f"Insert: {new[:200]!r}"], "Allow this edit?"
    ):
        return {"error": "replace_in_file was rejected by the human operator."}
    updated = text.replace(old, new, 1)
    if len(updated.encode("utf-8")) > config.MAX_FILE_WRITE_BYTES:
        return {"error": f"Result would exceed {config.MAX_FILE_WRITE_BYTES} bytes."}
    try:
        with open(full, "w", encoding="utf-8", newline="") as f:
            f.write(updated)
    except OSError as e:
        return {"error": f"Could not write file: {e}"}
    logger.log_event({"tool": "replace_in_file", "path": full})
    return {"result": "replaced", "path": path}


def tool_list_dir(path: str = ".", recursive: bool = False, max_entries: int = 200) -> dict:
    try:
        full = _resolve(path or ".", allow_missing=False)
    except ValueError as e:
        return {"error": f"BLOCKED: {e}"}
    if not os.path.isdir(full):
        return {"error": "Not a directory."}
    try:
        limit = max(1, min(int(max_entries), 1000))
    except (TypeError, ValueError):
        limit = 200
    root = _workspace_root()
    entries, truncated = [], False
    for dirpath, dirnames, filenames in os.walk(full):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        for name in dirnames + sorted(filenames):
            p = os.path.join(dirpath, name)
            if _is_secret_name(p):
                continue
            is_dir = os.path.isdir(p)
            entries.append({
                "path": os.path.relpath(p, root).replace(os.sep, "/"),
                "type": "dir" if is_dir else "file",
                "size": None if is_dir else (os.path.getsize(p) if os.path.exists(p) else None),
            })
            if len(entries) >= limit:
                truncated = True
                break
        if truncated or not recursive:
            break
    return {"path": path, "entries": entries, "truncated": truncated}


def tool_search_in_files(query: str, path: str = ".", is_regex: bool = False,
                         file_glob: str = "*", max_results: int = 50) -> dict:
    if not isinstance(query, str) or not query:
        return {"error": "query must be a non-empty string."}
    try:
        base = _resolve(path or ".", allow_missing=False)
    except ValueError as e:
        return {"error": f"BLOCKED: {e}"}
    try:
        pattern = re.compile(query if is_regex else re.escape(query), re.IGNORECASE)
    except re.error as e:
        return {"error": f"Invalid regex: {e}"}
    try:
        limit = max(1, min(int(max_results), 200))
    except (TypeError, ValueError):
        limit = 50
    root = _workspace_root()
    matches, files_scanned, truncated = [], 0, False
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            p = os.path.join(dirpath, name)
            if not fnmatch.fnmatch(name, file_glob or "*") or _is_secret_name(p):
                continue
            try:
                if os.path.getsize(p) > config.MAX_FILE_READ_BYTES:
                    continue
                with open(p, "rb") as f:
                    raw = f.read()
            except OSError:
                continue
            if _looks_binary(raw[:4096]):
                continue
            files_scanned += 1
            for i, line in enumerate(raw.decode("utf-8", errors="replace").splitlines(), 1):
                if pattern.search(line):
                    matches.append({"file": os.path.relpath(p, root).replace(os.sep, "/"),
                                    "line": i, "text": line.strip()[:200]})
                    if len(matches) >= limit:
                        truncated = True
                        break
            if truncated:
                break
        if truncated:
            break
    return {"query": query, "files_scanned": files_scanned, "matches": matches, "truncated": truncated}


# ---------------------------------------------------------------------------
# Terminal tool
# ---------------------------------------------------------------------------

# (regex, reason) — matched case-insensitively against the whole command string.
_DENY_PATTERNS = [
    (r"\bformat-volume\b|\bformat\s+[a-z]:|\bclear-disk\b|\binitialize-disk\b|\bremove-partition\b|\bdiskpart\b",
     "disk formatting / partition commands"),
    (r"\bmkfs(\.\w+)?\b|\bdd\s+[^|;&]*\bof=/dev/", "raw disk writes"),
    (r":\(\)\s*\{[^}]*\}\s*;\s*:", "fork bomb"),
    (r"\b(shutdown|restart-computer|stop-computer|reboot|poweroff|halt)\b", "power / reboot commands"),
    (r"\breg(\.exe)?\s+(delete|add|import)\b|\bbcdedit\b|\bvssadmin\b\s+delete|\bwevtutil\b\s+cl\b|\bcipher\b\s+/w",
     "registry / boot / log-wiping commands"),
    (r"\bnet(\.exe)?\s+user\b|\bnew-localuser\b|\badd-localgroupmember\b|\bnetsh\b\s+advfirewall|\bset-mppreference\b|\badd-mppreference\b",
     "account / firewall / antivirus tampering"),
    (r"\bset-executionpolicy\b", "execution-policy changes"),
    (r"-enc(odedcommand)?\b", "encoded PowerShell commands"),
    (r"\b(invoke-expression|iex)\b", "Invoke-Expression / iex (runs arbitrary strings)"),
    (r"\b(curl|wget|invoke-webrequest|iwr|invoke-restmethod|irm)\b[^\n]*\|\s*(sh|bash|zsh|iex|invoke-expression|powershell|pwsh)\b",
     "download-and-execute pipelines"),
    (r"\.env\b|id_rsa|id_ed25519|\.pem\b|\.npmrc|\.netrc", "access to secret files"),
    (r"\b(GEMINI|OPENROUTER|GROK|BRAVE|TAVILY|GITHUB|NVD)_(API_)?(KEY|TOKEN)\b", "reading API-key variables"),
]
_DENY_COMPILED = [(re.compile(p, re.IGNORECASE), why) for p, why in _DENY_PATTERNS]

_DELETE_VERBS = {"rm", "del", "erase", "rd", "rmdir", "remove-item", "ri"}
_RECURSIVE_FLAGS = {"-r", "-rf", "-fr", "-recurse", "/s", "-force", "-f"}
_DANGEROUS_TARGETS = {"/", "~", "*", "\\", "$home", "$env:userprofile", "$env:systemroot", "$env:windir",
                      "$env:homepath", "c:\\windows", "c:/windows", "c:\\users", "c:/users", "/etc", "/usr", "/bin",
                      "/home", "/var", "/boot", "/lib", "/opt", "/root", "/sys", "/proc", "%userprofile%", "%systemroot%"}


def _tokens(cmd: str) -> list:
    return [t.strip("\"'") for t in re.findall(r"\"[^\"]*\"|'[^']*'|\S+", cmd)]


def _destructive_delete(cmd: str):
    """Return a reason if the command recursively deletes something drive-root-ish."""
    for segment in re.split(r"[;&|\n]+", cmd):
        toks = _tokens(segment.strip())
        if not toks or toks[0].lower() not in _DELETE_VERBS:
            continue
        lowered = [t.lower() for t in toks[1:]]
        recursive = any(t in _RECURSIVE_FLAGS or (t.startswith("-") and "r" in t[1:] and not t.startswith("--")) for t in lowered)
        if not recursive:
            continue
        for t in lowered:
            norm = t.rstrip("\\/") or t
            if t in _DANGEROUS_TARGETS or norm in _DANGEROUS_TARGETS or re.fullmatch(r"[a-z]:[\\/]?\*?", t):
                return "recursive delete of a root / system / home location"
    return None


def check_command_policy(command: str):
    """Return a human-readable reason if the command is hard-blocked, else None."""
    if not isinstance(command, str) or not command.strip():
        return "empty command"
    if len(command) > 4000:
        return "command is too long (max 4000 characters)"
    for rx, why in _DENY_COMPILED:
        if rx.search(command):
            return why
    return _destructive_delete(command)


_SAFE_READONLY_FIRST = {"pwd", "get-location", "get-date", "whoami", "hostname", "echo", "write-output",
                        "ls", "dir", "get-childitem", "gci", "tree"}
_SAFE_READONLY_PAIRS = {("git", "status"), ("git", "log"), ("git", "diff"), ("git", "branch"), ("git", "--version"),
                        ("node", "--version"), ("node", "-v"), ("npm", "--version"), ("npm", "-v"),
                        ("python", "--version"), ("python3", "--version"), ("py", "--version"), ("pip", "--version"),
                        ("npm", "ls"), ("pip", "list")}


def is_safe_readonly(command: str) -> bool:
    if re.search(r"[;|&<>`$\n\r(){}]", command):
        return False
    toks = command.strip().split()
    if not toks:
        return False
    first = toks[0].lower()
    if first in _SAFE_READONLY_FIRST:
        return True
    return len(toks) >= 2 and (first, toks[1].lower()) in _SAFE_READONLY_PAIRS


def _pick_shell(requested: str):
    """Return (shell_name, argv_or_string, use_string_command) or raise RuntimeError."""
    on_windows = os.name == "nt"
    choice = (requested or config.COMMAND_SHELL or "auto").lower()
    if choice == "auto":
        choice = "powershell" if on_windows else "bash"
    if choice not in ("powershell", "cmd", "bash"):
        raise RuntimeError("shell must be one of: powershell, cmd, bash.")
    if choice == "powershell":
        order = ("powershell", "pwsh") if on_windows else ("pwsh", "powershell")
        exe = next((shutil.which(n) for n in order if shutil.which(n)), None)
        if not exe:
            raise RuntimeError("PowerShell not found on PATH (looked for powershell / pwsh).")
        return "powershell", exe
    if choice == "cmd":
        if not on_windows:
            raise RuntimeError("cmd is only available on Windows.")
        return "cmd", shutil.which("cmd") or "cmd.exe"
    exe = shutil.which("bash") or shutil.which("sh")
    if not exe:
        raise RuntimeError("bash/sh not found on PATH.")
    return "bash", exe


def _scrubbed_env() -> dict:
    """Child environment without anything that looks like a secret."""
    secret_words = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL")
    return {k: v for k, v in os.environ.items() if not any(w in k.upper() for w in secret_words)}


def _kill_tree(proc: subprocess.Popen) -> None:
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True, timeout=10)
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def _cap(text: str, limit: int) -> str:
    raw = text.encode("utf-8", errors="ignore")
    if len(raw) <= limit:
        return text
    return raw[:limit].decode("utf-8", errors="ignore") + f"\n...[TRUNCATED at {limit} bytes]"


def tool_run_command(command: str, reason: str = "", shell: str = None, timeout_seconds: int = None) -> dict:
    blocked = check_command_policy(command)
    if blocked:
        logger.log_security_block("run_command", f"{blocked}: {str(command)[:200]}")
        return {"error": f"BLOCKED by policy ({blocked}). Choose a safer approach or ask the user to run it themselves."}

    try:
        shell_name, exe = _pick_shell(shell)
    except RuntimeError as e:
        return {"error": str(e)}

    try:
        timeout = int(timeout_seconds) if timeout_seconds else config.COMMAND_TIMEOUT_SECONDS
    except (TypeError, ValueError):
        timeout = config.COMMAND_TIMEOUT_SECONDS
    timeout = max(1, min(timeout, config.COMMAND_MAX_TIMEOUT_SECONDS))

    cwd = _workspace_root()
    auto = config.AUTO_APPROVE_SAFE_COMMANDS and is_safe_readonly(command)
    if not auto:
        approved = _ask_human(
            ["COMMAND APPROVAL REQUIRED", f"Shell  : {shell_name}", f"Dir    : {cwd}",
             f"Timeout: {timeout}s", f"Why    : {(reason or '(none given)')[:300]}", "Command:", "",
             *["   " + ln for ln in command.strip().splitlines()]],
            "Run this command?",
        )
        if not approved:
            logger.log_event({"tool": "run_command", "approved": False, "command": command[:300]})
            return {"error": "Command was REJECTED by the human operator. Do not retry it; "
                             "explain what you wanted to do and ask the user, or use another approach."}
    else:
        print(f"\n[auto-approved read-only command] {command}")

    if shell_name == "powershell":
        prefix = ("try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}; "
                  "$ProgressPreference = 'SilentlyContinue'; ")
        argv = [exe, "-NoProfile", "-NonInteractive", "-Command", prefix + command]
    elif shell_name == "cmd":
        argv = f'"{exe}" /d /s /c "{command}"'  # string form: list2cmdline would mangle cmd quoting
    else:
        argv = [exe, "-c", command]

    popen_kwargs = dict(cwd=cwd, env=_scrubbed_env(), stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if os.name == "nt":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        popen_kwargs["start_new_session"] = True

    try:
        proc = subprocess.Popen(argv, **popen_kwargs)
    except OSError as e:
        return {"error": f"Could not start {shell_name}: {e}"}

    timed_out = False
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_tree(proc)
        try:
            out, err = proc.communicate(timeout=5)
        except Exception:
            out, err = b"", b""
    except KeyboardInterrupt:
        _kill_tree(proc)
        raise

    limit = config.COMMAND_MAX_OUTPUT_BYTES
    result = {
        "shell": shell_name,
        "cwd": cwd,
        "command": command,
        "exit_code": proc.returncode,
        "timed_out": timed_out,
        "stdout": _cap((out or b"").decode("utf-8", errors="replace"), limit),
        "stderr": _cap((err or b"").decode("utf-8", errors="replace"), max(1000, limit // 4)),
    }
    if timed_out:
        result["note"] = f"Killed after {timeout}s. Output above is partial."
    logger.log_event({"tool": "run_command", "approved": True, "auto": auto, "shell": shell_name,
                      "command": command[:500], "exit_code": proc.returncode, "timed_out": timed_out})
    return result


# ---------------------------------------------------------------------------
# Memory tools
# ---------------------------------------------------------------------------

_MAX_NOTES = 300


def _load_notes() -> list:
    try:
        with open(config.MEMORY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        notes = data.get("notes", []) if isinstance(data, dict) else []
        return [n for n in notes if isinstance(n, dict) and "key" in n and "value" in n]
    except (OSError, ValueError):
        return []


def _save_notes(notes: list) -> None:
    directory = os.path.dirname(os.path.abspath(config.MEMORY_FILE))
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"notes": notes}, f, indent=2, ensure_ascii=False)
        os.replace(tmp, config.MEMORY_FILE)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def tool_remember(key: str, value: str) -> dict:
    if not isinstance(key, str) or not key.strip() or not isinstance(value, str) or not value.strip():
        return {"error": "key and value must be non-empty strings."}
    key = key.strip()[:80]
    value = value.strip()[:2000]
    notes = _load_notes()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for n in notes:
        if n["key"].lower() == key.lower():
            n["value"], n["saved_at"] = value, now
            break
    else:
        if len(notes) >= _MAX_NOTES:
            return {"error": f"Memory is full ({_MAX_NOTES} notes). Use forget to remove some."}
        notes.append({"key": key, "value": value, "saved_at": now})
    try:
        _save_notes(notes)
    except OSError as e:
        return {"error": f"Could not save memory: {e}"}
    return {"result": "saved", "key": key, "total_notes": len(notes)}


def tool_recall(query: str = "") -> dict:
    notes = _load_notes()
    q = (query or "").strip().lower()
    if q:
        notes = [n for n in notes if q in n["key"].lower() or q in n["value"].lower()]
    return {"query": query, "count": len(notes), "notes": notes[-50:]}


def tool_forget(key: str) -> dict:
    if not isinstance(key, str) or not key.strip():
        return {"error": "key must be a non-empty string."}
    notes = _load_notes()
    kept = [n for n in notes if n["key"].lower() != key.strip().lower()]
    if len(kept) == len(notes):
        return {"error": f"No note with key '{key}'."}
    try:
        _save_notes(kept)
    except OSError as e:
        return {"error": f"Could not save memory: {e}"}
    return {"result": "forgotten", "key": key}


def memory_summary(max_items: int = 15) -> str:
    """Short text block for the system prompt (empty string if no notes)."""
    if not config.ENABLE_MEMORY_TOOLS:
        return ""
    notes = _load_notes()[-max_items:]
    if not notes:
        return ""
    return "\n".join(f"- {n['key']}: {n['value'][:200]}" for n in notes)


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

_PATH = {"type": "string", "description": "Path relative to the workspace folder, e.g. 'notes/plan.md'."}

FILE_DEFINITIONS = [
    {"name": "read_file",
     "description": "Read a text file inside the workspace folder (UTF-8). Use start_line/max_lines to page through big files.",
     "parameters": {"type": "object", "properties": {
         "path": _PATH,
         "start_line": {"type": "integer", "description": "First line to return (default 1)."},
         "max_lines": {"type": "integer", "description": "Max lines to return (default 400, max 2000)."}},
         "required": ["path"]}},
    {"name": "write_file",
     "description": "Create or overwrite (or append to) a text file inside the workspace. Parent folders are created automatically. Always write the COMPLETE file content when overwriting.",
     "parameters": {"type": "object", "properties": {
         "path": _PATH,
         "content": {"type": "string", "description": "Full text content to write."},
         "mode": {"type": "string", "enum": ["overwrite", "append"], "description": "Default overwrite."}},
         "required": ["path", "content"]}},
    {"name": "replace_in_file",
     "description": "Replace ONE exact, unique piece of text in a workspace file. Fails if the old text is missing or appears more than once.",
     "parameters": {"type": "object", "properties": {
         "path": _PATH,
         "old": {"type": "string", "description": "Exact existing text (must be unique in the file)."},
         "new": {"type": "string", "description": "Replacement text."}},
         "required": ["path", "old", "new"]}},
    {"name": "list_dir",
     "description": "List files and folders inside the workspace (skips .git, node_modules, __pycache__, secrets).",
     "parameters": {"type": "object", "properties": {
         "path": {"type": "string", "description": "Folder relative to workspace (default '.')."},
         "recursive": {"type": "boolean", "description": "Walk subfolders too."},
         "max_entries": {"type": "integer", "description": "Default 200, max 1000."}}}},
    {"name": "search_in_files",
     "description": "Search text (or a regex) inside workspace files, like grep. Returns file, line number and the matching line.",
     "parameters": {"type": "object", "properties": {
         "query": {"type": "string", "description": "Text or regex to look for."},
         "path": {"type": "string", "description": "Folder to search (default '.')."},
         "is_regex": {"type": "boolean", "description": "Treat query as a regular expression."},
         "file_glob": {"type": "string", "description": "Filename filter, e.g. '*.js' (default '*')."},
         "max_results": {"type": "integer", "description": "Default 50, max 200."}},
         "required": ["query"]}},
]

TERMINAL_DEFINITIONS = [
    {"name": "run_command",
     "description": (
         "Run a terminal command (PowerShell on Windows, bash elsewhere) inside the workspace folder. "
         "A HUMAN MUST APPROVE every command, so prefer one clear command over many small ones and always "
         "give a short 'reason'. Destructive commands are blocked. Output is truncated and commands time out. "
         "Good uses: git status, npm/pip commands, running tests or scripts, listing processes/ports, ping/nslookup."),
     "parameters": {"type": "object", "properties": {
         "command": {"type": "string", "description": "The exact command line to run."},
         "reason": {"type": "string", "description": "One sentence shown to the human explaining why."},
         "shell": {"type": "string", "enum": ["powershell", "cmd", "bash"], "description": "Optional; default is PowerShell on Windows, bash elsewhere."},
         "timeout_seconds": {"type": "integer", "description": "Optional, default 60, max 300."}},
         "required": ["command", "reason"]}},
]

MEMORY_DEFINITIONS = [
    {"name": "remember",
     "description": "Save a short note (key + value) that persists across runs — findings, user preferences, useful URLs, decisions.",
     "parameters": {"type": "object", "properties": {
         "key": {"type": "string", "description": "Short label, e.g. 'target_server_software'."},
         "value": {"type": "string", "description": "The fact to remember (max 2000 chars)."}},
         "required": ["key", "value"]}},
    {"name": "recall",
     "description": "Look up saved notes. Leave query empty to list recent notes.",
     "parameters": {"type": "object", "properties": {
         "query": {"type": "string", "description": "Optional text to match in keys/values."}}}},
    {"name": "forget",
     "description": "Delete a saved note by key.",
     "parameters": {"type": "object", "properties": {
         "key": {"type": "string", "description": "Key of the note to delete."}},
         "required": ["key"]}},
]

IMPLEMENTATIONS = {
    "read_file": lambda a: tool_read_file(a.get("path", ""), a.get("start_line", 1), a.get("max_lines", 400)),
    "write_file": lambda a: tool_write_file(a.get("path", ""), a.get("content"), a.get("mode", "overwrite")),
    "replace_in_file": lambda a: tool_replace_in_file(a.get("path", ""), a.get("old", ""), a.get("new")),
    "list_dir": lambda a: tool_list_dir(a.get("path", "."), bool(a.get("recursive", False)), a.get("max_entries", 200)),
    "search_in_files": lambda a: tool_search_in_files(a.get("query", ""), a.get("path", "."), bool(a.get("is_regex", False)),
                                                      a.get("file_glob", "*"), a.get("max_results", 50)),
    "run_command": lambda a: tool_run_command(a.get("command", ""), a.get("reason", ""), a.get("shell"), a.get("timeout_seconds")),
    "remember": lambda a: tool_remember(a.get("key", ""), a.get("value", "")),
    "recall": lambda a: tool_recall(a.get("query", "")),
    "forget": lambda a: tool_forget(a.get("key", "")),
}
