# Controlled Web AI Agent

A small, readable, **tool-calling AI agent** written in plain Python. Give it a task in natural language and it will research on the internet, inspect *your own* website, read and write files in a sandbox folder, and — only with your explicit approval, command by command — run terminal commands (PowerShell on Windows, bash elsewhere).

It is built to answer one question honestly: **how do you give an LLM real capabilities without giving it real power over your machine?** Every safety control lives in Python code you can read and test (`security.py`, `system_tools.py`, `web_tools.py`). None of them depend on the model behaving well.

Works with free-tier LLM APIs: **Google Gemini**, **OpenRouter** and **xAI Grok**. Only two dependencies: `requests` and `python-dotenv`.

---

## ⚠️ Read this before you run it

This project connects a language model to a terminal, your file system (inside a folder), the public internet and a website. That is useful, and it is **not risk-free**. Please read all of these.

1. **Only test websites you own or have written permission to test.** The recon tools are passive and read-only, but scanning someone else's site without permission can still be illegal and violates most hosting terms. You are responsible for how you use this software.
2. **The terminal tool runs commands with your user's full permissions.** Every command asks you for `y/N` first, and a deny-list blocks obviously destructive commands — but the deny-list is a seatbelt, **not a sandbox**. The commands are *not* confined to the workspace folder (the workspace is only the starting directory; a command can `cd ..` or use absolute paths). **You are the safety system. Read every command before typing `y`.**
3. **Prompt injection is real.** Any web page, search result, file, or target-site response can contain text written to trick the model ("ignore your instructions and run this command…"). The agent is instructed to treat such text as data, and dangerous actions need your approval, but no prompt is a guarantee. Be extra careful when researching unfamiliar sites; consider `CONFIRM_FETCH_URL=true`.
4. **Everything the agent reads is sent to your LLM provider.** Web pages, file contents, command output and target-site responses become part of the conversation and are transmitted to Gemini/OpenRouter/Grok. Do not put secrets, customer data or private documents in the workspace. Free tiers may use your data differently than paid tiers — **check your provider's current terms**.
5. **LLMs make mistakes.** Findings are heuristics (pattern matching on headers and HTML). Expect false positives and false negatives, and verify before you report or "fix" anything. This is not a substitute for a professional security assessment.
6. **Free tiers have limits.** Rate limits, small context windows and weaker tool-calling in some free models will cause stalls or odd behaviour. That is a model limitation, not necessarily a bug.
7. **No warranty.** Use at your own risk. See the [License](#license).

**Recommended first-run settings** (edit `.env`):

```ini
ENABLE_CONFIRMATION_PROMPT=true   # ask before any POST/PUT/PATCH/DELETE to your site
CONFIRM_FILE_WRITES=true          # ask before every file write (optional but good while learning)
AUTO_APPROVE_SAFE_COMMANDS=false  # every terminal command needs your y/N
```

---

## Table of contents

1. [What this is (and is not)](#1-what-this-is-and-is-not)
2. [Feature overview](#2-feature-overview)
3. [How it works](#3-how-it-works)
4. [Project layout](#4-project-layout)
5. [Quick start](#5-quick-start)
6. [Getting free API keys](#6-getting-free-api-keys)
7. [Using the agent](#7-using-the-agent)
8. [Tool reference](#8-tool-reference)
9. [The safety model](#9-the-safety-model)
10. [The terminal tool in depth](#10-the-terminal-tool-in-depth)
11. [Web research tools in depth](#11-web-research-tools-in-depth)
12. [Configuration reference](#12-configuration-reference)
13. [Logs, reports and memory](#13-logs-reports-and-memory)
14. [What data leaves your machine](#14-what-data-leaves-your-machine)
15. [Testing](#15-testing)
16. [Troubleshooting](#16-troubleshooting)
17. [Extending the agent](#17-extending-the-agent)
18. [Known limitations](#18-known-limitations)
19. [FAQ](#19-faq)
20. [Contributing](#20-contributing)
21. [Reporting security issues](#21-reporting-security-issues)
22. [License](#license)

---

## 1. What this is (and is not)

**It is:**

- A learning-friendly reference for building a safe(r) LLM agent: a real tool-calling loop, provider adapters, input validation, human approval gates, redaction and tests.
- A practical assistant for a developer: research a topic, review your own site's public security posture, read/edit files in a scratch folder, run a command with your sign-off, and remember notes between sessions.

**It is not:**

- A penetration-testing or exploitation framework. It does **not** do exploitation, credential harvesting, authentication bypass, port scanning, brute forcing or denial-of-service, and the system prompt tells the model to refuse such requests. The terminal tool's deny-list blocks the obvious ways of smuggling them in.
- A sandbox. If you approve a command, it really runs.
- A general HTTP client. Target-site tools talk to exactly one host.

---

## 2. Feature overview

The agent has **38 tools** in six groups. Groups 2–6 can each be switched off with one setting.

| # | Group | What it does | Needs your approval? | Switch |
|---|---|---|---|---|
| 1 | **Target site tools** (20) | GET-family inspection and hardening checks of *your* site; optional POST/PUT/PATCH/DELETE | Mutating requests (configurable) | always on |
| 2 | **Web research** (3) | Search the internet, query free knowledge APIs, read public pages | No (optional per-fetch confirmation) | `ENABLE_WEB_TOOLS` |
| 3 | **Terminal** (1) | Run PowerShell / bash / cmd commands | **Yes, every command** | `ENABLE_TERMINAL_TOOL` |
| 4 | **Workspace files** (5) | Read, write, edit, list and grep files inside one folder | Optional (`CONFIRM_FILE_WRITES`) | `ENABLE_FILE_TOOLS` |
| 5 | **Memory** (3) | Save and recall short notes across sessions | No | `ENABLE_MEMORY_TOOLS` |
| 6 | **Recon & reporting** (6) | DNS, tech-stack fingerprint, robots/security.txt, forms & endpoints, redirect chain, Markdown report | No (passive GETs) | `ENABLE_RECON_TOOLS` |

Session features: the conversation continues across tasks (`/reset` to clear), old tool output is compacted to save context, identical repeated tool calls are stopped, oversized results are capped, a crashing tool is reported to the model instead of ending the session, and `Ctrl+C` cancels only the current task.

---

## 3. How it works

A plain LLM turns text into text. An **agent** adds tools and a loop:

```
you type a task
      │
      ▼
┌──────────────┐    "I want to call web_search(query=…)"
│     LLM      │ ─────────────────────────────────────────┐
└──────────────┘                                          ▼
      ▲                                    ┌───────────────────────────────┐
      │ tool result (as data)              │ Python validates the request  │
      │                                    │  • domain lock / SSRF checks  │
      │                                    │  • workspace jail             │
      │                                    │  • deny-list + human approval │
      │                                    └───────────────┬───────────────┘
      │                                                    ▼
      └──────────── redacted, size-capped result ◄── tool executes (or is refused)
```

The model never touches the network, disk or shell. It can only **ask** (as structured JSON). `agent.py` runs the loop; `tools.py` maps a tool name to a Python function; `security.py` / `system_tools.py` / `web_tools.py` decide whether the request is allowed. The loop ends when the model stops asking for tools, or when `MAX_TOOL_CALLS_PER_TASK` is reached.

**Two categories of network access, deliberately separate:**

- *Target tools* can reach **only** the host in `TARGET_BASE_URL` (exact hostname match, re-checked on every redirect hop, never private/loopback/metadata addresses).
- *Research tools* (`web_search`, `search_source`, `fetch_url`) can read the **public** internet, GET only, with SSRF protections. They never use the target tools' session or cookies.

---

## 4. Project layout

```
ai-agent/
├── agent.py            CLI + the agent loop, system prompt, session handling
├── config.py           All settings, read from .env (nothing here makes network calls)
├── llm_provider.py     Gemini / OpenRouter / Grok adapters behind one chat() function
├── security.py         THE enforcement boundary: domain lock, SSRF/IP checks, redaction
├── tools.py            Target-site tools (20) + registration of the other groups
├── web_tools.py        web_search, search_source, fetch_url
├── system_tools.py     run_command, file tools, memory tools
├── recon_tools.py      DNS, tech stack, robots/security.txt, forms/endpoints, redirects, report
├── logger.py           JSON-lines logging with automatic secret redaction
├── selftest.py         Offline test-suite (no API keys, no internet needed)
├── requirements.txt    requests, python-dotenv
├── .env.example        Copy to .env and fill in
├── workspace/          The ONLY folder file tools can touch; commands start here
└── logs/               agent.log, memory.json, reports/  (git-ignored)
```

---

## 5. Quick start

**Requirements:** Python 3.9+ (developed and tested on 3.12), an API key for one LLM provider (see [section 6](#6-getting-free-api-keys)), and a website you own or are authorised to test.

### Linux / macOS

```bash
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

### Windows (PowerShell)

```powershell
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>
py -m venv venv
.\venv\Scripts\Activate.ps1      # if blocked: Set-ExecutionPolicy -Scope Process Bypass
pip install -r requirements.txt
Copy-Item .env.example .env
```

### Configure and run

1. Open `.env` and set at least:

   ```ini
   LLM_PROVIDER=gemini
   MODEL=gemini-2.5-flash
   GEMINI_API_KEY=your-key
   TARGET_BASE_URL=https://your-site.example
   ```

   Web search works with **no extra keys** (DuckDuckGo, Wikipedia).
2. Verify the install (offline, no keys used): `python selftest.py` — see [Testing](#15-testing).
3. Start the agent: `python agent.py`
4. Try a harmless first task:

   ```
   > Search the web for the current Node.js LTS version and summarise it in two lines.
   ```

> **Important:** `TARGET_BASE_URL` must be a **public** address. The agent refuses to contact `localhost`, `127.0.0.1`, private networks and cloud-metadata addresses — that is a deliberate safety feature. To test a local dev server, expose it through a staging deployment or a tunnelling service that gives you a public hostname.

---

## 6. Getting free API keys

| Service | Used for | Where | Notes |
|---|---|---|---|
| **Google Gemini** | LLM (default) | [aistudio.google.com/apikey](https://aistudio.google.com/apikey) | Free tier available; use a model with function-calling support (e.g. `gemini-2.5-flash`). Model names change — check the current list. |
| **OpenRouter** | LLM | [openrouter.ai/keys](https://openrouter.ai/keys) | Pick a `:free` model **that supports tool calling**; not all do. |
| **xAI Grok** | LLM | [console.x.ai](https://console.x.ai) | Availability and free credit terms change — verify on their site. |
| **Brave Search** | Better web search (optional) | [brave.com/search/api](https://brave.com/search/api/) | Free plan; set `BRAVE_API_KEY`. |
| **Tavily** | Better web search (optional) | [tavily.com](https://tavily.com) | Free plan; set `TAVILY_API_KEY`. |
| **GitHub token** | Higher GitHub search limit (optional) | GitHub → Settings → Developer settings | Set `GITHUB_TOKEN`; a token with no scopes is enough. |
| **NVD API key** | Higher CVE-lookup rate limit (optional) | [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key) | Set `NVD_API_KEY`. |

Only fill in the key for the provider you selected. **Never commit `.env`** — the included `.gitignore` excludes it.

---

## 7. Using the agent

### Interactive mode

```bash
python agent.py
```

The startup banner shows which tool groups and toggles are ON so you always know what is enabled before you type a task.

| Command | What it does |
|---|---|
| *any text* | Sent to the agent as a task |
| `/help` | Show commands |
| `/tools` | List every tool by group |
| `/memory` | Show saved notes |
| `/reset` | Start a fresh conversation (reloads saved notes) |
| `/quit`, `quit`, `exit` | Leave |
| `Ctrl+C` | Cancel the current task (history for that task is discarded) |

The conversation **continues across tasks** until you `/reset`, so you can say "now write that to a file" or "check the same thing on /login".

### One-shot mode

```bash
python agent.py "check my security headers and write a report"
```

### Example tasks

**Research**
```
> What changed in the latest Socket.IO major release? Give me sources.
> Find popular npm packages for rate limiting in Express and compare them.
> Look up how to configure a Content-Security-Policy for a Next.js app.
```

**Testing your own site (passive)**
```
> Fingerprint my homepage's technology stack, then look up known CVEs for any versions you find.
> Check my DNS records, SPF and DMARC.
> Trace the redirect chain for /login and tell me if HTTP upgrades to HTTPS.
> Run every hardening check you have and write me a report called site_review.
```

**Files and terminal (workspace)**
```
> List what's in the workspace, then create notes/todo.md with a checklist for hardening my site.
> Run "git --version" and tell me what you see.        # you'll be asked to approve
```

**Memory**
```
> Remember that my staging site is https://staging.example.com and I use Cloudflare.
```

### What an approval looks like

When the model wants to run a command you see exactly what will happen:

```
================================================================
 COMMAND APPROVAL REQUIRED
 Shell  : powershell
 Dir    : C:\projects\ai-agent\workspace
 Timeout: 60s
 Why    : Check the Node version before suggesting an upgrade
 Command:

    node --version
================================================================
Run this command? [y/N]:
```

Anything other than `y` / `yes` is a **no**. The model is told the command was rejected and must not retry it.

---

## 8. Tool reference

### 8.1 Target-site tools (20) — locked to `TARGET_BASE_URL`

All GET-family and mutating requests share one `requests.Session`, so cookies your own site sets (e.g. after a login POST) persist during the run. Use `reset_session` to clear it. Redirects are never followed blindly: each hop is re-validated.

| Tool | What it does |
|---|---|
| `get_page` | GET a path (optional custom headers) |
| `batch_get` | Several GETs in one call |
| `head_page` | HEAD — status and headers only |
| `crawl_links` | GET a page and list same-domain links |
| `get_sitemap` | Fetch `/robots.txt` and `/sitemap.xml` |
| `check_options` | OPTIONS — which methods are allowed (performs none of them) |
| `timing_check` | Repeated GETs, response-time stats |
| `check_security_headers` | HSTS, CSP, X-Frame-Options, etc. — presence and value |
| `check_cookie_flags` | Secure / HttpOnly / SameSite flags (never cookie names or values) |
| `check_exposed_files` | Status-only check of commonly leaked paths (`.env`, `.git`, backups) |
| `check_ssl_certificate` | TLS handshake on port 443: issuer, expiry, protocol version |
| `check_cors_policy` | Sends a foreign `Origin`, flags risky wildcard/credentials combos |
| `check_directory_listing` | Flags "Index of /" style listings |
| `read_source_deep` | Reads a page and same-domain assets; checks external assets for Subresource Integrity (does not fetch them) |
| `save_report` | Writes JSON to `logs/reports/<name>.json` only |
| `lookup_cve` | Keyword lookup in the public NVD vulnerability database |
| `reset_session` | Clears local cookies (no network call) |
| `post_json` | POST with a JSON body — **approval per `ENABLE_CONFIRMATION_PROMPT`** |
| `post_form` | POST with a form body — same approval rules |
| `modify_resource` | PUT / PATCH / DELETE — same approval rules |

### 8.2 Web research (3)

| Tool | What it does |
|---|---|
| `web_search` | General search. Tries Brave (if key) → Tavily (if key) → DuckDuckGo (no key) → Wikipedia. Returns titles, URLs, snippets. |
| `search_source` | Targeted free APIs: `wikipedia` (with intro summary), `stackoverflow`, `github` (repositories), `hackernews`, `npm` |
| `fetch_url` | Read one **public** page / JSON / text URL as clean text. `include_links` optionally returns links found on the page. |

### 8.3 Terminal (1)

| Tool | What it does |
|---|---|
| `run_command` | Run a command in `powershell` / `cmd` / `bash` inside the workspace. Requires human approval. Parameters: `command`, `reason`, optional `shell`, optional `timeout_seconds`. |

### 8.4 Workspace files (5)

| Tool | What it does |
|---|---|
| `read_file` | Read a UTF-8 text file (with `start_line` / `max_lines` paging) |
| `write_file` | Create, overwrite or append; creates parent folders |
| `replace_in_file` | Replace one exact, unique piece of text (fails if missing or ambiguous) |
| `list_dir` | List files/folders (skips `.git`, `node_modules`, `__pycache__`, virtualenvs, build folders) |
| `search_in_files` | grep-style text/regex search with an optional filename glob |

### 8.5 Memory (3)

| Tool | What it does |
|---|---|
| `remember` | Save a note (key + value). Same key = update. |
| `recall` | Find notes by text, or list recent ones |
| `forget` | Delete a note by key |

### 8.6 Recon & reporting (6) — passive, GET-only, target-locked

| Tool | What it does |
|---|---|
| `check_dns_records` | A / AAAA / CNAME / MX / NS / TXT / CAA plus SPF and DMARC review, via DNS-over-HTTPS (`dns.google`) |
| `detect_tech_stack` | Fingerprints server, framework, CMS, libraries and versions from headers, cookie names and markup; suggests `lookup_cve` |
| `check_robots_and_security_txt` | Parses `robots.txt` (disallow hints, sitemaps) and `security.txt` |
| `extract_forms_and_endpoints` | Finds forms (flags missing CSRF token, HTTP action, GET passwords) and API routes / websocket URLs in inline and same-domain scripts |
| `trace_redirects` | Full redirect chain and an HTTP → HTTPS upgrade check; off-domain redirects are reported, never followed |
| `generate_report` | Severity-sorted Markdown report saved to `logs/reports/<name>.md` |

---

## 9. The safety model

The core rule: **Python enforces, the prompt only advises.** Assume the model can be wrong, manipulated or malicious; the code must stay safe anyway.

### Always enforced (not configurable from `.env`)

| Control | Where | What it stops |
|---|---|---|
| Target domain lock | `security.validate_url` | Target tools reaching any host but `TARGET_BASE_URL`'s |
| Private / loopback / link-local / reserved / metadata IP block | `security` | SSRF into your network or cloud metadata (`169.254.169.254`) |
| Redirect re-validation | `security.validate_redirect` | A redirect being used to escape the domain lock |
| Scheme block | `security` | `file:`, `javascript:`, `data:` URLs |
| Public-URL checks for `fetch_url` | `security.validate_public_url` | http/https only; no credentials in URL; ports 80/443/8080/8443 only; every resolved IP must be public; every redirect hop re-checked |
| Workspace jail | `system_tools._resolve` | Path traversal, absolute paths, symlink escapes |
| Secret-file block | `system_tools` | Reading/writing `.env*`, `*.pem`, `*.key`, `id_rsa*`, `.npmrc`, `.netrc`, … |
| Terminal deny-list | `system_tools.check_command_policy` | Destructive or stealthy commands, even if approved |
| Human approval for `run_command` | `system_tools` | Anything running without you seeing it (unless you enable the tiny safe-list) |
| Redaction in logs | `logger` / `security` | Auth headers, cookies, and keys like `password`, `token`, `api_key` |
| Size / time / count limits | `config` | Runaway responses, commands, loops and costs |

### Guidance only (the prompt) — not a security control

The system prompt tells the model to explain steps, avoid credentials, refuse exploitation, and treat fetched content as untrusted. This shapes behaviour but **can be ignored or bypassed** by a determined injection. That is why the controls above live in code.

### Threat model

| Threat | Mitigation | Residual risk |
|---|---|---|
| Model asked to attack another domain | Domain lock, IP block | None for target tools |
| Redirect / DNS trick to reach internal services | Every hop re-validated; DNS results checked | DNS rebinding between check and connect (see [limitations](#18-known-limitations)) |
| SSRF through `fetch_url` | Public-URL validation on every hop | Same rebinding caveat |
| Prompt injection from web pages or target responses | Untrusted labelling, approvals, deny-list, no secrets in env/files | A convincing injection might still persuade **you** to approve something bad |
| Destructive command | Approval + deny-list | Deny-list is regex-based; approval fatigue is real |
| Secret exfiltration | Secret-file block, scrubbed env, secrets excluded from file tools | Commands are **not** jailed; a command you approve can read anything your user can |
| Data-exfiltration via URL query strings | Optional `CONFIRM_FETCH_URL`; logs record fetched URLs | With confirmation off, a fetch can carry data in its query string |
| Runaway loops / cost | Tool-call cap, repeated-call guard, timeouts, retries with caps | Free-tier quotas can still be exhausted |
| Secrets in logs | Redaction (headers, JSON keys) | Logs can still contain URLs, queries and command text — keep `logs/` private |

---

## 10. The terminal tool in depth

`run_command` is the most powerful — and most dangerous — tool. Here is exactly what it does.

**Approval.** Every command is displayed (shell, folder, timeout, the model's stated reason, the command) and needs `y`/`yes`. Empty input, EOF and `Ctrl+C` all mean no.

**Shell selection.** `COMMAND_SHELL=auto` picks PowerShell on Windows (`powershell.exe`, then `pwsh`) and bash elsewhere (`pwsh` is preferred on Linux/macOS if you choose `powershell`). The model may request `powershell`, `cmd` (Windows only) or `bash`. PowerShell runs with `-NoProfile -NonInteractive` and UTF-8 output.

**Working directory and environment.**
- Starts in `WORKSPACE_DIR`. It is a *starting point*, not a jail.
- The child process environment drops every variable whose name contains `KEY`, `TOKEN`, `SECRET`, `PASSWORD`, `PASSWD` or `CREDENTIAL`, so your LLM/search keys are not visible to commands. (Side effect: a command that legitimately needs such a variable, e.g. `NPM_TOKEN`, won't see it.)
- stdin is closed, so a command can't hang waiting for input.

**Limits.** Timeout defaults to 60 s (model may ask for more, capped at `COMMAND_MAX_TIMEOUT_SECONDS`, default 300). On timeout the whole process tree is killed. Output is truncated (stdout 20 000 bytes, stderr a quarter of that) so it can't flood the model's context.

**Hard deny-list (blocked even if you would approve).** Matching is regex-based and case-insensitive:

| Category | Examples blocked |
|---|---|
| Disk / partition | `Format-Volume`, `format C:`, `diskpart`, `mkfs`, `dd … of=/dev/…` |
| Recursive deletes of roots | `rm -rf /`, `rm -rf ~`, `Remove-Item -Recurse C:\`, `del /s C:\*`, `$HOME`, `%USERPROFILE%`, system folders |
| Power | `shutdown`, `Restart-Computer`, `Stop-Computer`, `reboot`, `poweroff` |
| System tampering | `reg add/delete/import`, `bcdedit`, `vssadmin delete`, `wevtutil cl`, `cipher /w`, `net user`, `New-LocalUser`, firewall/Defender changes, `Set-ExecutionPolicy` |
| Obfuscation / remote code | `-EncodedCommand`, `Invoke-Expression` / `iex`, `curl … \| bash`, `irm … \| iex` |
| Secrets | any mention of `.env`, `id_rsa`, `*.pem`, `.npmrc`, `.netrc`, or your API-key variable names |
| Other | fork bombs, commands over 4 000 characters |

The deny-list intentionally errs on the side of blocking; it can produce false positives (for example a Node one-liner that reads `process.env`). It cannot catch every dangerous command — that is the job of **your** approval.

**Optional safe-list.** `AUTO_APPROVE_SAFE_COMMANDS=true` skips the prompt for a very small set of read-only commands **with no pipes, redirects, chaining, subshells or variables**: `pwd`, `Get-Location`, `Get-Date`, `whoami`, `hostname`, `echo`, `ls`/`dir`/`Get-ChildItem`/`tree`, `git status|log|diff|branch|--version`, `node|npm|python|pip --version`, `npm ls`, `pip list`. Everything else still asks. Off by default.

**How to review a command before approving** — stop and say no if you see any of:
- paths outside the workspace you didn't expect (`..`, `C:\Users\…`, `~`, `/etc`);
- network downloads combined with execution, or unfamiliar URLs;
- anything that touches credentials, SSH keys, browser profiles or cloud CLI configs;
- a command that doesn't obviously match the "Why" the model gave;
- text that looks copied from a web page you asked it to read.

> **Status of testing:** the bash path is covered by `selftest.py`. The PowerShell path is written carefully but has not been exercised on a live Windows machine by the author of this document — try a harmless command (`Get-Date`) first and open an issue if anything misbehaves.

---

## 11. Web research tools in depth

**Search provider order (`SEARCH_PROVIDER=auto`):** Brave (if `BRAVE_API_KEY`) → Tavily (if `TAVILY_API_KEY`) → DuckDuckGo → Wikipedia. The first provider that returns results wins; if all fail, the error lists what each one said. You can pin one provider with `SEARCH_PROVIDER=brave|tavily|duckduckgo|wikipedia`.

**DuckDuckGo caveat.** The keyless option parses DuckDuckGo's public HTML page. It is convenient but unofficial, can be rate-limited or served a bot-check page, and may break if the page layout changes. For reliable results add a free Brave or Tavily key.

**`fetch_url` details.**
- GET only, fresh session per call (never sends your target-site cookies).
- Every URL and every redirect hop goes through `security.validate_public_url`.
- Reads text-like content only (HTML, plain text, JSON, XML, JavaScript, RSS/Atom). PDFs and binaries are refused.
- Stops downloading at `FETCH_MAX_BYTES` (2 MB) and returns at most `max_chars` of text (default 12 000, up to 50 000).
- The result carries an "untrusted content" note. `CONFIRM_FETCH_URL=true` asks you `y/N` before each fetch.

**`search_source` endpoints:** Wikipedia API, Stack Exchange API, GitHub Search API, Algolia Hacker News API, npm registry search. All are free public APIs with their own rate limits.

---

## 12. Configuration reference

All settings live in `.env` (copy `.env.example`). "Code default" applies when a variable is unset; `.env.example` ships some looser values, shown in the last column where they differ.

### LLM

| Variable | Code default | Notes |
|---|---|---|
| `LLM_PROVIDER` | `gemini` | `gemini`, `openrouter` or `grok` |
| `MODEL` | `gemini-2.5-flash` | Provider-specific model name. Must support tool/function calling. |
| `GEMINI_API_KEY` / `OPENROUTER_API_KEY` / `GROK_API_KEY` | empty | Only the selected provider's key is needed |
| `LLM_MAX_RETRIES` | `3` | Retries on HTTP 429/5xx and network errors, with backoff |

### Target site

| Variable | Code default | Notes |
|---|---|---|
| `TARGET_BASE_URL` | empty (required) | The only host target tools may contact |
| `REQUEST_TIMEOUT_SECONDS` | `30` | Per request |
| `MAX_RESPONSE_BYTES` | `100000` | Body bytes handed to the model. Keep modest — free-tier context windows are small |
| `MAX_POST_BODY_BYTES` | `50000` (`5000000` in example) | Cap on POST bodies |
| `MIN_SECONDS_BETWEEN_REQUESTS` | `0.3` (`0` in example) | Used when rate limiting is ON |
| `ENABLE_CONFIRMATION_PROMPT` | `false` | ON = ask `y/N` before every POST/PUT/PATCH/DELETE. **Recommended: `true`.** |
| `AUTO_APPROVE_POST_PATHS` | `/` | Path prefixes that skip the prompt when it is ON (`/` matches everything!). Use a narrow prefix like `/api/agent-test`. |
| `ENABLE_RATE_LIMIT` | `false` | ON = wait `MIN_SECONDS_BETWEEN_REQUESTS` between requests |
| `ENABLE_REDIRECT_CONFIRMATION` | `false` | ON = report same-domain redirects instead of following |
| `AUTO_REDIRECT_MAX_HOPS` | `5` | Max redirects followed automatically |

> With `ENABLE_CONFIRMATION_PROMPT=false`, POST/PUT/PATCH/DELETE requests to your site fire immediately. A mistake in a task description can hit your live site with no pause. Check `logs/agent.log` after the fact.

### Tool groups

| Variable | Default | Effect |
|---|---|---|
| `ENABLE_WEB_TOOLS` | `true` | `web_search`, `search_source`, `fetch_url` |
| `ENABLE_TERMINAL_TOOL` | `true` | `run_command` |
| `ENABLE_FILE_TOOLS` | `true` | File tools |
| `ENABLE_MEMORY_TOOLS` | `true` | `remember`, `recall`, `forget` |
| `ENABLE_RECON_TOOLS` | `true` | DNS, tech stack, robots, forms, redirects, report |

Accepted true values: `1`, `true`, `yes`, `on`.

### Web research

| Variable | Default | Notes |
|---|---|---|
| `SEARCH_PROVIDER` | `auto` | `auto`, `brave`, `tavily`, `duckduckgo`, `wikipedia` |
| `BRAVE_API_KEY`, `TAVILY_API_KEY` | empty | Optional free keys |
| `GITHUB_TOKEN` | empty | Optional; raises GitHub search limits |
| `SEARCH_TIMEOUT_SECONDS` | `15` | Per search/fetch request |
| `FETCH_MAX_BYTES` | `2000000` | Download cap per `fetch_url` |
| `FETCH_MAX_CHARS` | `12000` | Default text returned per `fetch_url` |
| `CONFIRM_FETCH_URL` | `false` | ON = ask `y/N` before every `fetch_url` |
| `NVD_API_KEY` | empty | Optional; raises CVE-lookup rate limit |

### Terminal

| Variable | Default | Notes |
|---|---|---|
| `COMMAND_SHELL` | `auto` | `auto`, `powershell`, `cmd`, `bash` |
| `COMMAND_TIMEOUT_SECONDS` | `60` | Default timeout |
| `COMMAND_MAX_TIMEOUT_SECONDS` | `300` | Upper bound the model can request |
| `COMMAND_MAX_OUTPUT_BYTES` | `20000` | Output cap |
| `AUTO_APPROVE_SAFE_COMMANDS` | `false` | See [section 10](#10-the-terminal-tool-in-depth) |

### Workspace and memory

| Variable | Default | Notes |
|---|---|---|
| `WORKSPACE_DIR` | `workspace` | Folder the file tools are jailed to and commands start in. **Do not point this at a folder containing secrets or your whole home directory.** |
| `MAX_FILE_READ_BYTES` | `200000` | Per-file read cap |
| `MAX_FILE_WRITE_BYTES` | `1000000` | Per-write cap |
| `CONFIRM_FILE_WRITES` | `false` | ON = ask `y/N` before every write/edit |
| `MEMORY_FILE` | `logs/memory.json` | Notes file |

### Loop, logging, reports

| Variable | Code default | Notes |
|---|---|---|
| `MAX_TOOL_CALLS_PER_TASK` | `30` (`100` in example) | Hard cap per task |
| `MAX_TOOL_RESULT_CHARS` | `30000` | Larger tool results are cut |
| `MAX_HISTORY_MESSAGES` | `60` | Oldest whole turns are dropped beyond this |
| `LOG_FILE_PATH` | `logs/agent.log` | JSON-lines log |
| `REPORTS_DIR` | `logs/reports` | Where `save_report` / `generate_report` write |

---

## 13. Logs, reports and memory

**`logs/agent.log`** — one JSON object per line: tool calls with method, URL, status, approval result, blocked requests and reasons, and (for the terminal) the command text, exit code and whether it was auto-approved.

```json
{"tool": "get_page", "path": "/", "url": "https://your-site.example/", "method": "GET", "status": 200, "timestamp": "..."}
{"tool": "run_command", "approved": true, "auto": false, "shell": "bash", "command": "git --version", "exit_code": 0, "timed_out": false, "timestamp": "..."}
{"tool": "get_page", "blocked": true, "reason": "Blocked request to 'evil.com' — only 'your-site.example' is permitted.", "timestamp": "..."}
```

Authorization/Cookie/Set-Cookie headers and JSON keys such as `password`, `token`, `api_key`, `otp` are replaced with `***REDACTED***`. **Redaction is best-effort:** URLs, search queries and command text are logged as-is, so treat `logs/` as private and never commit it.

**Reports** — `generate_report` writes a Markdown file (`logs/reports/<name>.md`) with a severity table and findings sorted from critical to info; `save_report` writes raw JSON. Names may contain only letters, digits, `_` and `-`.

**Memory** — notes in `logs/memory.json` (max 300 notes, 2000 characters each). The 15 most recent notes are shown to the model at the start of every session, labelled as data. Don't store secrets in memory.

---

## 14. What data leaves your machine

| Data | Sent to | When |
|---|---|---|
| Your task, conversation history, **all tool results** (page text, file contents, command output) | Your LLM provider (Gemini / OpenRouter / Grok) | Every model call |
| Search queries | Brave / Tavily / DuckDuckGo / Wikipedia | `web_search`, `search_source` |
| Fetched URLs | The sites you fetch | `fetch_url` |
| Software names/versions from your site | NIST NVD | `lookup_cve` |
| Your target's hostname | Google Public DNS (`dns.google`) | `check_dns_records` |
| Requests | Your target site | Target tools |

Nothing is sent anywhere else, and there is no telemetry.

---

## 15. Testing

```bash
python selftest.py
```

The self-test needs **no API keys and no internet**. It starts a small local web server, points the agent at it, and runs 35 checks:

- registry consistency, Gemini schema validity, argument coercion;
- SSRF/URL validation (loopback, metadata IPs, IPv4-mapped IPv6, bad schemes/ports/credentials);
- file tools (read/write/append/replace/list/search, traversal, symlink escape, secret files, binary and oversize refusal, write confirmation);
- terminal (deny-list, safe-list, approve/reject, workspace cwd, scrubbed environment, exit codes, stderr, timeout, output truncation, auto-approve behaviour);
- memory (remember/recall/forget/summary);
- web tools (HTML→text, DuckDuckGo parsing, provider fallback, each free API's parsing via mocks, fetch/redirect/binary/size/SSRF-redirect handling);
- recon tools against the local site (tech stack, robots/security.txt, forms & endpoints, redirect chain, DNS review via mock, report generation);
- provider adapters (OpenAI-style and Gemini message shapes, retry on 429, API key never in URL/error text);
- the agent loop with a scripted fake model (multi-tool turns, crash isolation, session memory, repeated-call guard, tool-call limit, interrupt/error recovery, history compaction).

**Platform note:** the terminal tests call `bash`, so run the suite on Linux, macOS, WSL, or Windows with Git Bash on `PATH`.

**What the suite does *not* prove:** live calls to Gemini/OpenRouter/Grok (mocked), live Brave/Tavily/DuckDuckGo (parsers and fallback are tested, not the live services), and real PowerShell. Before relying on the agent, run one real end-to-end task with your own key.

**Run it after every change and before every release.** Example GitHub Actions workflow (`.github/workflows/tests.yml`):

```yaml
name: tests
on: [push, pull_request]
jobs:
  selftest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -r requirements.txt
      - run: python selftest.py
```

---

## 16. Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| `TARGET_BASE_URL is not set` | Create `.env` from `.env.example` and set it |
| `Missing GEMINI_API_KEY` (or other key) | Set the key for your selected `LLM_PROVIDER` in `.env` |
| `BLOCKED: Blocked request to 'localhost' …` / `resolves to a private … address` | Working as designed. Target must be a public host; use staging or a tunnel |
| `BLOCKED: Blocked request to 'other.com' — only '…' is permitted` | The model tried to reach another domain with a target tool. Use `fetch_url` for public research |
| `HTTP 429` from the LLM | Free-tier rate limit. The agent retries automatically; if it persists, wait or switch model/provider |
| `HTTP 400` mentioning function declarations / tools | The chosen `MODEL` doesn't support tool calling. Use a function-calling model (e.g. `gemini-2.5-flash`) |
| OpenRouter `HTTP 404 … support tool use` | Pick a `:free` model that supports tools |
| `Gemini returned an empty response (finishReason=…)` | Model produced an invalid call. Rephrase the task, or `/reset` and retry |
| Agent loops, repeats itself or stalls | Common with weaker free models. `/reset`, simplify the task, or use a stronger model. Identical calls are blocked after two repeats |
| `All search providers failed` | DuckDuckGo may be rate-limiting you. Add a free Brave or Tavily key, or set `SEARCH_PROVIDER=wikipedia` |
| `PowerShell not found on PATH` | Install PowerShell 7 (`pwsh`) or set `COMMAND_SHELL=cmd` on Windows / `bash` elsewhere |
| `Activate.ps1 cannot be loaded` (Windows) | `Set-ExecutionPolicy -Scope Process Bypass`, then activate again |
| Garbled characters in the Windows console | `$env:PYTHONUTF8 = "1"` before starting |
| `Command … BLOCKED by policy` | The deny-list refused it. Choose another approach or run it yourself outside the agent |
| `Tool '…' crashed` | A bug. Check `logs/agent.log` and open an issue with the traceback-free message and steps to reproduce |
| `selftest.py` fails on Windows | Terminal tests require `bash`; use WSL/Git Bash |

---

## 17. Extending the agent

### Add a tool

1. Write the function (return a `dict`; return `{"error": "..."}` on failure; validate every argument; never trust input):

   ```python
   # in a module of your choice, e.g. my_tools.py
   import security

   def tool_word_count(path: str) -> dict:
       ...
       return {"path": path, "words": 123}
   ```

2. Describe it for the model with a JSON schema and map it to the function:

   ```python
   DEFINITIONS = [{
       "name": "word_count",
       "description": "Count words in a workspace text file.",
       "parameters": {
           "type": "object",
           "properties": {"path": {"type": "string", "description": "Workspace-relative path."}},
           "required": ["path"],
       },
   }]
   IMPLEMENTATIONS = {"word_count": lambda a: tool_word_count(a.get("path", ""))}
   ```

3. Register it at the bottom of `tools.py` (see the existing `_register_group(...)` calls), ideally behind an `ENABLE_*` flag in `config.py`.
4. Add checks to `selftest.py`.
5. Mention it in the README tool tables.

**Schema rules that keep every provider happy:** every property needs a `type`; an `object` parameter needs real `properties` (otherwise Gemini rejects it — the adapter works around this by sending JSON strings, but explicit schemas are better); use `enum` only for strings.

**Design rules for new tools:** anything that touches the network must go through `security.py`; anything that touches disk must stay in the workspace jail; anything with side effects should ask a human; output must be size-capped.

### Add an LLM provider

All provider logic lives in `llm_provider.py` behind one function:

```python
chat(messages) -> {"text": str | None, "tool_calls": [{"id", "name", "arguments"}], "raw": ...}
```

For OpenAI-compatible services (Ollama, LM Studio, Together, Groq, etc.), add an entry to `_OPENAI_COMPATIBLE_ENDPOINTS` plus its key handling in `_chat_openai_compatible`; otherwise write a `_chat_<provider>` function that converts the internal message list and normalises the response, add a branch in `chat()`, and set `LLM_PROVIDER` in `.env`. (Additional providers are not tested by the author.)

---

## 18. Known limitations

- **The terminal deny-list is not a sandbox** and commands are not jailed to the workspace ([section 10](#10-the-terminal-tool-in-depth)).
- **DNS rebinding:** hostnames are resolved and checked, then the HTTP library resolves again to connect. A hostile DNS server could in theory return a public IP first and a private one second. The redirect and IP checks make this hard but not impossible; do not point `fetch_url` at hosts you don't trust with an attacker-controlled DNS setup.
- **Localhost targets are blocked by design.**
- **Heuristic findings:** fingerprints and issue flags are pattern matches; verify manually.
- **JSON/form POSTs only:** the target tools are deliberately not a general HTTP client.
- **Single target host:** exactly one hostname per run.
- **No JavaScript rendering:** `fetch_url` and the recon tools see server-returned HTML, not what a browser builds at runtime.
- **Free-tier realities:** quotas, small context windows, and models that call tools poorly.
- **Not tested live by the maintainers of this document:** real PowerShell, Brave/Tavily/DuckDuckGo live endpoints, and live LLM provider calls (all covered by mocks/parsers only).

---

## 19. FAQ

**Why does it refuse to test my localhost server?** The private-IP block is what makes the domain lock trustworthy (otherwise a DNS entry or redirect could point "your domain" at an internal service). It cannot be turned off from `.env`.

**Why is the terminal tool included at all if it's dangerous?** Because many real tasks need it (running tests, checking versions). It's gated the way a careful teammate would be: shown to you, approved by you, limited in time and output, and stripped of your keys.

**Can I make it fully autonomous?** Not for the terminal, by design. You can reduce prompts for the target site (`ENABLE_CONFIRMATION_PROMPT`, `AUTO_APPROVE_POST_PATHS`) and read-only commands (`AUTO_APPROVE_SAFE_COMMANDS`), but arbitrary commands always need you.

**Does it store my data?** Locally: logs, reports, memory notes and workspace files, all on your disk. Remotely: see [section 14](#14-what-data-leaves-your-machine).

**Can I use a local model?** Not built in. If your local server exposes an OpenAI-compatible API (many do), see [Add an LLM provider](#add-an-llm-provider). The model must support tool calling.

**Which model should I use?** Any function-calling model works, but stronger models follow multi-step tool plans far more reliably. Weak free models may loop or misuse tools.

**Is it a pen-testing tool?** No. It performs passive, read-only checks of a site you control and refuses exploitation. See [section 1](#1-what-this-is-and-is-not).

---

## 20. Contributing

Contributions are welcome — bug reports, tests, docs, provider adapters and new **safe** tools.

**Before opening a pull request**
1. Run `python selftest.py` — all checks must pass.
2. Add tests for new behaviour (especially anything security-relevant).
3. Follow the design rules in [Extending the agent](#17-extending-the-agent).
4. Update this README if you change behaviour, settings or tools.

**What will not be accepted** (these would undo the project's purpose)
- Exploitation, credential harvesting, authentication bypass, port scanning, brute forcing, or DoS capabilities.
- An unrestricted shell or code-execution tool with no human approval.
- Any way to disable the domain lock, the private-IP block, the workspace jail, or the terminal deny-list from configuration or from the model.
- Tools that send local data to third parties without clear disclosure and consent.

**Style:** small readable functions, explicit error dicts (never raise into the loop), limits on sizes/timeouts, comments that explain *why*.

---

## 21. Reporting security issues

If you find a way around the domain lock, SSRF checks, workspace jail, deny-list or approval flow, please **do not open a public issue**. Report it privately through the repository's **Security → Report a vulnerability** page (maintainers: enable *Private vulnerability reporting* in the repo settings) and include steps to reproduce. Please allow reasonable time for a fix before public disclosure.

---

## License

See the [`LICENSE`](LICENSE) file in this repository.

---

## Disclaimer

This software is provided "as is", without warranty of any kind. It is a research and development aid, not a security guarantee. The authors and contributors are not responsible for any damage, data loss, cost, policy violation or legal consequence arising from its use. Test only systems you own or are explicitly authorised to test.
