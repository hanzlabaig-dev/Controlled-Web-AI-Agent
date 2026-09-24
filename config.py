"""
config.py — Central configuration and safety limits.

All tunable safety limits live here so they are easy to audit and change
in one place. Nothing in this file executes network requests.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Provider configuration (swappable: gemini | openrouter | grok)
# ---------------------------------------------------------------------------
# LLM_PROVIDER selects which free-tier provider to use. The agent loop and
# tool-calling logic are provider-agnostic; only llm_provider.py needs to
# change if you add a new provider.
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "gemini").strip().lower()

# Generic model name — meaning depends on provider (see llm_provider.py):
#   gemini     -> e.g. "gemini-2.5-flash" / "gemini-2.5-flash-lite"
#   openrouter -> e.g. "meta-llama/llama-3.1-8b-instruct:free"
#   grok       -> e.g. "grok-beta" (xAI free/trial tier, if available)
MODEL = os.getenv("MODEL", "gemini-2.5-flash")

# API keys — only the one matching LLM_PROVIDER needs to be set.
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
GROK_API_KEY = os.getenv("GROK_API_KEY", "")

# ---------------------------------------------------------------------------
# Target website — the ONLY domain the agent may ever contact
# ---------------------------------------------------------------------------
TARGET_BASE_URL = os.getenv("TARGET_BASE_URL", "").strip()

# ---------------------------------------------------------------------------
# Safety limits (all enforced in Python, never trusted to the LLM)
# ---------------------------------------------------------------------------
REQUEST_TIMEOUT_SECONDS = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "30"))
MAX_RESPONSE_BYTES = int(os.getenv("MAX_RESPONSE_BYTES", "100000"))          # truncate response bodies
MAX_TOOL_CALLS_PER_TASK = int(os.getenv("MAX_TOOL_CALLS_PER_TASK", "30"))
MAX_POST_BODY_BYTES = int(os.getenv("MAX_POST_BODY_BYTES", "50000"))
MIN_SECONDS_BETWEEN_REQUESTS = float(os.getenv("MIN_SECONDS_BETWEEN_REQUESTS", "0.3"))

LOG_FILE_PATH = os.getenv("LOG_FILE_PATH", "logs/agent.log")

# Scoped "filesystem" access: the ONLY directory the agent may ever write
# to for reports. Not configurable to an arbitrary path from the LLM side —
# tools.py always joins report names under this fixed directory and
# rejects any name that tries to escape it (../, absolute paths, etc.).
REPORTS_DIR = os.getenv("REPORTS_DIR", "logs/reports")

# Public vulnerability-database lookup (NVD). This is a read-only,
# external KNOWLEDGE lookup — not a request to TARGET_BASE_URL — so it is
# intentionally exempt from the single-domain lock, the same way a person
# consulting a CVE database while testing their own site would be.
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY", "")  # optional, raises NVD's rate limit

# ---------------------------------------------------------------------------
# TOGGLE PANEL — explicit ON/OFF switches for the settings that are safe to
# adjust. Each one is named ENABLE_* so its state is unambiguous. These only
# affect confirmation prompts, rate limiting, and redirect handling.
#
# NOT included here, and NOT toggleable by any setting, ever:
#   - the single-domain lock (security.py: validate_url / build_target_url)
#   - the private/loopback/link-local/reserved IP block, which also covers
#     cloud metadata endpoints (security.py: _is_private_or_dangerous_ip)
#   - the file:// / javascript: / data: scheme block
#   - the system prompt's refusal of credential harvesting, auth bypass,
#     and exploitation techniques (agent.py)
# These stay hardcoded regardless of provider, domain, or any .env value,
# because they're what makes the domain lock actually hold under redirects
# and DNS tricks rather than being cosmetic.
# ---------------------------------------------------------------------------

# ON  -> every POST/PUT/PATCH/DELETE prints the request and waits for y/N.
# OFF -> those requests fire immediately with no prompt (still domain-locked).
ENABLE_CONFIRMATION_PROMPT = os.getenv("ENABLE_CONFIRMATION_PROMPT", "false").strip().lower() == "true"

# ON  -> agent waits MIN_SECONDS_BETWEEN_REQUESTS between requests.
# OFF -> no delay between requests.
ENABLE_RATE_LIMIT = os.getenv("ENABLE_RATE_LIMIT", "false").strip().lower() == "true"

# ON  -> a same-domain redirect is reported back, requiring a fresh tool call.
# OFF -> same-domain redirects (only) are followed automatically.
ENABLE_REDIRECT_CONFIRMATION = os.getenv("ENABLE_REDIRECT_CONFIRMATION", "false").strip().lower() == "true"
AUTO_FOLLOW_REDIRECTS = not ENABLE_REDIRECT_CONFIRMATION
AUTO_REDIRECT_MAX_HOPS = int(os.getenv("AUTO_REDIRECT_MAX_HOPS", "5"))

# Path prefixes that skip the confirmation prompt even when
# ENABLE_CONFIRMATION_PROMPT=true (useful for approving just one or two
# test endpoints while keeping the prompt on for everything else).
# "/" matches every path. Ignored entirely when the prompt is OFF.
_auto_approve_raw = os.getenv("AUTO_APPROVE_POST_PATHS", "/")
AUTO_APPROVE_POST_PATHS = [p.strip() for p in _auto_approve_raw.split(",") if p.strip()]

# ---------------------------------------------------------------------------
# v2 ADDITIONS — web search, terminal (human-approved), workspace files,
# memory, recon tools. Each group can be switched off with one flag.
# ---------------------------------------------------------------------------
def _flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


ENABLE_WEB_TOOLS = _flag("ENABLE_WEB_TOOLS", True)          # web_search, search_source, fetch_url
ENABLE_TERMINAL_TOOL = _flag("ENABLE_TERMINAL_TOOL", True)  # run_command (human approval)
ENABLE_FILE_TOOLS = _flag("ENABLE_FILE_TOOLS", True)        # read/write/list/search inside WORKSPACE_DIR
ENABLE_MEMORY_TOOLS = _flag("ENABLE_MEMORY_TOOLS", True)    # remember / recall / forget
ENABLE_RECON_TOOLS = _flag("ENABLE_RECON_TOOLS", True)      # dns, tech stack, robots, forms, redirects, report

# --- Web search (all free options) -----------------------------------------
# auto = Brave (if key) -> Tavily (if key) -> DuckDuckGo (no key) -> Wikipedia
SEARCH_PROVIDER = os.getenv("SEARCH_PROVIDER", "auto").strip().lower()
BRAVE_API_KEY = os.getenv("BRAVE_API_KEY", "")       # free tier: https://brave.com/search/api/
TAVILY_API_KEY = os.getenv("TAVILY_API_KEY", "")     # free tier: https://tavily.com
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")         # optional, raises GitHub search rate limit
SEARCH_TIMEOUT_SECONDS = int(os.getenv("SEARCH_TIMEOUT_SECONDS", "15"))

# fetch_url: read-only GET of any PUBLIC page (private/metadata IPs always blocked)
FETCH_MAX_BYTES = int(os.getenv("FETCH_MAX_BYTES", "2000000"))
FETCH_MAX_CHARS = int(os.getenv("FETCH_MAX_CHARS", "12000"))
CONFIRM_FETCH_URL = _flag("CONFIRM_FETCH_URL", False)  # ON = ask y/N before every fetch_url

# --- Terminal tool -----------------------------------------------------------
# Every command needs a human y/N unless AUTO_APPROVE_SAFE_COMMANDS=true AND
# the command is on the tiny read-only allow-list (no pipes/redirects).
COMMAND_SHELL = os.getenv("COMMAND_SHELL", "auto").strip().lower()   # auto|powershell|cmd|bash
COMMAND_TIMEOUT_SECONDS = int(os.getenv("COMMAND_TIMEOUT_SECONDS", "60"))
COMMAND_MAX_TIMEOUT_SECONDS = int(os.getenv("COMMAND_MAX_TIMEOUT_SECONDS", "300"))
COMMAND_MAX_OUTPUT_BYTES = int(os.getenv("COMMAND_MAX_OUTPUT_BYTES", "20000"))
AUTO_APPROVE_SAFE_COMMANDS = _flag("AUTO_APPROVE_SAFE_COMMANDS", False)

# --- Workspace (file tools + terminal working directory) ---------------------
WORKSPACE_DIR = os.getenv("WORKSPACE_DIR", "workspace")
MAX_FILE_READ_BYTES = int(os.getenv("MAX_FILE_READ_BYTES", "200000"))
MAX_FILE_WRITE_BYTES = int(os.getenv("MAX_FILE_WRITE_BYTES", "1000000"))
CONFIRM_FILE_WRITES = _flag("CONFIRM_FILE_WRITES", False)

# --- Memory -------------------------------------------------------------------
MEMORY_FILE = os.getenv("MEMORY_FILE", "logs/memory.json")

# --- Agent loop ---------------------------------------------------------------
MAX_TOOL_RESULT_CHARS = int(os.getenv("MAX_TOOL_RESULT_CHARS", "30000"))
MAX_HISTORY_MESSAGES = int(os.getenv("MAX_HISTORY_MESSAGES", "60"))
LLM_MAX_RETRIES = int(os.getenv("LLM_MAX_RETRIES", "3"))

# Headers that must never be logged or shown, regardless of source.
SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "proxy-authorization",
}

SENSITIVE_JSON_KEYS = {
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "session",
    "otp",
}
