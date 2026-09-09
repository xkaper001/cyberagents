"""Embedded default LLM credentials.

Values load from a `.env` file next to this module (see `.env.example`).
The `.env` is gitignored so keys never enter source control. When packaging
the exe, ship a `.env` alongside — or leave it out and require users to set
LLM_* env vars / their own config.json (see llm.py precedence).

Ship a low-privilege, rate-limited, rotatable key ONLY. Anything bundled in a
binary is extractable (strings/decompile). This module's values are never
printed to the user.
"""
import os
import sys


def _load_dotenv(path):
    """Tiny KEY=VALUE parser. stdlib only, no python-dotenv dependency."""
    out = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return out


def _find_env():
    # 1. Next to the executable if running as a frozen PyInstaller bundle
    if getattr(sys, "frozen", False):
        exe_env = os.path.join(os.path.dirname(sys.executable), ".env")
        if os.path.exists(exe_env):
            return exe_env
    # 2. Next to this file / extracted _MEIPASS directory
    return os.path.join(os.path.dirname(__file__), ".env")


_env = _load_dotenv(_find_env())

EMBEDDED = {
    "base_url": _env.get("LLM_BASE_URL", ""),
    "api_key": _env.get("LLM_API_KEY", ""),
    "model": _env.get("LLM_MODEL", ""),
}
