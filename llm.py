"""OpenAI-compatible chat client. Stdlib only (no deps -> clean exe).

Config precedence (highest first):
  1. user config file  ~/.cyberagents/config.json   (user's own endpoint/key)
  2. env vars          LLM_BASE_URL / LLM_API_KEY / LLM_MODEL
  3. embedded default  (shipped in the exe; never shown to the user)
"""
import json
import os
import urllib.request
import urllib.error

from secrets_embedded import EMBEDDED

CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".cyberagents", "config.json")


def _load_user_file():
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def resolve_config():
    """Merge sources by precedence. Returns dict base_url/api_key/model + 'source'."""
    cfg = dict(EMBEDDED)
    source = "embedded (default)"

    env = {
        "base_url": os.environ.get("LLM_BASE_URL"),
        "api_key": os.environ.get("LLM_API_KEY"),
        "model": os.environ.get("LLM_MODEL"),
    }
    if any(env.values()):
        cfg.update({k: v for k, v in env.items() if v})
        source = "environment variables"

    user = _load_user_file()
    if user:
        cfg.update({k: v for k, v in user.items() if k in cfg and v})
        source = f"user config ({CONFIG_PATH})"

    cfg["source"] = source
    return cfg


def save_user_config(base_url, model, api_key=None):
    """Write the user's own config. api_key optional (blank keeps none)."""
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    data = {"base_url": base_url, "model": model}
    if api_key:
        data["api_key"] = api_key
    with open(CONFIG_PATH, "w") as f:
        json.dump(data, f, indent=2)
    try:
        os.chmod(CONFIG_PATH, 0o600)  # user's own key -> restrict
    except OSError:
        pass
    return CONFIG_PATH


def clear_user_config():
    """Delete user config -> fall back to env/embedded default."""
    try:
        os.remove(CONFIG_PATH)
        return True
    except OSError:
        return False


def _mask(key):
    if not key:
        return "(none)"
    if len(key) <= 8:
        return "****"
    return key[:4] + "…" + key[-2:]


def describe():
    """Human-readable config summary. NEVER reveals a full key (embedded or user)."""
    c = resolve_config()
    return (f"  source:   {c['source']}\n"
            f"  base_url: {c['base_url']}\n"
            f"  model:    {c['model']}\n"
            f"  api_key:  {_mask(c.get('api_key'))}")


class LLM:
    def __init__(self):
        c = resolve_config()
        self.base_url = c["base_url"].rstrip("/")
        self.api_key = c.get("api_key") or ""
        self.model = c["model"]

    def chat(self, system, user, temperature=0.2, timeout=120):
        body = json.dumps({
            "model": self.model,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }).encode()
        headers = {"Content-Type": "application/json", "User-Agent": "CyberAgents/1.0"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions", data=body, headers=headers, method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = json.loads(r.read())
            return data["choices"][0]["message"]["content"]
        except urllib.error.URLError as e:
            return f"[LLM ERROR] Could not reach {self.base_url}: {e}"
        except (KeyError, json.JSONDecodeError) as e:
            return f"[LLM ERROR] Unexpected response shape: {e}"


if __name__ == "__main__":
    # self-check: precedence + masking never leaks a full key
    os.environ["LLM_BASE_URL"] = "http://env-test/v1"
    c = resolve_config()
    assert c["base_url"] == "http://env-test/v1", "env should override embedded"
    assert c["source"] == "environment variables"
    assert _mask("sk-abcdef1234") == "sk-a…34"
    assert _mask("") == "(none)"
    assert EMBEDDED["api_key"] not in describe(), "embedded key must never appear"
    del os.environ["LLM_BASE_URL"]
    print("llm config self-check ok")
    print(describe())
