"""Detect and (optionally) install the pentest tools the advisor recommends.
Windows: winget or choco. macOS (dev): brew. Read-only nmap runner included."""
import platform
import re
import shutil
import subprocess


def normalize_target(target):
    """Reduce a user-typed target to a bare host nmap can scan.

    nmap wants a hostname/IP, not a URL. Users paste `https://google.com/path`
    (or a `https;//` typo) and nmap reports 0 hosts up. Strip scheme, userinfo,
    path/query, and any :port; keep bracketed IPv6 intact.
    """
    t = (target or "").strip()
    t = re.sub(r"^(\w+)\s*[;:]//", r"\1://", t)   # fix `https;//` typo -> `https://`
    t = re.sub(r"^\w+://", "", t)                  # drop scheme
    t = re.split(r"[/?#]", t, maxsplit=1)[0]        # drop path/query/fragment
    t = t.rsplit("@", 1)[-1]                        # drop userinfo
    if t.startswith("["):                          # [ipv6]:port -> ipv6
        return t[1:].split("]", 1)[0]
    if t.count(":") == 1:                          # host:port -> host (raw ipv6 has >1)
        t = t.split(":", 1)[0]
    return t

# name -> project homepage (shown as a clickable link in the tools dialog)
HOMEPAGES = {
    "nmap":       "https://nmap.org",
    "metasploit": "https://www.metasploit.com",
    "sqlmap":     "https://sqlmap.org",
    "whois":      "https://github.com/rfc1036/whois",
    "dig":        "https://www.isc.org/bind/",
}

# name -> (command on PATH, winget id, choco id, brew id)
TOOLS = {
    "nmap":       ("nmap",       "Insecure.Nmap",                "nmap",           "nmap"),
    "metasploit": ("msfconsole", "Rapid7.Metasploit",            "metasploit",     "metasploit"),
    "sqlmap":     ("sqlmap",     "sqlmapproject.sqlmap",         "sqlmap",         "sqlmap"),
    "whois":      ("whois",      "Microsoft.Sysinternals.Whois", "whois",          "whois"),
    "dig":        ("dig",        "ISC.BIND",                     "bind-toolsonly", "bind"),
}


def status():
    """Return {tool: bool_installed}."""
    return {name: shutil.which(spec[0]) is not None for name, spec in TOOLS.items()}


def _installer_cmd(name):
    _, winget_id, choco_id, brew_id = TOOLS[name]
    system = platform.system()
    if system == "Windows":
        if shutil.which("winget"):
            return ["winget", "install", "-e", "--id", winget_id]
        if shutil.which("choco"):
            return ["choco", "install", "-y", choco_id]
        return None
    if system == "Darwin" and shutil.which("brew"):
        return ["brew", "install", brew_id]
    return None


MSF_OMNIBUS = (
    "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/"
    "config/templates/metasploit-framework-wrappers/msfupdate.erb "
    "> msfinstall && chmod 755 msfinstall && ./msfinstall"
)


def install(name):
    """Attempt install. Returns (ok, message)."""
    # Metasploit on macOS/Linux: use Rapid7's omnibus installer (brew is flaky).
    # NOTE: it uses sudo and may prompt for a password — run from a terminal if
    # a GUI button appears to hang. Windows still uses winget/choco below.
    if name == "metasploit" and platform.system() != "Windows":
        print("  running metasploit omnibus installer (may prompt for sudo)...")
        try:
            subprocess.run(MSF_OMNIBUS, shell=True, check=True)
            return shutil.which("msfconsole") is not None, "done (may need a new shell for PATH)"
        except subprocess.CalledProcessError as e:
            return False, f"omnibus installer failed: {e}"

    cmd = _installer_cmd(name)
    if cmd is None:
        return False, f"No package manager found for {name}. Install manually."
    print(f"  running: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True)
        return shutil.which(TOOLS[name][0]) is not None, "done"
    except subprocess.CalledProcessError as e:
        return False, f"installer failed: {e}"


def run_nmap(target, args=None):
    """Read-only service scan. Returns stdout (or error)."""
    if not shutil.which("nmap"):
        return "[nmap not installed]"
    host = normalize_target(target)
    if not host:
        return "[no target]"
    cmd = ["nmap"] + (args or ["-sV", "-T4", "--top-ports", "100"]) + [host]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return out.stdout or out.stderr
    except subprocess.TimeoutExpired:
        return "[nmap timed out]"


def run_whois(target):
    """Query WHOIS for a target if installed. Returns stdout (or error/not installed)."""
    if not shutil.which("whois"):
        return "[whois not installed]"
    host = normalize_target(target)
    if not host:
        return "[no target]"
    try:
        out = subprocess.run(["whois", host], capture_output=True, text=True, timeout=20)
        return out.stdout or out.stderr or "[no whois output]"
    except subprocess.TimeoutExpired:
        return "[whois timed out]"
    except Exception as e:
        return f"[whois error: {e}]"


def run_dig(target, qtype="ANY"):
    """Run DNS query with dig if installed. Returns stdout (or error/not installed)."""
    if not shutil.which("dig"):
        return "[dig not installed]"
    host = normalize_target(target)
    if not host:
        return "[no target]"
    try:
        out = subprocess.run(["dig", "+nocmd", host, qtype, "+multiline", "+noall", "+answer"],
                             capture_output=True, text=True, timeout=15)
        return out.stdout or out.stderr or "[no dig output]"
    except subprocess.TimeoutExpired:
        return "[dig timed out]"
    except Exception as e:
        return f"[dig error: {e}]"


if __name__ == "__main__":
    print(status())
    assert set(status()) == set(TOOLS)
    assert normalize_target("https://google.com/path?q=1") == "google.com"
    assert normalize_target("https;//google.com") == "google.com"
    assert normalize_target("http://user@vtop.vitbhopal.ac.in:8080/x") == "vtop.vitbhopal.ac.in"
    assert normalize_target("google.com") == "google.com"
    assert normalize_target("10.0.0.1:443") == "10.0.0.1"
    assert normalize_target("[2001:db8::1]:80") == "2001:db8::1"
    print("normalize_target ok")
