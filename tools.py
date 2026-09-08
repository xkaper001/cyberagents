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

# name -> (command on PATH, winget id, choco id, brew id)
TOOLS = {
    "nmap":       ("nmap",       "Insecure.Nmap",        "nmap",       "nmap"),
    "metasploit": ("msfconsole", "Rapid7.Metasploit",    "metasploit", "metasploit"),
    "sqlmap":     ("sqlmap",     "sqlmapproject.sqlmap", "sqlmap",     "sqlmap"),
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
