"""Scanning phase: port/service scan (nmap) with script scan options,
recon focus integration, and LLM-powered service/version analysis.
Feeds into later agents (e.g. exploitation).
"""
import datetime
import os
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

if __package__ is None or __package__ == "":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.base import Agent
import llm
from llm import LLM
import tools

SYSTEM_PROMPT = """You are a penetration-testing scanning analysis AGENT for \
authorized/lab targets only. You analyze raw nmap scan results and structure them \
into a clear, actionable service map and vulnerability/version analysis for the pentest team.

Given a target and its nmap scan output (along with any prior reconnaissance context), \
produce a markdown summary with EXACTLY the following structure:

## Open ports/services
A markdown table with columns:
| Port | Protocol | State | Service | Version |
List every open or filtered port identified in the scan. If no open ports are found or the scan is empty, state so clearly in the table.

## Version notes
Bullet points describing notable software versions identified, end-of-life or legacy indicators, \
software banners, configuration details, and any findings revealed by nmap scripts.

## Interesting findings for exploitation
Actionable items and potential attack vectors to guide the exploitation phase:
- Potential weaknesses, exposed administrative interfaces, unauthenticated services, or default credentials to check.
- High-priority services/ports to investigate further.
- Specific CVEs, vulnerabilities, or exploitation tools/modules suggested by the versions or script output.

Be precise, objective, and faithful to the scan output. Do not hallucinate open ports or services \
not present in the raw scan."""


def _extract_recon_focus(prior: Optional[Dict[str, Any]]) -> Tuple[Optional[str], bool, bool]:
    """Inspect prior phase data (e.g. recon) to extract recommended ports and script scan flags.

    Returns (ports_str, script_scan, vuln_scan).
    """
    if not prior:
        return None, False, False

    recon_text = ""
    for k, v in prior.items():
        if "recon" in k.lower() and isinstance(v, str):
            recon_text += "\n" + v

    if not recon_text:
        return None, False, False

    ports: List[str] = []

    # Check for specific ports mentioned in recommended scan focus or general recon text
    # Matches patterns like "ports 80, 443, 8080", "port 22", "80/tcp", "p: 80,443"
    focus_match = re.search(r"##\s*Recommended scan focus.*?(?=\n##|\Z)", recon_text, re.DOTALL | re.IGNORECASE)
    search_scope = focus_match.group(0) if focus_match else recon_text

    port_patterns = [
        r"\b(?:ports?|p(?:ort)?s?)\s*[:=]?\s*([0-9,\s/-]+)\b",
        r"\b([0-9]{1,5})\s*/\s*(?:tcp|udp)\b",
    ]

    for pat in port_patterns:
        for match in re.finditer(pat, search_scope, re.IGNORECASE):
            raw = match.group(1)
            # Extract individual port numbers
            for num in re.findall(r"\b\d{1,5}\b", raw):
                if 1 <= int(num) <= 65535 and num not in ports:
                    ports.append(num)

    ports_str = ",".join(ports) if ports else None

    # Check if script scans or vulnerability scans were recommended
    vuln_scan = bool(re.search(r"\b(?:vuln\w*|cve\w*|exploit\w*)\b", search_scope, re.IGNORECASE))
    script_scan = vuln_scan or bool(re.search(r"\b(?:script\w*|-sC|nse|default\s+scripts?)\b", search_scope, re.IGNORECASE))

    return ports_str, script_scan, vuln_scan


def run_scan(
    target: str,
    args: Optional[List[str]] = None,
    script_scan: bool = False,
    vuln_scan: bool = False,
    ports: Optional[str] = None,
) -> str:
    """Return nmap service-scan text for a target.

    If `args` is provided, it is passed directly to tools.run_nmap.
    Otherwise, builds arguments using service scan (-sV) with options for:
      - `script_scan`: adds '-sC' (default script scan)
      - `vuln_scan`: adds '--script vuln' (vulnerability scripts)
      - `ports`: comma-separated port list or range (e.g. '80,443' or '1-1000')
    """
    if args is not None:
        return tools.run_nmap(target, args)

    cmd_args = ["-sV", "-T4"]

    if ports:
        cmd_args.extend(["-p", str(ports)])
    else:
        cmd_args.extend(["--top-ports", "100"])

    if vuln_scan:
        cmd_args.extend(["--script", "vuln"])
    elif script_scan:
        cmd_args.append("-sC")

    return tools.run_nmap(target, cmd_args)


def run_scanning(
    target: str,
    prior: Optional[Dict[str, Any]] = None,
    script_scan: bool = False,
    vuln_scan: bool = False,
    ports: Optional[str] = None,
    progress=None,
) -> str:
    """Run nmap scan, taking recon's scan focus from prior if available,
    and LLM-summarize into structured markdown.

    Returns the markdown summary followed by the raw scan fenced in ```.
    """
    # If parameters not explicitly specified, inspect recon in prior context
    recon_ports, recon_script, recon_vuln = _extract_recon_focus(prior)
    effective_ports = ports or recon_ports
    effective_script = script_scan or recon_script
    effective_vuln = vuln_scan or recon_vuln

    # Run nmap scan
    if progress:
        progress(0.05, "running nmap scan")
    raw_scan = run_scan(
        target,
        script_scan=effective_script,
        vuln_scan=effective_vuln,
        ports=effective_ports,
    )
    if progress:
        progress(0.65, "LLM analysis")

    # Build prompt for LLM summary
    prompt_parts = [
        f"TARGET: {target}",
        f"\nNMAP SCAN OUTPUT:\n{raw_scan or '(no scan output)'}",
    ]

    if prior:
        for phase, out in prior.items():
            if out and isinstance(out, str) and out.strip():
                prompt_parts.append(f"\nPRIOR PHASE — {phase.upper()} CONTEXT:\n{out.strip()}")

    user_prompt = "\n".join(prompt_parts)
    summary = llm.LLM().chat(SYSTEM_PROMPT, user_prompt)

    # Combine LLM summary with raw scan fence
    return f"{summary}\n\n## Raw Nmap Scan\n```\n{raw_scan}\n```"


def save_report(target: str, content: str) -> str:
    """Write a markdown report, return its path."""
    os.makedirs("reports", exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    safe = target.replace("/", "_").replace(":", "_")
    path = os.path.join("reports", f"scan-{safe}-{ts}.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# Scanning phase report\n\n- Target: {target}\n- Time: {ts}\n\n{content}\n")
    return path


class ScanningAgent(Agent):
    name = "scanning"
    description = "Port/service scan with nmap, script scans, and LLM-assisted service/version analysis."

    def run(self, target: str) -> None:
        self._ensure_tools()
        print(f"[*] Scanning target: {target}")
        print("Scan options:")
        print("  [1] Standard service scan (-sV -T4 --top-ports 100)")
        print("  [2] Service scan with default scripts (-sV -sC -T4 --top-ports 100)")
        print("  [3] Vulnerability script scan (-sV --script vuln -T4 --top-ports 100)")
        print("  [4] Custom ports (e.g. 80,443,8080)")
        opt = input("Select scan type [1]: ").strip()

        script_scan = False
        vuln_scan = False
        ports = None

        if opt == "2":
            script_scan = True
        elif opt == "3":
            vuln_scan = True
        elif opt == "4":
            ports = input("Enter ports (comma-separated, e.g. 21,22,80,443): ").strip() or None
            s_opt = input("Include script scans (-sC)? [y/N]: ").strip().lower()
            if s_opt in ("y", "yes"):
                script_scan = True

        print("  running scan and analyzing with LLM (this may take a minute)...")
        result = run_scanning(target, script_scan=script_scan, vuln_scan=vuln_scan, ports=ports)
        print("\n" + result)
        path = save_report(target, result)
        print(f"\nReport saved: {path}")

    def _ensure_tools(self) -> None:
        st = tools.status()
        if not st.get("nmap", False):
            print("Missing tool: nmap")
            if input("Install nmap now? [y/N]: ").strip().lower() in ("y", "yes"):
                ok, msg = tools.install("nmap")
                print(f"  nmap: {'installed' if ok else 'FAILED'} ({msg})")


if __name__ == "__main__":
    # Self-test: check focus extraction and mocked scanning output
    print("Running scanning agent self-tests...")

    # 1. Test focus extraction from recon
    mock_prior = {
        "recon": (
            "## Assets found\n- domain.local\n\n"
            "## Recommended scan focus\n"
            "Focus on web ports 80, 443, 8080 and ssh port 22. Run vulnerability script scan."
        )
    }
    extracted_ports, extracted_script, extracted_vuln = _extract_recon_focus(mock_prior)
    assert extracted_ports == "80,443,8080,22", f"Unexpected ports extracted: {extracted_ports}"
    assert extracted_script is True, "Expected script scan to be True"
    assert extracted_vuln is True, "Expected vuln scan to be True"
    print("  [OK] Recon focus extraction test passed")

    # 2. Test run_scan argument construction
    # Mock tools.run_nmap temporarily
    original_run_nmap = tools.run_nmap
    captured_args = {}

    def mock_run_nmap(target, args=None):
        captured_args["target"] = target
        captured_args["args"] = args
        return "PORT   STATE SERVICE VERSION\n80/tcp open  http    Apache httpd 2.4.49"

    tools.run_nmap = mock_run_nmap

    try:
        # Default scan
        out = run_scan("127.0.0.1")
        assert captured_args["args"] == ["-sV", "-T4", "--top-ports", "100"]

        # Script scan
        out = run_scan("127.0.0.1", script_scan=True)
        assert captured_args["args"] == ["-sV", "-T4", "--top-ports", "100", "-sC"]

        # Vuln scan
        out = run_scan("127.0.0.1", vuln_scan=True)
        assert captured_args["args"] == ["-sV", "-T4", "--top-ports", "100", "--script", "vuln"]

        # Custom ports + script
        out = run_scan("127.0.0.1", ports="80,443", script_scan=True)
        assert captured_args["args"] == ["-sV", "-T4", "-p", "80,443", "-sC"]

        print("  [OK] run_scan argument builder tests passed")

        # 3. Test run_scanning with mock LLM
        class MockLLM:
            def chat(self, system, user, temperature=0.2, timeout=120):
                return (
                    "## Open ports/services\n"
                    "| Port | Protocol | State | Service | Version |\n"
                    "| 80 | tcp | open | http | Apache httpd 2.4.49 |\n\n"
                    "## Version notes\n"
                    "- Apache 2.4.49 is vulnerable to path traversal (CVE-2021-41773).\n\n"
                    "## Interesting findings for exploitation\n"
                    "- Path traversal and RCE via mod_cgi."
                )

        import llm
        original_llm_cls = llm.LLM
        llm.LLM = MockLLM

        try:
            res = run_scanning("127.0.0.1", prior=mock_prior)
            assert "## Open ports/services" in res
            assert "## Version notes" in res
            assert "## Interesting findings for exploitation" in res
            assert "## Raw Nmap Scan" in res
            assert "```\nPORT   STATE SERVICE VERSION" in res
            print("  [OK] run_scanning pipeline test passed")
        finally:
            llm.LLM = original_llm_cls

    finally:
        tools.run_nmap = original_run_nmap

    print("All scanning agent self-tests passed successfully.")
