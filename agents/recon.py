"""Reconnaissance phase: Passive OSINT & attack surface gathering
(DNS, WHOIS, SSL certificates, subdomains, reverse DNS, tech fingerprinting)
with LLM-powered attack surface synthesis and scan-focus recommendations.
Feeds into later agents (scanning, exploitation).
"""
import concurrent.futures
import datetime
import ipaddress
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Set, Tuple

if __package__ is None or __package__ == "":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.base import Agent
import llm
import tools

SYSTEM_PROMPT = """You are an expert penetration-testing reconnaissance and OSINT ADVISOR for \
authorized/lab targets only. You analyze passive reconnaissance findings (DNS records, \
WHOIS registration, SSL/TLS certificates, subdomains, reverse DNS, and HTTP response headers) \
to produce an educational, highly detailed, and actionable reconnaissance brief for the pentest operator.

Given a target and its raw reconnaissance data (along with any prior phase context), \
produce a structured markdown brief with EXACTLY the following structure:

## Executive Recon Summary
A concise 2-3 sentence overview explaining what the target is, its primary hosting/network footprint, and its overall exposure level so any operator or student immediately understands the target context.

## Assets found
Bullet points of all discovered assets with brief explanations:
- **Primary Host & IP Addresses**: Resolved IPv4 and IPv6 addresses, IP ownership/ASN (e.g. ISP or Cloud provider), and reverse DNS pointer (PTR). Explain what the reverse DNS reveals (e.g. static business line, CDN node, hosting provider).
- **Domain & Infrastructure**: Nameservers, authoritative DNS provider, mail exchangers (MX records), and SPF/TXT verification records.
- **Subdomains Discovered**: Subdomains found via SSL Subject Alternative Names (SANs) or DNS probes, and their probable role (e.g. web portal, API gateway, mail).

## Likely tech stack
Bullet points identifying detected technologies with security insights:
- **Web Server & Reverse Proxy**: Specific server software and version (e.g. Apache, Nginx, IIS, Cloudflare) detected via response headers.
- **Application & Framework**: Backend indicators (PHP, ASP.NET, Java/Tomcat, Node.js) and CMS or platform signatures.
- **SSL/TLS & Encryption**: Certificate Authority/Issuer, validity status, and security headers (Strict-Transport-Security, Content-Security-Policy).
- **Cloud / CDN / WAF**: Any indications of perimeter defense, caching, or load balancing (e.g. Cloudflare, Akamai, AWS CloudFront).

## Attack Surface & Exposure Analysis
Bullet points detailing the potential security implications:
- Notable exposure vectors or misconfigurations indicated by the passive findings (e.g. exposed administrative subdomains, legacy software indicators, missing security headers).
- Information leakage from DNS TXT records or SSL SANs.

## Recommended scan focus
Actionable guidance to feed into the upcoming scanning and port-enumeration phase:
- **Prioritized Ports**: Format clearly (e.g., "ports: 80, 443, 8080, 22" or "port 80/tcp") so scanning agents can automate port targeting.
- **Scan Scripts & Flags**: Recommend specific nmap scan options (e.g., default scripts `-sC`, vulnerability scripts `--script vuln`, SSL cipher checks, HTTP title/methods scripts).
- **High-Priority Probe Targets**: Specific services or subdomains that should be inspected first during active scanning.

Be objective, educational, concise, and faithful to the gathered data. Do not invent domains, IPs, or services that were not observed."""


def _is_ip_address(host: str) -> bool:
    """Check if the given host string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _query_socket_whois(query_target: str) -> str:
    """Query WHOIS using standard Python socket on port 43 (stdlib fallback)."""
    def _tcp_query(server: str, text: str, timeout: float = 4.0) -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((server, 43))
            s.send((text.strip() + "\r\n").encode("utf-8"))
            chunks = []
            total = 0
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > 65536:
                    break
            return b"".join(chunks).decode("utf-8", errors="ignore")
        finally:
            try:
                s.close()
            except Exception:
                pass

    try:
        # IP lookup: query ARIN directly
        if _is_ip_address(query_target):
            return _tcp_query("whois.arin.net", f"n + {query_target}")

        # Domain lookup: query IANA first to find the authoritative TLD WHOIS server
        tld = query_target.lower().split(".")[-1]
        iana_res = _tcp_query("whois.iana.org", tld)
        ref_match = re.search(r"whois:\s*([a-zA-Z0-9.-]+)", iana_res, re.IGNORECASE)

        target_server = ref_match.group(1).strip() if ref_match else "whois.iana.org"
        whois_data = _tcp_query(target_server, query_target)

        # Truncate disclaimers / long legal blurbs
        lines = [line for line in whois_data.splitlines() if line.strip()]
        return "\n".join(lines[:60]) if lines else "(empty whois response)"
    except Exception as e:
        return f"[whois socket query failed: {e}]"


def _query_dns_records(host: str) -> str:
    """Query DNS records using dig (if installed) or native nslookup concurrently."""
    # 1. Try dig if installed
    dig_res = tools.run_dig(host, "ANY")
    if dig_res and "[dig not installed]" not in dig_res and "[no dig output]" not in dig_res:
        return dig_res

    # 2. Use nslookup with common record types in parallel
    record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]

    def _query_one_rtype(rtype: str) -> Optional[str]:
        try:
            cmd = ["nslookup", f"-type={rtype}", host]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            output = (res.stdout or res.stderr or "").strip()
            filtered_lines = [
                line for line in output.splitlines()
                if not line.startswith("Server:") and not line.startswith("Address:")
            ]
            clean_output = "\n".join(filtered_lines).strip()
            if (
                clean_output
                and "can't find" not in clean_output.lower()
                and "non-existent" not in clean_output.lower()
                and "unknown" not in clean_output.lower()
            ):
                return f"[{rtype} RECORDS]\n{clean_output}"
        except Exception:
            pass
        return None

    records: List[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        futures = [executor.submit(_query_one_rtype, rt) for rt in record_types]
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                records.append(res)

    return "\n\n".join(records) if records else "(no DNS records found via nslookup)"


def _inspect_ssl_cert(host: str, port: int = 443) -> Tuple[Dict[str, Any], List[str]]:
    """Connect to host:port with TLS to inspect certificate Subject, Issuer, and SANs."""
    info: Dict[str, Any] = {}
    sans: List[str] = []

    def _extract_from_cert(cert: Dict[str, Any]) -> None:
        if not cert:
            return
        subject_entries = dict(x[0] for x in cert.get("subject", ()) if x)
        issuer_entries = dict(x[0] for x in cert.get("issuer", ()) if x)
        info["subject_cn"] = subject_entries.get("commonName")
        info["subject_org"] = subject_entries.get("organizationName")
        info["issuer_cn"] = issuer_entries.get("commonName")
        info["issuer_org"] = issuer_entries.get("organizationName")
        info["valid_from"] = cert.get("notBefore")
        info["valid_until"] = cert.get("notAfter")

        for san_type, san_val in cert.get("subjectAltName", ()):
            if san_type.lower() == "dns" and san_val not in sans:
                sans.append(san_val)

    # 1. Attempt verified SSL handshake
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=3.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                _extract_from_cert(ssock.getpeercert())
        return info, sans
    except Exception:
        pass

    # 2. Fallback to unverified SSL context (for self-signed certs in lab/pentest environments)
    try:
        unverified_ctx = ssl._create_unverified_context()
        with socket.create_connection((host, port), timeout=3.0) as sock:
            with unverified_ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                if cert_bin:
                    info["note"] = "Self-signed or unverified lab certificate present"
    except Exception:
        pass

    return info, sans


def _probe_common_subdomains(domain: str) -> Dict[str, str]:
    """Concurrent lightweight passive DNS probe for common high-value subdomains."""
    if _is_ip_address(domain) or domain in ("localhost", "127.0.0.1", "::1"):
        return {}

    candidates = [
        "www", "mail", "api", "dev", "staging", "admin", "app",
        "vpn", "portal", "test", "remote", "blog", "shop", "cdn"
    ]

    def _check_sub(sub: str) -> Optional[Tuple[str, str]]:
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            return (fqdn, ip)
        except Exception:
            return None

    found: Dict[str, str] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(_check_sub, sub) for sub in candidates]
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                found[res[0]] = res[1]

    return found


def _probe_web_fingerprint(host: str) -> Dict[str, Any]:
    """Probe HTTP and HTTPS endpoints concurrently for banner, status, and server header."""
    results: Dict[str, Any] = {}

    def _probe_one(proto: str) -> Tuple[str, Dict[str, Any]]:
        url = f"{proto}://{host}"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberAgents/1.0"}
        )
        ssl_ctx = ssl._create_unverified_context() if proto == "https" else None
        try:
            with urllib.request.urlopen(req, timeout=3.0, context=ssl_ctx) as resp:
                headers = dict(resp.headers)
                body = resp.read(2048).decode("utf-8", errors="ignore")
                title_match = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
                return (proto, {
                    "status": resp.status,
                    "server": headers.get("Server"),
                    "powered_by": headers.get("X-Powered-By"),
                    "title": title_match.group(1).strip() if title_match else None,
                    "headers": {k: v for k, v in headers.items() if k.lower() in (
                        "server", "x-powered-by", "x-aspnet-version", "content-type",
                        "strict-transport-security", "set-cookie", "location"
                    )}
                })
        except urllib.error.HTTPError as e:
            headers = dict(e.headers)
            return (proto, {
                "status": e.code,
                "server": headers.get("Server"),
                "powered_by": headers.get("X-Powered-By"),
                "headers": {k: v for k, v in headers.items() if k.lower() in (
                    "server", "x-powered-by", "x-aspnet-version", "content-type", "location"
                )}
            })
        except Exception as e:
            return (proto, {"error": str(e)})

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(_probe_one, p) for p in ["http", "https"]]
        for fut in concurrent.futures.as_completed(futures):
            proto, data = fut.result()
            results[proto] = data

    return results


def gather_recon(target: str) -> str:
    """Collect passive OSINT data on a target (domain or IP).

    Gathers DNS records, WHOIS, SSL cert details, subdomains, reverse DNS,
    and HTTP headers without aggressive port scanning. Returns raw findings text.
    """
    host = tools.normalize_target(target)
    if not host:
        return "[no valid target specified]"

    sections: List[str] = []
    sections.append(f"=== RECON TARGET ===\nHost: {host}\nIs IP: {_is_ip_address(host)}")

    # 1. Target DNS resolution & Reverse DNS
    res_lines: List[str] = []
    resolved_ips: List[str] = []
    try:
        addr_info = socket.getaddrinfo(host, None)
        for entry in addr_info:
            ip = entry[4][0]
            if ip not in resolved_ips:
                resolved_ips.append(ip)
        res_lines.append(f"Resolved IP(s): {', '.join(resolved_ips) if resolved_ips else '(none)'}")
    except Exception as e:
        res_lines.append(f"Forward resolution error: {e}")

    # Reverse DNS
    for ip in resolved_ips or ([host] if _is_ip_address(host) else []):
        try:
            rev_host, aliases, _ = socket.gethostbyaddr(ip)
            alias_str = f" (aliases: {', '.join(aliases)})" if aliases else ""
            res_lines.append(f"Reverse DNS for {ip}: {rev_host}{alias_str}")
        except Exception:
            res_lines.append(f"Reverse DNS for {ip}: (none)")

    sections.append("=== HOST RESOLUTION & REVERSE DNS ===\n" + "\n".join(res_lines))

    # 2. DNS Records
    dns_records = _query_dns_records(host)
    sections.append("=== DNS RECORDS ===\n" + dns_records)

    # 3. WHOIS Information
    whois_res = tools.run_whois(host)
    if not whois_res or "[whois not installed]" in whois_res or "[whois error" in whois_res:
        whois_res = _query_socket_whois(host)
    sections.append("=== WHOIS REGISTRATION ===\n" + whois_res.strip())

    # 4. SSL/TLS Certificate & SANs
    cert_info, cert_sans = _inspect_ssl_cert(host)
    cert_lines: List[str] = []
    if cert_info:
        if cert_info.get("subject_cn"):
            cert_lines.append(f"Subject CN: {cert_info['subject_cn']}")
        if cert_info.get("subject_org"):
            cert_lines.append(f"Subject Org: {cert_info['subject_org']}")
        if cert_info.get("issuer_cn"):
            cert_lines.append(f"Issuer: {cert_info['issuer_cn']} ({cert_info.get('issuer_org', 'Unknown')})")
        if cert_info.get("valid_from") and cert_info.get("valid_until"):
            cert_lines.append(f"Validity: {cert_info['valid_from']} -> {cert_info['valid_until']}")
        if cert_info.get("note"):
            cert_lines.append(f"Note: {cert_info['note']}")
    if cert_sans:
        cert_lines.append("Subject Alt Names (SANs): " + ", ".join(cert_sans))

    sections.append("=== SSL/TLS CERTIFICATE ===\n" + ("\n".join(cert_lines) if cert_lines else "(no certificate data retrieved)"))

    # 5. Subdomain Discovery
    discovered_subdomains: Dict[str, str] = {}
    for san in cert_sans:
        san_clean = san.lstrip("*.")
        if san_clean != host and host in san_clean:
            discovered_subdomains[san_clean] = "(from cert SAN)"

    probed = _probe_common_subdomains(host)
    for sub, ip in probed.items():
        discovered_subdomains[sub] = ip

    if discovered_subdomains:
        sub_text = "\n".join(f"- {sub}: {val}" for sub, val in sorted(discovered_subdomains.items()))
    else:
        sub_text = "(none discovered passively)"
    sections.append("=== PASSIVE SUBDOMAINS ===\n" + sub_text)

    # 6. HTTP / HTTPS Web Fingerprint
    web_fp = _probe_web_fingerprint(host)
    web_lines: List[str] = []
    for proto in ["http", "https"]:
        data = web_fp.get(proto, {})
        if "error" in data:
            web_lines.append(f"{proto.upper()}: not responding ({data['error']})")
        else:
            status = data.get("status")
            server = data.get("server") or "(hidden/none)"
            powered = data.get("powered_by")
            title = data.get("title")
            line = f"{proto.upper()}: HTTP {status} | Server: {server}"
            if powered:
                line += f" | Powered-By: {powered}"
            if title:
                line += f" | Title: {title}"
            web_lines.append(line)
            if data.get("headers"):
                for hk, hv in data["headers"].items():
                    web_lines.append(f"  {hk}: {hv}")

    sections.append("=== HTTP/HTTPS WEB FINGERPRINT ===\n" + ("\n".join(web_lines) if web_lines else "(no response)"))

    return "\n\n".join(sections)


def _generate_local_recon_brief(target: str, raw_recon: str) -> str:
    """Generate a rich, educational analysis directly from raw findings if LLM is unavailable."""
    host = tools.normalize_target(target)
    
    # Extract IPs
    ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", raw_recon)
    unique_ips = list(dict.fromkeys(ips))
    
    # Extract Reverse DNS
    ptrs = re.findall(r"Reverse DNS for [^:]+:\s*([^\n\r]+)", raw_recon)
    ptrs = [p.strip() for p in ptrs if p.strip() and "(none)" not in p]
    
    # Extract Nameservers
    nss = re.findall(r"nameserver\s*=\s*([^\s]+)", raw_recon, re.IGNORECASE)
    nss = list(dict.fromkeys(nss))
    
    # Extract Mail Servers
    mxs = re.findall(r"mail exchanger\s*=\s*([^\s]+)", raw_recon, re.IGNORECASE)
    mxs = list(dict.fromkeys(mxs))
    
    # Extract SSL SANs
    sans = re.findall(r"Subject Alt Names \(SANs\):\s*([^\n\r]+)", raw_recon)
    san_list = [s.strip() for s in sans[0].split(",") if s.strip()] if sans else []
    
    # Extract Server banner
    server_match = re.search(r"Server:\s*([^\n\r]+)", raw_recon, re.IGNORECASE)
    server_banner = server_match.group(1).strip() if server_match else None
    
    # Extract Title
    title_match = re.search(r"Title:\s*([^\n\r]+)", raw_recon, re.IGNORECASE)
    web_title = title_match.group(1).strip() if title_match else None

    # Determine recommended ports
    rec_ports = ["80", "443"]
    if mxs:
        rec_ports.extend(["25", "587"])
    if nss:
        rec_ports.append("53")
    rec_ports.extend(["8080", "8443", "22"])
    ports_str = ", ".join(list(dict.fromkeys(rec_ports)))

    lines = [
        "## Executive Recon Summary",
        f"Passive reconnaissance on `{host}` successfully gathered foundational infrastructure data. "
        + (f"The target is serving `{web_title}` via `{server_banner}`. " if (web_title and server_banner) else f"Target resolved to {len(unique_ips)} IPv4 endpoint(s). ")
        + f"Ownership and reverse DNS indicate network infrastructure managed by: {', '.join(ptrs) if ptrs else 'standard hosting provider'}.",
        "",
        "## Assets found",
        f"- **Primary Target**: `{host}`",
        f"- **Resolved IP Address(es)**: {', '.join(f'`{ip}`' for ip in unique_ips) if unique_ips else '*(none resolved)*'}",
    ]
    if ptrs:
        lines.append(f"- **Reverse DNS (PTR)**: {', '.join(f'`{p}`' for p in ptrs)} *(reveals network block / ISP provider)*")
    if nss:
        lines.append(f"- **Authoritative DNS Nameservers**: {', '.join(f'`{ns}`' for ns in nss)}")
    if mxs:
        lines.append(f"- **Mail Exchange (MX)**: {', '.join(f'`{mx}`' for mx in mxs)} *(indicates mail routing infrastructure)*")
    if san_list:
        lines.append(f"- **SSL Subject Alt Names (SANs)**: {', '.join(f'`{s}`' for s in san_list[:6])}")

    lines.extend([
        "",
        "## Likely tech stack",
        f"- **Web Server**: `{server_banner or 'Hidden / Filtered / Not detected'}`" + (" *(Fingerprinted via HTTP response header)*" if server_banner else ""),
        f"- **Application Title**: `{web_title or 'N/A'}`",
        "- **Transport Security**: TLS / SSL enabled on port 443" if "=== SSL/TLS CERTIFICATE ===" in raw_recon and "(no certificate" not in raw_recon else "- **Transport Security**: Standard HTTP",
        f"- **Infrastructure Provider**: {', '.join(ptrs[:2]) if ptrs else 'Public Internet Routing'}",
        "",
        "## Attack Surface & Exposure Analysis",
        "- **Information Disclosure**: Server banner and DNS PTR records reveal underlying infrastructure details.",
        "- **Perimeter Exposure**: Web application endpoints detected. Verify authentication portals and admin interfaces.",
        "- **SSL/TLS Configuration**: Ensure legacy TLS versions (TLS 1.0/1.1) and weak ciphers are disabled.",
        "",
        "## Recommended scan focus",
        f"- Prioritize ports: {ports_str}",
        "- Run default script scan (-sC) and service version detection (-sV) on web ports.",
        "- Execute vulnerability checks (`--script vuln`) against discovered HTTP services and login endpoints.",
        f"- Probe high-priority target: `{host}` on HTTP/HTTPS to inspect application routes."
    ])
    return "\n".join(lines)


def run_recon(target: str, prior: Optional[Dict[str, Any]] = None) -> str:
    """Execute passive reconnaissance on a target and summarize via LLM.

    Returns structured markdown with Assets, Likely tech stack, and
    Recommended scan focus, followed by the raw reconnaissance data.
    If the LLM endpoint is unavailable or returns an error, seamlessly
    provides an expert educational local analysis so the operator always
    gets actionable insights.
    """
    raw_recon = gather_recon(target)

    prompt_parts = [
        f"TARGET: {target}",
        f"\nRAW RECONNAISSANCE FINDINGS:\n{raw_recon}",
    ]

    if prior:
        for phase, out in prior.items():
            if out and isinstance(out, str) and out.strip():
                prompt_parts.append(f"\nPRIOR PHASE — {phase.upper()} CONTEXT:\n{out.strip()}")

    user_prompt = "\n".join(prompt_parts)
    brief = llm.LLM().chat(SYSTEM_PROMPT, user_prompt)

    # If the LLM call fails or returns an error string, provide the smart local analysis
    if not brief or "[LLM ERROR]" in brief or "[ERROR]" in brief:
        error_note = f"> [!NOTE]\n> {brief.strip()}\n> *Displaying offline educational reconnaissance analysis below.*\n\n" if brief else ""
        local_brief = _generate_local_recon_brief(target, raw_recon)
        return f"{error_note}{local_brief}\n\n## Raw Reconnaissance Data\n```\n{raw_recon}\n```"

    return f"{brief}\n\n## Raw Reconnaissance Data\n```\n{raw_recon}\n```"


def save_report(target: str, content: str) -> str:
    """Write a markdown recon report, return its path."""
    os.makedirs("reports", exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    safe = target.replace("/", "_").replace(":", "_")
    path = os.path.join("reports", f"recon-{safe}-{ts}.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# Reconnaissance phase report\n\n- Target: {target}\n- Time: {ts}\n\n{content}\n")
    return path


class ReconAgent(Agent):
    name = "recon"
    description = "Passive OSINT & attack surface recon: DNS, WHOIS, subdomains, reverse DNS, tech stack, and scan focus recommendations."

    def run(self, target: str) -> None:
        self._ensure_tools()
        print(f"[*] Gathering passive reconnaissance on: {target}")
        print("  gathering DNS, WHOIS, SSL certs, and tech fingerprints...")
        result = run_recon(target)
        print("\n" + result)
        path = save_report(target, result)
        print(f"\nReport saved: {path}")

    def _ensure_tools(self) -> None:
        st = tools.status()
        missing = [t for t in ["whois", "dig"] if not st.get(t, False)]
        if not missing:
            return
        print(f"Optional recon tools available: {', '.join(missing)} (built-in stdlib fallbacks active)")
        if input("Install optional tools now? [y/N]: ").strip().lower() in ("y", "yes"):
            for t in missing:
                ok, msg = tools.install(t)
                print(f"  {t}: {'installed' if ok else 'FAILED'} ({msg})")


if __name__ == "__main__":
    print("Running recon agent self-tests...")

    # 1. Test normalization and IP detection
    assert _is_ip_address("127.0.0.1") is True
    assert _is_ip_address("::1") is True
    assert _is_ip_address("example.com") is False
    assert tools.normalize_target("https://example.com/foo") == "example.com"
    print("  [OK] IP detection and target normalization passed")

    # 2. Test raw recon gathering on localhost / loopback
    raw_local = gather_recon("127.0.0.1")
    assert "=== RECON TARGET ===" in raw_local
    assert "=== HOST RESOLUTION & REVERSE DNS ===" in raw_local
    print("  [OK] Local raw recon gathering passed")

    # 3. Test run_recon with MockLLM
    class MockLLM:
        def chat(self, system: str, user: str, temperature: float = 0.2, timeout: int = 120) -> str:
            assert "TARGET:" in user or "RECON TARGET" in user
            return (
                "## Assets found\n"
                "- Primary Target: test.local (192.168.1.10)\n"
                "- Subdomains: www.test.local, mail.test.local\n\n"
                "## Likely tech stack\n"
                "- Web Server: Nginx/1.20.1\n"
                "- SSL Certificate: Cloudflare TLS\n\n"
                "## Recommended scan focus\n"
                "- Prioritize ports: 80, 443, 8080, 22\n"
                "- Run default script scan (-sC) and vulnerability scripts (--script vuln) on web services."
            )

    original_llm_cls = llm.LLM
    llm.LLM = MockLLM

    try:
        recon_out = run_recon("example.com")
        assert "## Assets found" in recon_out
        assert "## Likely tech stack" in recon_out
        assert "## Recommended scan focus" in recon_out
        assert "## Raw Reconnaissance Data" in recon_out
        print("  [OK] run_recon pipeline with MockLLM passed")

        # 4. Verify report saving
        saved_path = save_report("test.local", recon_out)
        assert os.path.exists(saved_path)
        with open(saved_path, "r", encoding="utf-8") as f:
            content = f.read()
            assert "# Reconnaissance phase report" in content
            assert "## Recommended scan focus" in content
        print(f"  [OK] Report saved successfully at {saved_path}")

        # 5. Verify scanning agent's focus extraction parses this recon output!
        from agents.scanning import _extract_recon_focus
        ports, script, vuln = _extract_recon_focus({"recon": recon_out})
        assert ports == "80,443,8080,22", f"Expected ports 80,443,8080,22, got: {ports}"
        assert script is True, "Expected script scan to be True"
        assert vuln is True, "Expected vuln scan to be True"
        print("  [OK] Cross-phase integration: scanning._extract_recon_focus parsed recon output correctly")

    finally:
        llm.LLM = original_llm_cls

    print("All recon agent self-tests passed successfully.")
