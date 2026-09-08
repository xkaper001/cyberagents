# CyberAgents — Project Briefing & Defense Notes

**Five AI agents for the five phases of a penetration test.**
A single desktop app walks an operator through recon → scanning → exploitation →
loot → post-exploitation. Each phase is its own LLM-backed agent, and each
agent's findings feed the next.

> **Scope: advisor-mode only — authorized / lab / educational targets.**

| Fact | Value |
|---|---|
| Agents | 5 (one per pentest phase) |
| Ships as | 1 self-contained `.exe` (no install) |
| Brain | LLM over an OpenAI-compatible endpoint |
| Posture | Advises — never auto-exploits |

---

## 01 · What the project is

Penetration testing is a five-phase discipline. Operators today juggle dozens of
tools and must remember what each phase needs from the last. CyberAgents wraps
each phase in an AI agent: give it a target, it gathers what it can, reasons over
the results with an LLM, and returns a ranked, explained plan of what to do next.

- **Problem** — pentest tooling is fragmented and expert-only; raw output like an
  `nmap` dump is unreadable to a beginner.
- **Approach** — one agent per phase; each runs read-only tools, then an LLM turns
  raw output into a prioritized, explained action plan. Phases share findings.
- **Why it's safe** — agents are *advisors*: they analyze and *suggest* exact
  commands; the human reviews and runs them. The app fires no exploits itself.

---

## 02 · The five agents

Phases run in order, and the order carries information: each agent reads previous
phases' output from a shared session context.

| # | Phase | Does | Tools | Owner |
|---|---|---|---|---|
| 01 | **Recon** | Passive/OSINT — DNS, WHOIS, subdomains, tech fingerprint → attack-surface brief | socket, whois | teammate |
| 02 | **Scanning** | Active nmap port/service scan, LLM-summarized into a services map | nmap | teammate |
| 03 | **Exploitation** | Ranks likely vulns from the scan, emits exact exploit commands | nmap, msf, sqlmap | **me (built)** |
| 04 | **Loot / Gathering** | Advises what high-value data to collect and how to enumerate it | advisor | teammate |
| 05 | **Post-Exploitation** | Privesc, persistence, lateral movement, cleanup for the report | advisor | teammate |

**Context flows forward:** recon findings → carried through every later phase.

---

## 03 · How a run works

1. **Pick an agent & enter a target** — the GUI lists all five phases; choose one, type a target.
2. **The agent gathers read-only data** — shells out to real tools via a shared `tools.py` (e.g. `nmap -sV`), or takes a pasted scan.
3. **The LLM reasons over the results** — raw output plus earlier-phase findings go to an OpenAI-compatible endpoint via `llm.py`; the model returns structured markdown.
4. **Findings are stored and rendered** — output is drawn as formatted markdown and saved to the session context under the phase name, so the next agent inherits it.
5. **A report is written** — each run saves a timestamped markdown report to `reports/`.

### Shared agent contract
1. Subclass `Agent`; logic lives in a function returning **markdown**.
2. Takes a `prior` dict of earlier phases' output as context.
3. Talks to the LLM only through `llm.py`; tools only through `tools.py`.
4. Read-only / advisor posture — no destructive actions.
5. Stdlib only — no new dependencies, so the `.exe` stays clean.

### LLM configuration — precedence
1. **User config file** — the operator's own endpoint/model/key.
2. **Environment variables** — `LLM_BASE_URL` / `LLM_MODEL` / `LLM_API_KEY`.
3. **Embedded default** — a shipped fallback key, masked in the UI, never displayed.

Users can bring their own model without ever seeing the built-in key; all keys
are masked (e.g. `cast…d9`).

---

## 04 · Technology & why

Every choice optimizes for one goal: a single, dependency-free executable a
teammate can build and a user can double-click.

| Tech | Why |
|---|---|
| Python 3 | Fastest path for LLM orchestration + shelling out to pentest tools |
| tkinter | GUI bundled with Python — native window, **zero extra deps** |
| stdlib only | LLM calls use `urllib`; no `requests`, no frameworks — small bundle, tiny surface |
| Custom markdown renderer | ~90 lines drawing headings/code/lists — no markdown library |
| PyInstaller | Packs Python + tkinter + embedded config into one `.exe` (per-OS build) |
| GitHub Actions | Windows runner builds the `.exe` on every push — no local Windows box |
| nmap · Metasploit · sqlmap | The real binaries the agents drive; app detects + offers to install |

---

## 05 · Security, ethics & legality

**AUTHORIZED USE ONLY** — scoped for targets you own or have written permission to
test: lab VMs (Metasploitable), CTF boxes, or a client engagement with a signed
SOW. The constraint is stated in the UI and in every LLM prompt.

**ADVISOR, NOT ATTACKER** — agents gather read-only info and *suggest* commands.
They do not launch exploits, exfiltrate data, or change the target on their own.
The human executes every action deliberately.

**Honest limitation we can defend** — the embedded fallback API key is bundled in
the `.exe` and is therefore *extractable*; no client-side secret is ever truly
hidden. We treat it as a low-privilege, rate-limited, rotatable burner, mask it
everywhere, and let users supply their own key that takes precedence. The correct
long-term fix — a server-side proxy holding the key — is scoped as future work.

---

## 06 · Status & division of labor

| Component | Detail | Status |
|---|---|---|
| Foundation | launcher · llm.py · tools.py · GUI · shared context · CI | ✅ done |
| Exploitation | advisor · ranks vulns · emits commands · saves report | ✅ done |
| Scanning | nmap starter in place; LLM summary to extend | 🟡 started |
| Recon | teammate — spec written | ⬜ assigned |
| Loot | teammate — spec written | ⬜ assigned |
| Post-exploit | teammate — spec written | ⬜ assigned |

---

## 07 · Anticipated questions (cross-question defense)

**Is this legal? Aren't you building a hacking tool?**
It's a defensive/educational pentest assistant, scoped to authorized and lab
targets — same category as Metasploit, nmap, or Burp Suite. It never attacks on
its own; it advises a human testing systems they're permitted to test. The
authorized-use constraint is in the UI and every LLM prompt.

**Does it actually exploit anything, or just talk?**
By design it advises. It runs genuine read-only recon (e.g. an nmap service
scan), then produces the *exact* commands an operator would run — real Metasploit
modules, real sqlmap invocations. The value is reasoning and sequencing;
execution stays with the human.

**What is the LLM actually doing? Isn't it just a ChatGPT wrapper?**
The LLM is the reasoning layer. Each agent feeds it structured tool output plus
earlier phases' findings, and it returns a ranked, explained plan for that
target. The engineering is the agent framework around it: a shared contract, tool
integration, phase-to-phase context passing, config precedence, packaging — not
the model itself. The endpoint is open and OpenAI-compatible; users can swap it.

**How do the five agents work together instead of being five separate scripts?**
A shared in-memory session context. Each agent stores its output under its phase
name; the next agent's LLM prompt receives that prior output. Scanning's results
reach exploitation automatically, and so on. All five implement one interface, so
they plug into the same launcher and context store.

**You embed an API key in the .exe — isn't that insecure?**
Yes, and we don't hide that. Any secret shipped in a client binary is
extractable — a property of client-side software, not a bug we can code away. We
mitigate: the key is a low-privilege, rate-limited, rotatable burner, never
displayed (always masked), and users can supply their own that takes precedence.
The proper fix — a server-side proxy — is documented as future work.

**Why a desktop .exe and not a web app?**
Pentest tools run on the operator's own machine and need local execution. A
self-contained executable runs them directly, works offline against lab networks,
and needs no server or install. tkinter gives a native window with no extra deps,
so it all packs into one file.

**What did each team member actually build?**
The foundation (launcher, LLM client, tool detection/installer, GUI + markdown
renderer, shared context, CI) plus the full exploitation agent were built first as
the reference. Each of four teammates then builds one remaining phase against a
written contract — genuinely divided work, consistent result.

**What's novel here versus existing tools?**
Existing tools produce raw output an expert must interpret. Our contribution is an
LLM reasoning layer spanning all five phases that carries context forward —
turning fragmented, expert-only output into an explained, prioritized plan that
also teaches the operator why. It lowers the expertise barrier for learning
pentesting.

**How would you extend it?**
A server-side key proxy; an agentic mode that (with explicit confirmation) runs
suggested commands and reads results back into the loop; consolidated cross-phase
reporting; persistent context surviving a restart.

---

*CyberAgents · pentest-phase agent launcher · authorized / lab / educational use only.*
*Five agents, one contract, one executable.*
