# CyberAgents — Agent Build Tasks (for the team)

Five pentest-phase agents behind one GUI. **Authorized / lab / learning use only.**
Owner built the foundation + the **exploitation** agent. Each teammate builds
ONE of the remaining agents so it drops into the same app with zero glue.

Copy your section's prompt into your AI assistant, work in this repo.

---

## Shared contract (read first — applies to EVERY agent)

Before writing code, read these files:
- `agents/base.py` — the `Agent` interface you subclass.
- `agents/exploitation.py` — **the reference**. Copy its shape exactly.
- `llm.py` — `LLM().chat(system, user)` for any LLM call. Don't add HTTP code.
- `tools.py` — `tools.run_nmap(target)`, `tools.status()`, `tools.install(name)`.
  Add new tool binaries here (name → PATH cmd + winget/choco/brew ids).
- `gui.py` — how agents are wired to the window and the shared context store.

Rules — non-negotiable so everything integrates:
1. **Subclass `Agent`** in `agents/<yourphase>.py`. Set `name` and `description`.
2. **Put the real logic in a module-level function** (e.g. `def run_recon(target, prior=None)`)
   that RETURNS a markdown string. The class's `run()` and the GUI both call it.
   (Exactly like `exploitation.advise()`.)
3. **Return markdown**, not plain text. The GUI renders headings (`#`,`##`,`###`),
   `**bold**`, `` `code` ``, bullets (`- `), numbered lists, code fences (```), and `---`.
4. **Use the shared context.** Your function takes `prior` = dict `{phase: output}`
   from earlier agents. Use it (e.g. exploitation reads scanning's scan). The GUI
   stores your return value under your phase name automatically.
5. **No new pip dependencies.** Stdlib only (keeps the .exe clean). Shell out to
   real tools via `subprocess` through `tools.py`; talk to the LLM via `llm.py`.
6. **Never execute destructive actions.** Advisor/read-only posture like the
   exploitation agent: gather + analyze + SUGGEST commands. Don't auto-exploit.
7. **Leave one runnable check** — an `if __name__ == "__main__":` self-test that
   asserts your function builds output without crashing (mock the LLM if needed).

Wiring into the GUI (owner or you, one line each): in `gui.py._work`, add an
`elif agent == "<yourphase>":` branch that calls your function with
`prior = {k:v for k,v in self.context.items()}` and renders the result. Follow
the `scanning` / `exploitation` branches already there.

Definition of done: your agent appears in the dropdown, runs on a target,
renders formatted markdown, reads prior-phase context, saves a report to
`reports/`, and the app still builds (`python3 gui.py`).

---

## Task 1 — RECON agent  (file: `agents/recon.py`)

Build the reconnaissance phase. Passive/OSINT-style info gathering on a target
(domain or IP), then an LLM summary of the attack surface to hand to scanning.

Do:
- Gather what you can without touching the target hard: DNS records, WHOIS,
  subdomains, reverse DNS, tech fingerprint. Use stdlib (`socket`) for DNS/reverse
  DNS; add any binary (e.g. `whois`, `dig`) to `tools.py` with install ids.
- `def run_recon(target, prior=None) -> str`: collect raw findings, then call
  `LLM().chat(SYSTEM_PROMPT, ...)` to produce a markdown recon brief:
  ## Assets found, ## Likely tech stack, ## Recommended scan focus (feeds scanning).
- Return markdown. Self-test with a mocked LLM.

Acceptance: run `recon` on a domain → get a readable brief; its output is
available to scanning/exploitation via context.

---

## Task 2 — SCANNING agent  (file: `agents/scanning.py`)

A starter exists (`run_scan()` = nmap service scan). **Extend it.**

Do:
- Keep `run_scan(target, args=None)` returning nmap output.
- Add `def run_scanning(target, prior=None) -> str`: run nmap (use recon's
  "scan focus" from `prior` to pick ports/scripts), then LLM-summarize into
  markdown: ## Open ports/services (table), ## Version notes, ## Interesting
  findings for exploitation. Return the raw scan inside a ``` fence PLUS the summary.
- Add nmap script scans (`-sC`, `--script vuln`) as an option.

Acceptance: `scanning` produces a readable service map + summary; exploitation
already auto-consumes the scan from context.

---

## Task 3 — LOOT / GATHERING agent  (file: `agents/loot.py`)

Post-access data-gathering ADVISOR. Given confirmed access context (from
exploitation in `prior`), advise WHAT to collect and HOW — do not exfiltrate.

Do:
- `def run_loot(target, prior=None) -> str`: read exploitation output from
  `prior`, then LLM-produce a markdown checklist:
  ## High-value data to look for (creds, keys, configs, DBs, tokens),
  ## Commands to enumerate it (per-OS, exact), ## Handling/scope notes.
- Read-only advice only. No auto-collection.

Acceptance: `loot` uses exploitation's result and outputs a concrete,
service-specific loot plan.

---

## Task 4 — POST-EXPLOIT agent  (file: `agents/postexploit.py`)

Post-exploitation ADVISOR: persistence, privilege escalation, lateral movement,
and CLEANUP guidance for the engagement report. Advise, don't execute.

Do:
- `def run_postexploit(target, prior=None) -> str`: use exploitation + loot from
  `prior`; LLM-produce markdown:
  ## Privilege escalation checks (exact commands), ## Persistence options,
  ## Lateral movement leads, ## Cleanup / artifacts to remove, ## Report notes.
- Read-only advice. Emphasize scope + cleanup.

Acceptance: `postexploit` chains off prior phases and outputs an actionable,
authorized-engagement checklist.

---

## Handing off
- One agent per person. Match `exploitation.py` structure — that's the spec.
- Test: `python3 gui.py`, pick your agent, run on a lab target (e.g.
  `192.168.56.101` Metasploitable, or `scanme.nmap.org` for recon/scan).
- The Windows `.exe` is built by CI (`.github/workflows/build.yml`) — just push;
  don't add dependencies that would break the bundle.
