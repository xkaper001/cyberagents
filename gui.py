"""CyberAgents desktop GUI (tkinter, stdlib — no deps, packs to a .exe).

Styled with the 'clam' ttk theme + a small markdown renderer that draws the
advisor's output with real headings, bold, bullets and code blocks (no md lib).
Only the exploitation agent has real logic; the other four are teammate stubs.
"""
import re
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox

import llm
import tools
from agents import exploitation, scanning

AGENTS = ["recon", "scanning", "exploitation", "loot", "postexploit"]

# ---- palette ----
BG = "#eef1f5"
CARD = "#ffffff"
HEADER = "#141a24"
ACCENT = "#3b82f6"
ACCENT_DK = "#2563eb"
GREEN = "#16a34a"
GREEN_DK = "#15803d"
TEXT = "#1f2937"
MUTED = "#6b7280"
BORDER = "#d7dce3"
CODE_BG = "#0f172a"
CODE_FG = "#e2e8f0"
INLINE_BG = "#eef1f5"
INLINE_FG = "#b91c1c"


def _fonts():
    if sys.platform == "win32":
        return "Segoe UI", "Consolas"
    if sys.platform == "darwin":
        return "Helvetica Neue", "Menlo"
    return "DejaVu Sans", "DejaVu Sans Mono"


UI, MONO = _fonts()


class MarkdownView(tk.Text):
    """A read-only Text widget that renders a useful subset of markdown."""

    def __init__(self, master, **kw):
        super().__init__(master, wrap="word", state="disabled", relief="flat",
                         bg=CARD, fg=TEXT, padx=18, pady=14, spacing1=1, spacing3=4,
                         font=(UI, 12), cursor="arrow", highlightthickness=0, **kw)
        self.tag_configure("h1", font=(UI, 19, "bold"), foreground="#0f172a", spacing1=12, spacing3=6)
        self.tag_configure("h2", font=(UI, 15, "bold"), foreground=ACCENT_DK, spacing1=10, spacing3=4)
        self.tag_configure("h3", font=(UI, 13, "bold"), foreground="#334155", spacing1=8, spacing3=3)
        self.tag_configure("body", font=(UI, 12), foreground=TEXT, spacing3=4)
        self.tag_configure("bold", font=(UI, 12, "bold"))
        self.tag_configure("bullet", font=(UI, 12), lmargin1=22, lmargin2=38, spacing3=3)
        self.tag_configure("inline", font=(MONO, 11), background=INLINE_BG, foreground=INLINE_FG)
        self.tag_configure("code", font=(MONO, 11), background=CODE_BG, foreground=CODE_FG,
                           lmargin1=18, lmargin2=18, rmargin=18, spacing1=2, spacing3=2)
        self.tag_configure("muted", foreground=MUTED, font=(UI, 11))
        self.tag_configure("rule", foreground=BORDER)
        self._rules = []
        self.bind("<Configure>", self._resize_rules)

    _inline = re.compile(r"\*\*(.+?)\*\*|`([^`]+)`")

    def _put(self, text, *tags):
        self.insert("end", text, tags)

    def _put_inline(self, text, base):
        pos = 0
        for m in self._inline.finditer(text):
            if m.start() > pos:
                self._put(text[pos:m.start()], base)
            if m.group(1) is not None:
                self._put(m.group(1), base, "bold")
            else:
                self._put(m.group(2), "inline")
            pos = m.end()
        if pos < len(text):
            self._put(text[pos:], base)

    def render(self, md):
        self.configure(state="normal")
        self.delete("1.0", "end")
        for f in self._rules:
            f.destroy()
        self._rules = []
        in_code = False
        for line in md.splitlines():
            if line.strip().startswith("```"):
                in_code = not in_code
                continue
            if in_code:
                self._put((line or " ") + "\n", "code")
                continue
            s = line.strip()
            if not s:
                self._put("\n")
            elif s.startswith("### "):
                self._put(s[4:] + "\n", "h3")
            elif s.startswith("## "):
                self._put(s[3:] + "\n", "h2")
            elif s.startswith("# "):
                self._put(s[2:] + "\n", "h1")
            elif s in ("---", "***", "___"):
                self._hr()
            elif re.match(r"^[-*]\s+", s):
                self._put("•  ", "bullet")
                self._put_inline(re.sub(r"^[-*]\s+", "", s), "bullet")
                self._put("\n", "bullet")
            elif re.match(r"^\d+\.\s+", s):
                num = re.match(r"^(\d+\.)\s+", s).group(1)
                self._put(num + "  ", "bullet", "bold")
                self._put_inline(re.sub(r"^\d+\.\s+", "", s), "bullet")
                self._put("\n", "bullet")
            else:
                self._put_inline(line, "body")
                self._put("\n", "body")
        self.configure(state="disabled")
        self.see("1.0")

    def _hr(self):
        self._put("\n")
        f = tk.Frame(self, height=1, bg=BORDER)
        self.window_create("end", window=f, padx=18, pady=6)
        self._rules.append(f)
        self._put("\n")
        self._resize_rules()

    def _resize_rules(self, event=None):
        w = self.winfo_width() - 40
        if w < 10:
            return
        for f in self._rules:
            f.configure(width=w)

    def show_plain(self, text):
        self.configure(state="normal")
        self.delete("1.0", "end")
        self._put(text + "\n", "muted")
        self.configure(state="disabled")


class App:
    def __init__(self, root):
        self.root = root
        self.context = {}   # phase -> last output, shared across agent runs
        root.title("CyberAgents")
        root.geometry("960x720")
        root.minsize(760, 560)
        root.configure(bg=BG)
        self._style()

        # --- header bar ---
        head = tk.Frame(root, bg=HEADER)
        head.pack(fill="x")
        tk.Label(head, text="🛡  CyberAgents", bg=HEADER, fg="#ffffff",
                 font=(UI, 17, "bold")).pack(side="left", padx=18, pady=12)
        tk.Label(head, text="exploitation advisor · authorized / lab use only",
                 bg=HEADER, fg="#94a3b8", font=(UI, 11)).pack(side="left", pady=12)

        # --- controls card ---
        ctl = tk.Frame(root, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        ctl.pack(fill="x", padx=14, pady=(12, 8))
        inner = tk.Frame(ctl, bg=CARD)
        inner.pack(fill="x", padx=14, pady=12)

        tk.Label(inner, text="Agent", bg=CARD, fg=MUTED, font=(UI, 10)).grid(row=0, column=0, sticky="w")
        self.agent = tk.StringVar(value="exploitation")
        ttk.Combobox(inner, textvariable=self.agent, values=AGENTS, state="readonly",
                     width=15).grid(row=1, column=0, padx=(0, 14), sticky="w")

        tk.Label(inner, text="Target", bg=CARD, fg=MUTED, font=(UI, 10)).grid(row=0, column=1, sticky="w")
        self.target = tk.StringVar()
        ttk.Entry(inner, textvariable=self.target).grid(row=1, column=1, sticky="we", padx=(0, 14))
        inner.columnconfigure(1, weight=1)

        self.run_btn = ttk.Button(inner, text="▶  Run", style="Accent.TButton", command=self.on_run)
        self.run_btn.grid(row=1, column=2, padx=2)
        ttk.Button(inner, text="Configure LLM", command=self.on_config).grid(row=1, column=3, padx=2)
        ttk.Button(inner, text="Install tools", command=self.on_install).grid(row=1, column=4, padx=2)

        self.run_nmap = tk.BooleanVar(value=False)
        ttk.Checkbutton(inner, text="Run nmap now (requires nmap installed)",
                        variable=self.run_nmap, style="Card.TCheckbutton"
                        ).grid(row=2, column=0, columnspan=3, sticky="w", pady=(10, 0))

        # --- scan paste (collapsible-ish, always visible, compact) ---
        paste = tk.Frame(root, bg=BG)
        paste.pack(fill="x", padx=14)
        tk.Label(paste, text="Paste nmap scan (optional — ignored if 'Run nmap now' is checked)",
                 bg=BG, fg=MUTED, font=(UI, 10)).pack(anchor="w", pady=(4, 2))
        self.scan_in = tk.Text(paste, height=5, wrap="word", relief="flat", font=(MONO, 10),
                               bg=CARD, fg=TEXT, highlightbackground=BORDER, highlightthickness=1,
                               padx=10, pady=8)
        self.scan_in.pack(fill="x")

        # --- output card ---
        outwrap = tk.Frame(root, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        outwrap.pack(fill="both", expand=True, padx=14, pady=(10, 6))
        self.out = MarkdownView(outwrap)
        sb = ttk.Scrollbar(outwrap, command=self.out.yview)
        self.out.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.out.pack(side="left", fill="both", expand=True)
        self.out.show_plain("Pick an agent, enter a target, hit Run.")

        # --- status bar ---
        self.status = tk.StringVar()
        bar = tk.Frame(root, bg=BG)
        bar.pack(fill="x", padx=16, pady=(0, 8))
        tk.Label(bar, textvariable=self.status, bg=BG, fg=MUTED, font=(UI, 10)).pack(side="left")
        self._refresh_status()

    def _style(self):
        st = ttk.Style()
        st.theme_use("clam")
        st.configure("TButton", font=(UI, 11), padding=(12, 7), background="#e5e7eb",
                     foreground=TEXT, borderwidth=0, focuscolor=BG)
        st.map("TButton", background=[("active", "#d1d5db")])
        st.configure("Accent.TButton", background=GREEN, foreground="#ffffff")
        st.map("Accent.TButton", background=[("active", GREEN_DK), ("disabled", "#9ca3af")])
        st.configure("TEntry", fieldbackground=CARD, padding=6, borderwidth=1)
        st.configure("TCombobox", padding=5)
        st.configure("Card.TCheckbutton", background=CARD, font=(UI, 11))
        st.map("Card.TCheckbutton", background=[("active", CARD)])
        st.configure("TCheckbutton", font=(UI, 11))

    def _refresh_status(self):
        c = llm.resolve_config()
        have = ", ".join(t for t, ok in tools.status().items() if ok) or "none"
        carried = ", ".join(self.context) or "none"
        self.status.set(f"LLM: {c['model']}  ·  {c['source']}     tools: {have}     context: {carried}")

    def on_run(self):
        target = self.target.get().strip()
        if not target:
            messagebox.showwarning("No target", "Enter a target first.")
            return
        agent = self.agent.get()
        self.run_btn.configure(state="disabled")
        self.out.show_plain(f"Running {agent} on {target}…")
        threading.Thread(target=self._work, args=(agent, target), daemon=True).start()

    def _work(self, agent, target):
        try:
            if agent == "scanning":
                self.root.after(0, self.out.show_plain, f"[nmap] scanning {target} … (up to a minute)")
                prior = {k: v for k, v in self.context.items() if k != "scanning"}
                out = scanning.run_scanning(target, prior=prior)
                self.context["scanning"] = out
                path = scanning.save_report(target, out)
                self.root.after(0, self.out.render, out + f"\n\n---\n*Report saved: `{path}`*")
            elif agent == "exploitation":
                if self.run_nmap.get():
                    self.root.after(0, self.out.show_plain, f"[nmap] scanning {target} … (up to a minute)")
                    scan = tools.run_nmap(target)
                    self.context["scanning"] = scan
                else:
                    scan = self.scan_in.get("1.0", "end").strip() or self.context.get("scanning", "")
                prior = {k: v for k, v in self.context.items() if k != "exploitation"}
                advice = exploitation.advise(target, scan, prior)
                self.context["exploitation"] = advice
                path = exploitation.save_report(target, scan, advice)
                src = "carried scan" if (not self.run_nmap.get() and not self.scan_in.get("1.0", "end").strip() and scan) else "this run"
                self.root.after(0, self.out.render, advice + f"\n\n---\n*Report saved: `{path}`  ·  scan source: {src}*")
            else:
                carried = ", ".join(self.context) or "none"
                self.root.after(0, self.out.show_plain,
                                 f"[{agent}] not implemented yet (teammate stub).\nCarried context available to it: {carried}")
        except Exception as e:
            self.root.after(0, self.out.show_plain, f"[ERROR] {e}")
        finally:
            self.root.after(0, lambda: self.run_btn.configure(state="normal"))
            self.root.after(0, self._refresh_status)

    def on_install(self):
        missing = [t for t, ok in tools.status().items() if not ok]
        if not missing:
            messagebox.showinfo("Tools", "All tools already installed.")
            return
        if not messagebox.askyesno("Install tools", f"Install: {', '.join(missing)}?"):
            return
        self.out.show_plain(f"Installing {', '.join(missing)} …")
        threading.Thread(target=self._install_work, args=(missing,), daemon=True).start()

    def _install_work(self, missing):
        lines = []
        for t in missing:
            ok, msg = tools.install(t)
            lines.append(f"{t}: {'installed' if ok else 'FAILED'} ({msg})")
            self.root.after(0, self.out.show_plain, "\n".join(lines))
        self.root.after(0, self._refresh_status)

    def on_config(self):
        ConfigDialog(self.root, on_saved=self._refresh_status)


class ConfigDialog(tk.Toplevel):
    def __init__(self, parent, on_saved):
        super().__init__(parent)
        self.title("LLM configuration")
        self.on_saved = on_saved
        self.resizable(False, False)
        self.configure(bg=CARD)
        c = llm.resolve_config()

        frm = tk.Frame(self, bg=CARD, padx=16, pady=14)
        frm.pack(fill="both", expand=True)
        tk.Label(frm, text="LLM configuration", bg=CARD, fg=TEXT,
                 font=(UI, 14, "bold")).grid(row=0, column=0, columnspan=2, sticky="w")
        tk.Label(frm, text=f"current source: {c['source']}", bg=CARD, fg=MUTED,
                 font=(UI, 10)).grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 10))

        self.base = tk.StringVar(value=c["base_url"])
        self.model = tk.StringVar(value=c["model"])
        self.key = tk.StringVar()
        for i, (label, var) in enumerate([("base_url", self.base), ("model", self.model),
                                          ("api_key", self.key)], start=2):
            tk.Label(frm, text=label, bg=CARD, fg=MUTED, font=(UI, 10)).grid(row=i, column=0, sticky="w", pady=3)
            ttk.Entry(frm, textvariable=var, width=44).grid(row=i, column=1, sticky="we", pady=3)
        tk.Label(frm, text="api_key blank = keep current (never shown, for security)",
                 bg=CARD, fg=MUTED, font=(UI, 9)).grid(row=5, column=1, sticky="w")

        row = tk.Frame(frm, bg=CARD)
        row.grid(row=6, column=0, columnspan=2, pady=(12, 0), sticky="e")
        ttk.Button(row, text="Save", style="Accent.TButton", command=self._save).pack(side="left", padx=2)
        ttk.Button(row, text="Reset to default", command=self._reset).pack(side="left", padx=2)
        ttk.Button(row, text="Close", command=self.destroy).pack(side="left", padx=2)

    def _save(self):
        base, model = self.base.get().strip(), self.model.get().strip()
        if not base or not model:
            messagebox.showwarning("Missing", "base_url and model required.")
            return
        llm.save_user_config(base, model, self.key.get().strip() or None)
        self.on_saved()
        messagebox.showinfo("Saved", "Using your own config.")
        self.destroy()

    def _reset(self):
        llm.clear_user_config()
        self.on_saved()
        messagebox.showinfo("Reset", "Back to default config.")
        self.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()
