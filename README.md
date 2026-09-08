# CyberAgents

Five pentest-phase AI agents behind one launcher exe. **Authorized / lab / learning use only.**
The exploitation agent is *advisor-mode*: it analyzes a target and suggests
commands; it never runs exploits itself.

## Run (dev)
GUI (desktop window):
```
python3 gui.py
```
CLI (terminal menu):
```
python3 main.py
```

## Build the Windows .exe
On a Windows box (PyInstaller builds per-OS). tkinter ships with the python.org
installer, so no extra setup:
```
pip install pyinstaller
pyinstaller --onefile --windowed --name cyberagents gui.py   # desktop GUI
# or CLI: pyinstaller --onefile --name cyberagents main.py
# -> dist/cyberagents.exe
```

## Layout
- `gui.py`        desktop GUI (tkinter) — the graphical entry point
- `main.py`       launcher shell + agent menu (the foundation)
- `llm.py`        OpenAI-compatible client, stdlib only
- `tools.py`      detect/install nmap, metasploit, sqlmap; read-only nmap runner
- `agents/base.py`         Agent interface teammates subclass
- `agents/exploitation.py` the real one (advisor)
- `agents/{recon,scanning,loot,postexploit}.py`  stubs for teammates
