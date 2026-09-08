"""CyberAgents launcher. Pick an agent, give it a target, it runs.
You own: this shell + the exploitation agent. Teammates fill the stubs."""
import llm
from agents.exploitation import ExploitationAgent
from agents.recon import ReconAgent
from agents.scanning import ScanningAgent
from agents.loot import LootAgent
from agents.postexploit import PostExploitAgent

AGENTS = [
    ReconAgent(),
    ScanningAgent(),
    ExploitationAgent(),
    LootAgent(),
    PostExploitAgent(),
]


def menu():
    print("\n=== CyberAgents ===  (authorized/lab use only)\n")
    for i, a in enumerate(AGENTS, 1):
        print(f"  [{i}] {a.name:<12} {a.description}")
    print("  [c] configure LLM (use your own endpoint/model/key)")
    print("  [0] quit\n")


def configure():
    """Let the user set/clear their OWN LLM config. Embedded default stays hidden."""
    print("\n-- LLM configuration --")
    print("Current:")
    print(llm.describe())
    print("\n  [1] use my own endpoint   [2] reset to default   [enter] back")
    c = input("> ").strip()
    if c == "1":
        base = input("  base_url (OpenAI-compatible, e.g. http://host:port/v1): ").strip()
        model = input("  model: ").strip()
        key = input("  api_key (blank if none): ").strip()
        if base and model:
            path = llm.save_user_config(base, model, key or None)
            print(f"  saved -> {path}")
        else:
            print("  base_url and model required; nothing saved.")
    elif c == "2":
        print("  cleared, using default." if llm.clear_user_config() else "  no user config to clear.")


def main():
    while True:
        menu()
        choice = input("Select: ").strip().lower()
        if choice in ("0", "q", "quit", ""):
            return
        if choice == "c":
            configure()
            continue
        if not choice.isdigit() or not (1 <= int(choice) <= len(AGENTS)):
            print("Invalid choice.")
            continue
        agent = AGENTS[int(choice) - 1]
        target = input(f"[{agent.name}] Target: ").strip()
        if not target:
            print("No target given.")
            continue
        agent.run(target)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nbye")
