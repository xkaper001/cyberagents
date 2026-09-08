"""Scanning phase: port/service scan (nmap). Real logic so its output can feed
later agents (e.g. exploitation). Teammates can extend with more scan types."""
from agents.base import Agent
import tools


def run_scan(target, args=None):
    """Return nmap service-scan text for a target."""
    return tools.run_nmap(target, args)


class ScanningAgent(Agent):
    name = "scanning"
    description = "Port/service scan with nmap. Output is shared with later agents."

    def run(self, target: str) -> None:
        print(run_scan(target))
