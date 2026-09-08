"""Agent interface. Teammates: subclass this, fill name/description/run."""
from abc import ABC, abstractmethod


class Agent(ABC):
    name = "unnamed"
    description = ""

    @abstractmethod
    def run(self, target: str) -> None:
        """Do the work for one target. Print results; save a report if useful."""
        ...
