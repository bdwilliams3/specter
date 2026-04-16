from abc import ABC, abstractmethod
from app.scanners.base import ScanResult


class BaseDetector(ABC):
    @abstractmethod
    def analyze(self, result: ScanResult, raw_context: dict) -> ScanResult:
        """Augment result with additional threats/vulnerabilities."""
        ...
