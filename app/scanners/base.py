from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import AsyncIterator
import logging

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    assets: list[dict] = field(default_factory=list)
    threats: list[dict] = field(default_factory=list)
    vulnerabilities: list[dict] = field(default_factory=list)
    connections: list[dict] = field(default_factory=list)
    error: str | None = None


class BaseScanner(ABC):
    name: str = ""
    display_name: str = ""
    version: str = "1.0.0"

    @abstractmethod
    async def scan(self, target: str, config: dict) -> ScanResult:
        ...

    async def stream_scan(self, target: str, config: dict) -> AsyncIterator[dict]:
        yield {"event": "start", "scanner": self.name, "target": target}
        try:
            result = await self.scan(target, config)
            yield {"event": "complete", "scanner": self.name, "assets": len(result.assets),
                   "threats": len(result.threats), "vulnerabilities": len(result.vulnerabilities)}
        except Exception as e:
            logger.error(f"Scanner {self.name} failed: {e}")
            yield {"event": "error", "scanner": self.name, "error": str(e)}
