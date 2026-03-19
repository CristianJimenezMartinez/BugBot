import asyncio
from typing import List, Dict
from core.analyzer.orchestrator import AnalyzerOrchestrator
from core.analyzer.entropy import EntropyHunter

class FileAnalyzer:
    """
    Facade Atómico para BugBot FileAnalyzer.
    """
    def __init__(self, target_domain: str, concurrency: int = 5, timeout: int = 30):
        self._orchestrator = AnalyzerOrchestrator(target_domain, concurrency)
        self.findings = []
        self._hunter = EntropyHunter() # Para compatibilidad direct-call en cloud_hunter

    def detect_secrets_by_entropy(self, text: str) -> List[Dict]:
        """Proxy para compatibilidad con CloudHunter."""
        return self._hunter.detect_secrets(text)

    async def run(self, urls: List[str]) -> List[Dict]:
        self.findings = await self._orchestrator.run(urls)
        return self.findings
