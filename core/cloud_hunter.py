import asyncio
from typing import List, Dict
from core.cloud.orchestrator import CloudOrchestrator

class CloudBucketHunter:
    """
    Facade Atómico para BugBot CloudHunter.
    Delega la detección de buckets expuestos a CloudOrchestrator.
    """
    def __init__(self, concurrency: int = 50, strict_mode: bool = True):
        self._orchestrator = CloudOrchestrator(concurrency=concurrency, strict_mode=strict_mode)
        self.findings = []

    async def run(self, base_domain: str, known_subdomains: List[str] = None) -> List[Dict]:
        self.findings = await self._orchestrator.run(base_domain, known_subdomains)
        return self.findings
