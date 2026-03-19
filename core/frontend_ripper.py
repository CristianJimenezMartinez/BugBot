import asyncio
from typing import List
from core.ripper.orchestrator import RipperOrchestrator

class FrontendRipper:
    """
    Facade Atómico para BugBot FrontendRipper.
    Delega el análisis AST a RipperOrchestrator.
    """
    def __init__(self, target_domain: str):
        self._orchestrator = RipperOrchestrator(target_domain)

    async def run(self, js_urls: List[str]) -> List[str]:
        discovered = await self._orchestrator.run(js_urls)
        if discovered:
            print(f"       [!] Ripper: ¡Hallados {len(discovered)} endpoints ocultos en el Frontend!")
        return discovered
