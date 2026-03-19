"""
HackerOne Formatter Wrapper (v2.2):
- This file is now a wrapper for the atomized core.h1 package.
- Maintains backward compatibility with existing imports.
"""

from core.h1.formatter import H1Formatter as NewH1Formatter
from core.h1.tier_manager import TierManager
from core.h1.tactical_assistant import TacticalAssistant

class H1Formatter(NewH1Formatter):
    """
    Backward compatible wrapper for NewH1Formatter.
    """
    def _get_tier_info(self, target: str):
        """Legacy access to tier info."""
        return TierManager.get_tier_info(target)

    def _generate_exploit_guide(self, secrets, fuzz_findings, takeovers, auth_findings, analyzer_findings, target):
        """Legacy access to exploit guide."""
        return TacticalAssistant.generate_exploit_guide(secrets, fuzz_findings, takeovers, auth_findings, analyzer_findings, target)

    def save_h1_report(self, content: str) -> str:
        """Legacy save method (already in NewH1Formatter but kept for clarity)."""
        return super().save_h1_report(content)
