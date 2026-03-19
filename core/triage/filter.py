import re
from core.triage.constants import IGNORED_PATHS, THIRD_PARTY_LIBS, STATIC_DIRS, IGNORED_CONTEXT, GITHUB_NOISE

class TriageFilter:
    """Motor atómico para detección de falsos positivos."""
    
    @staticmethod
    def is_false_positive(file_path: str, context_string: str) -> bool:
        """Evalúa si el hallazgo es código real o ruido."""
        fp = file_path or ""
        ctx = context_string or ""
        
        if re.search(IGNORED_PATHS, fp): return True
        if re.search(THIRD_PARTY_LIBS, fp): return True
        if re.search(STATIC_DIRS, fp): return True
        if re.search(IGNORED_CONTEXT, ctx): return True
        if re.search(GITHUB_NOISE, ctx): return True
            
        return False
