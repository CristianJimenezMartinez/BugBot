import asyncio
import random
import string
import logging
from core.config import Config
from core.fuzzer.constants import get_random_ua

logger = logging.getLogger("BugBot.Fuzzer.Calibrator")

class FuzzerCalibrator:
    """Motor de calibración anti-WAF y Soft-404."""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    async def calibrate_host(self, session, base_url: str) -> dict:
        """[Anti-WAF/Noise] Calibra respuestas de error dinámicas (Soft 404)."""
        baseline = {
            "is_soft_404": False,
            "status_codes": set(),
            "sizes": set(),
            "word_counts": set()
        }
        
        random_paths = [
            ''.join(random.choices(string.ascii_lowercase + string.digits, k=16)),
            ''.join(random.choices(string.ascii_lowercase + string.digits, k=24)) + ".html",
            ''.join(random.choices(string.ascii_lowercase + string.digits, k=18)) + "/_fakeroute"
        ]
        
        for p in random_paths:
            url = base_url.rstrip("/") + "/" + p
            try:
                headers = {"User-Agent": get_random_ua()}
                headers.update(Config.CUSTOM_HEADERS)
                async with session.get(url, headers=headers, timeout=self.timeout, allow_redirects=False) as response:
                    content = await response.text(errors='ignore')
                    baseline["status_codes"].add(response.status)
                    if response.status in [200, 301, 302, 403]:
                        baseline["is_soft_404"] = True
                    baseline["sizes"].add(len(content))
                    baseline["word_counts"].add(len(content.split()))
            except Exception:
                pass
        return baseline

    def is_false_positive(self, baseline: dict, status: int, content_length: int, word_count: int) -> bool:
        """Filtro Inteligente contra Soft-404."""
        if not baseline["is_soft_404"] and status not in [200, 401, 403]:
            return True
            
        if status in baseline["status_codes"]:
            for b_size in baseline["sizes"]:
                if b_size == 0 and content_length == 0: return True
                if abs(content_length - b_size) <= max(b_size * 0.05, 100):
                    return True
            for b_words in baseline["word_counts"]:
                if abs(word_count - b_words) <= max(b_words * 0.05, 15):
                    return True
        return False
