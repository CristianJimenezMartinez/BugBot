import re
from typing import List
from core.config import Config

class SensitiveParser:
    """Análisis atómico de archivos robots.txt y sitemaps."""
    
    @staticmethod
    async def parse_sensitive_file(content: str) -> List[str]:
        """Extrae URLs de interés."""
        juicy_urls = []
        keywords = Config.INTEREST_KEYWORDS
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            if not line: continue
            xpath = ""
            if "<loc>" in line:
                match = re.search(r'<loc>(.*?)</loc>', line)
                if match: xpath = match.group(1)
            elif line.lower().startswith("disallow:"):
                xpath = line.split(":", 1)[1].strip()
            elif "http" in line:
                xpath = line
                
            if xpath:
                lower_path = xpath.lower()
                for kw in keywords:
                    if kw.lower() in lower_path:
                        juicy_urls.append(xpath)
                        break 
        return juicy_urls
