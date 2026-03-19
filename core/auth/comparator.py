import logging
from typing import Dict

logger = logging.getLogger("BugBot.Auth.Comparator")

class AuthComparator:
    """Motor atómico para análisis diferencial de respuestas."""
    
    @staticmethod
    def is_similar(res_A: dict, res_B: dict, tolerance: float = 0.1) -> bool:
        """Compara si la respuesta B es sospechosamente similar a la A."""
        # 1. Comparación de Status
        if res_B["status"] not in [200, 201]: return False
        
        # 2. Comparación de Tamaño (Tolerancia configurable)
        len_A = res_A.get("size", 0)
        len_B = res_B.get("size", 0)
        
        if len_A == 0: return len_B > 0 # Si A era vacío y B tiene datos, es sospechoso
        
        diff = abs(len_B - len_A)
        return diff < max(len_A * tolerance, 50)

    @staticmethod
    def is_access_denied(status: int) -> bool:
        """Identifica si una respuesta es una denegación de acceso estándar."""
        return status in [401, 403, 302, 400]
