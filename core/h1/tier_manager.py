from typing import Dict

class TierManager:
    """Clasifica el objetivo en los Tiers de pago del programa."""
    
    @staticmethod
    def get_tier_info(target: str) -> Dict:
        """Clasifica el objetivo en los Tiers de pago de Playtika."""
        target_lower = target.lower()
        tier1 = ["target1.com", "target2.com"]
        tier2 = ["target3.com", "target4.com"]
        tier3 = ["target5.com", "target6.com"]
        
        for t in tier1:
            if t in target_lower: return {"tier": "Tier 1", "desc": "💎 ¡Máxima Recompensa! Bugs pagados a precio de oro."}
        for t in tier2:
            if t in target_lower: return {"tier": "Tier 2", "desc": "🥇 Recompensa Alta."}
        for t in tier3:
            if t in target_lower: return {"tier": "Tier 3", "desc": "🥈 Recompensa Estándar."}
        return {"tier": "Desconocido/General", "desc": "Tarifas estándar."}
