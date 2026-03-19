import json
import os
import logging
from typing import Dict, Any

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

logger = logging.getLogger("BugBot.ProjectManager")

class ProjectManager:
    """
    Gestor de Proyectos Universal (v1.0):
    - Carga configuraciones dinámicas por programa (ProgramA, ProgramB, etc.).
    - Gestiona el Scope (In-Scope / Out-of-Scope).
    - Permite cambiar de identidad (Headers/UA) al vuelo.
    """

    DEFAULT_TEMPLATE = {
        "program_name": "Generic_Bounty",
        "hackerone_handle": "researcher",
        "custom_headers": {
            "X-Bug-Bounty": "True",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) BugBot/1.0"
        },
        "target_domains": [],
        "excluded_subdomains": [],
        "interest_keywords": ["dev", "staging", "admin", "api", "conf", "secret"],
        "critical_only": False,
        "account_a_token": {"Authorization": "Bearer YOUR_TOKEN_HERE"},
        "account_b_token": {"Authorization": "Bearer YOUR_TOKEN_HERE"}
    }

    def __init__(self, projects_dir: str = "projects"):
        self.projects_dir = projects_dir
        if not os.path.exists(self.projects_dir):
            os.makedirs(self.projects_dir, exist_ok=True)
        self.current_config = self.DEFAULT_TEMPLATE.copy()

    def create_project(self, name: str, data: Dict[str, Any]):
        """Crea un nuevo perfil de programa."""
        path = os.path.join(self.projects_dir, f"{name}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        logger.info(f"Proyecto {name} creado con éxito.")

    def load_project(self, name: str) -> bool:
        """Carga la configuración de un proyecto (JSON o YAML)."""
        # Buscar primero JSON, luego YAML
        json_path = os.path.join(self.projects_dir, f"{name}.json")
        yaml_path = os.path.join(self.projects_dir, f"{name}.yaml")
        yml_path = os.path.join(self.projects_dir, f"{name}.yml")

        if os.path.exists(json_path):
            path, fmt = json_path, "json"
        elif os.path.exists(yaml_path):
            path, fmt = yaml_path, "yaml"
        elif os.path.exists(yml_path):
            path, fmt = yml_path, "yaml"
        else:
            logger.error(f"Error: El proyecto {name} no existe (.json/.yaml).")
            return False

        with open(path, "r", encoding="utf-8") as f:
            if fmt == "yaml":
                if not HAS_YAML:
                    logger.error("PyYAML no instalado. Ejecuta: pip install pyyaml")
                    return False
                user_config = yaml.safe_load(f)
            else:
                user_config = json.load(f)

        # Aplanar config YAML con secciones anidadas al formato plano esperado
        flat_config = self._flatten_yaml_config(user_config) if fmt == "yaml" else user_config
        self.current_config = {**self.DEFAULT_TEMPLATE, **flat_config}

        logger.info(f"Proyecto {name} cargado correctamente ({fmt.upper()}).")
        return True

    @staticmethod
    def _flatten_yaml_config(cfg: Dict) -> Dict:
        """Convierte la config YAML anidada al formato plano que espera Config."""
        flat = {}
        # Datos básicos
        for key in ["program_name", "platform", "hackerone_handle"]:
            if key in cfg:
                flat[key] = cfg[key]

        # Scope
        scope = cfg.get("scope", {})
        flat["target_domains"] = scope.get("target_domains", [])
        flat["excluded_subdomains"] = scope.get("excluded_subdomains", [])
        flat["priority_targets"] = scope.get("priority_targets", [])
        flat["third_party_exclusions"] = scope.get("third_party_exclusions", [])

        # Rate Limiting
        rate = cfg.get("rate_limiting", {})
        flat["global_concurrency"] = rate.get("global_concurrency", 5)
        flat["module_concurrency"] = rate.get("module_concurrency", 2)
        flat["daily_max_requests"] = rate.get("daily_max_requests", 10000)
        flat["kill_switch_threshold"] = rate.get("kill_switch_threshold", 9500)
        flat["per_endpoint_rps"] = rate.get("per_endpoint_rps", 100)

        # Auth y Headers
        auth = cfg.get("authentication", {})
        flat["custom_headers"] = auth.get("custom_headers", {})
        if auth.get("research_header"):
            rh = auth["research_header"]
            flat["custom_headers"][rh["name"]] = rh["value"]
        flat["account_a_token"] = auth.get("account_a_token", {})
        flat["account_b_token"] = auth.get("account_b_token", {})

        # Keywords
        flat["interest_keywords"] = cfg.get("interest_keywords", [])

        # Business Rules y Noise Filter (se pasan tal cual)
        flat["business_rules"] = cfg.get("business_rules", {})
        flat["noise_filter"] = cfg.get("noise_filter", {})

        return flat

    def is_in_scope(self, url: str) -> bool:
        """Valida si una URL o host está dentro del alcance definido."""
        from urllib.parse import urlparse
        domain = urlparse(url).netloc if "://" in url else url
        
        # Check exclusion
        for excluded in self.current_config["excluded_subdomains"]:
            if excluded in domain:
                return False
                
        # Check inclusion
        for target in self.current_config["target_domains"]:
            if target in domain:
                return True
                
        return False

if __name__ == "__main__":
    # Test rápido
    pm = ProjectManager()
    pm.create_project("example_program", {
        "program_name": "Example_H1",
        "hackerone_handle": "researcher",
        "target_domains": ["example.com", "test.com"],
        "excluded_subdomains": ["out-of-scope.example.com"]
    })
    if pm.load_project("example_program"):
        print(f"Cargado: {pm.current_config['program_name']}")
        print(f"¿In Scope (api.example.com)? {pm.is_in_scope('api.example.com')}")
        print(f"¿In Scope (evil.com)? {pm.is_in_scope('evil.com')}")
